/**
 * Download of a recording held on a HomeBase 2 (T8010) or on a standalone doorbell, over the station's P2P
 * session.
 *
 * The request is `CMD_DOWNLOAD_VIDEO` (1024) in the string-pair shape
 * ({@link buildStringPairCommandPayload}) on the camera's channel. The station answers on
 * {@link RECORDING_DATA_TYPE}, tagged with that channel, with the recording's `CMD_VIDEO_FRAME` (1300) and
 * `CMD_AUDIO_FRAME` (1301) frames, faster than real time, then `CMD_DOWNLOAD_FINISH` (1304) on the control
 * data type, tagged with channel 0 whatever the camera's channel.
 *
 * Frame layouts:
 *
 * ```
 * video, keyframe: the live E2E layout ({@link VideoFrameDecoder}), length = 179 + len exactly
 * video, other frames: the same 22B header (u32@0 = len · u16@6 = frame number · u48@0x0e = stamp in ms),
 *   then len bytes of plaintext H.264
 * audio: 16B header (u32@0 = len · u8@5 = codec, 0 = AAC-LC), then 16B GCM tag, 12B GCM nonce and len
 *   bytes of AES-256-GCM AAC under the media key of the preceding keyframe, AAD as live video; the
 *   plaintext is a whole ADTS frame, header included
 * ```
 *
 * A standalone doorbell answers the request in the clear on a cipher-0 session, and differently:
 *
 * ```
 * reply to 1024, channel 0: i32@0 = result (0 = accepted), then a 10-digit ASCII download code
 * frames: on a channel of the doorbell's own, not the request's
 * video, signCode 1: 22B header, then len bytes whose first 128 are AES-128-ECB under the download key
 *   ({@link standaloneRecordingKey}), the rest plaintext H.264; length = 22 + len exactly
 * video, signCode 0: 22B header, then len bytes of plaintext H.264
 * audio: 16B header (as above), then len bytes of plaintext AAC, a whole ADTS frame
 * ```
 *
 * @module p2p/recording-download
 */
import { createDecipheriv } from "node:crypto";
import { getImageKey } from "../../core/image-key.js";
import { RecordingDownloadError, type RecordingDownload } from "../../core/contracts.js";
import { CommandType } from "./commands.js";
import type { P2PFrame, P2PSession } from "./p2p-session.js";
import {
  AccessUnitAssembler,
  VIDEO_GCM_AAD,
  VideoFrameDecoder,
  parseVideoFrameHeader,
  type VideoFrameHeader,
} from "./video.js";

/** Data type a station sends a recording's frames on: the binary channel (`0xd1 0x03`), not live video's. */
export const RECORDING_DATA_TYPE = 3;
/** Bytes of video frame header; a plaintext frame's H.264 starts here. */
const VIDEO_HEADER_LEN = 0x16;
/** Bytes at the start of a standalone recording's encrypted video body that are AES-128-ECB. */
const STANDALONE_SEALED_BYTES = 128;
/** Bytes of audio frame header; the 16-byte GCM tag starts here. */
const AUDIO_HEADER_LEN = 16;
/** Start of an audio frame's 12-byte GCM nonce. */
const AUDIO_NONCE_START = 32;
/** Start of an audio frame's AAC ciphertext. */
const AUDIO_BODY_START = 44;
/** Audio codec id for AAC-LC in the audio frame header. */
const AUDIO_CODEC_AAC_LC = 0;
/** Channel 0, the one a HomeBase tags `CMD_DOWNLOAD_FINISH` with whatever the camera's channel. */
const FINISH_CHANNEL = 0;
/** How long the station may take to send the first frame of a recording. */
const FIRST_FRAME_WAIT_MS = 20_000;
/**
 * Silence after the last frame that ends a transfer whose finish frame never arrived. Not covered: a station
 * that pauses longer than this mid-transfer and then resumes. The listener has stopped by then, so the rest of
 * that recording, its finish frame included, would reach the next download of the same camera.
 * `CMD_DOWNLOAD_CANCEL` would close that gap once its wire is captured.
 */
const IDLE_END_MS = 15_000;
/** Longest a transfer may run, whatever arrives. */
const DEFAULT_TRANSFER_MS = 120_000;
/**
 * Most frame bytes a transfer holds. The station sends faster than real time, so the time bounds alone do
 * not bound memory; the longest event recordings measured on a doorbell, about five minutes, are 50 MB.
 */
export const MAX_TRANSFER_BYTES = 64 * 1024 * 1024;

/** One recording frame as received, in arrival order. */
export interface RecordingFrame {
  commandId: number;
  signCode: number;
  raw: Buffer;
}

/**
 * The path a HomeBase 2 stores a camera's recording under: the channel as two digits, then the recording's
 * name as `yyyyMMddHHmmss` or `h265_yyyyMMddHHmmss`. Answers `undefined` for any other name, and for a channel
 * outside `0`–`99`. Both forms are digits behind one fixed prefix, so the anchored test lets no `..`, slash or
 * other character that could reach another path on the station through.
 */
export function homeBase2RecordingPath(channel: number, recording: string): string | undefined {
  if (!/^(?:h265_)?\d{14}$/.test(recording) || !Number.isInteger(channel) || channel < 0 || channel > 99)
    return undefined;
  return `/media/mmcblk0p1/Camera${String(channel).padStart(2, "0")}/${recording}.dat`;
}

/**
 * The path a standalone doorbell stores a recording under: its name as `h264_video_yyyyMMdd_HHmmss` in the
 * doorbell's video directory. Answers `undefined` for any other name. The name is digits behind one fixed
 * prefix, so the anchored test lets no `..`, slash or other character that could reach another path through.
 */
export function standaloneRecordingPath(recording: string): string | undefined {
  if (!/^h264_video_\d{8}_\d{6}$/.test(recording)) return undefined;
  return `/mnt/userdata/video/${recording}.data`;
}

/** One recording transfer on a station session. */
export interface RecordingTransfer {
  /** The recording's frames, in arrival order. Rejects as {@link receiveRecording} describes. */
  frames: Promise<RecordingFrame[]>;
  /** Resolves once the station has stopped sending this recording, which can be after `frames` rejected. */
  drained: Promise<void>;
}

/**
 * Request one recording and collect its frames until `CMD_DOWNLOAD_FINISH`. Only frames on
 * {@link RECORDING_DATA_TYPE} tagged with the camera's channel belong to it, so a live stream open on the same
 * station is never mixed in. The finish frame is taken on the camera's channel or channel 0. With `anyChannel`,
 * recording frames on every channel are kept: a standalone doorbell tags its transfer with a channel of its
 * own, and a station sends one recording at a time. The station's reply to the request, on the camera's
 * channel or channel 0, is kept among the frames as the session decoded it.
 *
 * `frames` rejects with {@link RecordingDownloadError}: `no-data` when nothing arrives within
 * {@link FIRST_FRAME_WAIT_MS}, and `incomplete` when the transfer ends without its finish frame, on a
 * {@link IDLE_END_MS} silence, on `timeoutMs` or on {@link MAX_TRANSFER_BYTES}. An abort rejects it at once
 * with the signal's reason. After a time bound, the byte ceiling or an abort, the transfer stops collecting
 * but keeps listening until the station finishes or goes quiet, and only then resolves `drained`.
 */
export function receiveRecording(
  session: P2PSession,
  request: {
    path: string;
    accountId: string;
    channel: number;
    anyChannel?: boolean;
    timeoutMs?: number;
    signal?: AbortSignal;
  },
): RecordingTransfer {
  let resolveFrames!: (frames: RecordingFrame[]) => void;
  let rejectFrames!: (error: Error) => void;
  const frames = new Promise<RecordingFrame[]>((resolve, reject) => {
    resolveFrames = resolve;
    rejectFrames = reject;
  });
  let resolveDrained!: () => void;
  const drained = new Promise<void>((resolve) => (resolveDrained = resolve));
  const limitMs = request.timeoutMs ?? DEFAULT_TRANSFER_MS;
  let collected: RecordingFrame[] = [];
  const started = Date.now();
  let lastFrameAt = started;
  let received = false;
  let bytes = 0;
  let draining: string | undefined;
  let delivered = false;
  let listening = true;
  const deliver = (error?: Error) => {
    if (delivered) return;
    delivered = true;
    request.signal?.removeEventListener("abort", onAbort);
    if (error) rejectFrames(error);
    else resolveFrames(collected);
  };
  const stop = () => {
    if (!listening) return;
    listening = false;
    clearInterval(tick);
    session.off("data", onData);
    resolveDrained();
  };
  const incomplete = (why: string) =>
    deliver(new RecordingDownloadError("incomplete", `the recording transfer ${why} before its finish frame`));
  const drain = (why: string) => {
    draining ??= why;
    collected = [];
  };
  const onData = (frame: P2PFrame) => {
    if (frame.commandId === CommandType.CMD_DOWNLOAD_FINISH) {
      if (frame.channel !== request.channel && frame.channel !== FINISH_CHANNEL) return;
      if (draining) incomplete(draining);
      else deliver();
      return stop();
    }
    if (frame.commandId === CommandType.CMD_DOWNLOAD_VIDEO) {
      if (frame.channel !== request.channel && frame.channel !== FINISH_CHANNEL) return;
      if (!draining)
        collected.push({ commandId: frame.commandId, signCode: frame.signCode, raw: Buffer.from(frame.data) });
      return;
    }
    if (frame.channel !== request.channel && !request.anyChannel) return;
    if (frame.commandId !== CommandType.CMD_VIDEO_FRAME && frame.commandId !== CommandType.CMD_AUDIO_FRAME) return;
    if (frame.dataType !== RECORDING_DATA_TYPE) return;
    received = true;
    lastFrameAt = Date.now();
    if (draining) return;
    collected.push({ commandId: frame.commandId, signCode: frame.signCode, raw: Buffer.from(frame.raw) });
    bytes += frame.raw.length;
    if (bytes >= MAX_TRANSFER_BYTES) drain(`reached ${MAX_TRANSFER_BYTES} bytes`);
  };
  const onAbort = () => {
    deliver(request.signal?.reason instanceof Error ? request.signal.reason : new Error("aborted"));
    drain("was aborted");
  };
  const tick = setInterval(() => {
    const now = Date.now();
    if (!received && now - started > FIRST_FRAME_WAIT_MS) {
      deliver(new RecordingDownloadError("no-data", `the station sent nothing within ${FIRST_FRAME_WAIT_MS} ms`));
      stop();
    } else if (received && now - lastFrameAt > IDLE_END_MS) {
      incomplete(draining ?? `went quiet for ${IDLE_END_MS} ms`);
      stop();
    } else if (now - started > 2 * limitMs && draining) {
      incomplete(draining);
      stop();
    } else if (now - started > limitMs) {
      drain(`ran past ${limitMs} ms`);
    }
  }, 250);
  if (request.signal?.aborted) {
    onAbort();
    stop();
    return { frames, drained };
  }
  request.signal?.addEventListener("abort", onAbort, { once: true });
  session.on("data", onData);
  try {
    session.sendStringPairCommand(CommandType.CMD_DOWNLOAD_VIDEO, request.path, request.accountId, request.channel);
  } catch (error) {
    deliver(error instanceof Error ? error : new Error(String(error)));
    stop();
  }
  return { frames, drained };
}

/** Open one AES-256-GCM audio body; `undefined` when it does not authenticate. */
function openAudio(key: Buffer, nonce: Buffer, tag: Buffer, body: Buffer): Buffer | undefined {
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAAD(VIDEO_GCM_AAD);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]);
  } catch {
    return undefined;
  }
}

/**
 * Decode a recording's frames, in arrival order, into elementary streams. Split pictures are assembled
 * before they enter the output; an orphan continuation cannot become its own picture. Keyframes go
 * through one {@link VideoFrameDecoder}, whose media key then opens the audio; a keyframe that does not
 * open under `eccPrivateKeyHex`, and every audio frame before the first media key, are dropped. Rejects with
 * {@link RecordingDownloadError} `undecodable` when no video frame decodes.
 */
export function decodeRecording(frames: readonly RecordingFrame[], eccPrivateKeyHex: string): RecordingDownload {
  const eccPrivateKey = Buffer.from(eccPrivateKeyHex, "hex");
  if (eccPrivateKey.length !== 32) throw new RecordingDownloadError("undecodable", "the cipher key is not a P-256 key");
  const decoder = new VideoFrameDecoder(eccPrivateKey);
  return assembleRecording(
    frames,
    (_frame, header, payload) => (header.keyframe ? decoder.decodeFrame(payload)?.h264 : plainVideo(header, payload)),
    (raw) => {
      const mediaKey = decoder.currentMediaKey;
      if (!mediaKey || raw.length < AUDIO_BODY_START || raw[5] !== AUDIO_CODEC_AAC_LC) return undefined;
      const len = raw.readUInt32LE(0);
      if (raw.length < AUDIO_BODY_START + len) return undefined;
      return openAudio(
        mediaKey,
        raw.subarray(AUDIO_NONCE_START, AUDIO_BODY_START),
        raw.subarray(AUDIO_HEADER_LEN, AUDIO_NONCE_START),
        raw.subarray(AUDIO_BODY_START, AUDIO_BODY_START + len),
      );
    },
  );
}

/**
 * The key a standalone doorbell seals a downloaded recording's video under: the first 16 bytes of the v1
 * device key ({@link getImageKey}) for its serial, its station's `p2p_did` and the download code its reply
 * carries — the derivation a v1 stored image uses with the code in its wrapper.
 */
export function standaloneRecordingKey(serialNumber: string, p2pDid: string, code: string): Buffer {
  return Buffer.from(getImageKey(serialNumber, p2pDid, code), "utf-8").subarray(0, 16);
}

/**
 * The download code of a standalone doorbell's reply to the request, among a transfer's frames. Throws
 * {@link RecordingDownloadError} `key-unavailable` when no reply was kept, when it states a non-zero result,
 * or when the code is not 10 digits.
 */
export function standaloneDownloadCode(frames: readonly RecordingFrame[]): string {
  const reply = frames.find((f) => f.commandId === CommandType.CMD_DOWNLOAD_VIDEO)?.raw;
  if (!reply || reply.length < 4) {
    throw new RecordingDownloadError("key-unavailable", "the station sent no reply carrying the download code");
  }
  const result = reply.readInt32LE(0);
  if (result !== 0) throw new RecordingDownloadError("key-unavailable", `the station answered the download ${result}`);
  const code = reply.subarray(4).toString("latin1").replace(/\0+$/, "");
  if (!/^\d{10}$/.test(code)) {
    throw new RecordingDownloadError("key-unavailable", "the station's reply carries no 10-digit download code");
  }
  return code;
}

/**
 * Decode a standalone doorbell's recording, in arrival order, into elementary streams, assembled as
 * {@link decodeRecording} assembles them. A video frame at signCode 1 has the first
 * {@link STANDALONE_SEALED_BYTES} of its body sealed under {@link standaloneRecordingKey}; one at signCode 0,
 * and the AAC audio, are plaintext. A sealed body shorter than that is dropped. Rejects with
 * {@link RecordingDownloadError}: `key-unavailable` as {@link standaloneDownloadCode} does, and `undecodable`
 * when no video frame decodes.
 */
export function decodeStandaloneRecording(
  frames: readonly RecordingFrame[],
  serialNumber: string,
  p2pDid: string,
): RecordingDownload {
  const key = standaloneRecordingKey(serialNumber, p2pDid, standaloneDownloadCode(frames));
  return assembleRecording(
    frames,
    (frame, header, payload) => {
      const body = plainVideo(header, payload);
      if (!body || frame.signCode === 0) return body;
      if (body.length < STANDALONE_SEALED_BYTES) return undefined;
      const decipher = createDecipheriv("aes-128-ecb", key, null);
      decipher.setAutoPadding(false);
      const head = Buffer.concat([decipher.update(body.subarray(0, STANDALONE_SEALED_BYTES)), decipher.final()]);
      return Buffer.concat([head, body.subarray(STANDALONE_SEALED_BYTES)]);
    },
    (raw) => {
      if (raw.length < AUDIO_HEADER_LEN || raw[5] !== AUDIO_CODEC_AAC_LC) return undefined;
      const len = raw.readUInt32LE(0);
      return raw.length >= AUDIO_HEADER_LEN + len ? raw.subarray(AUDIO_HEADER_LEN, AUDIO_HEADER_LEN + len) : undefined;
    },
  );
}

/** The H.264 a plaintext video frame carries after its header, or `undefined` when the frame is short. */
function plainVideo(header: VideoFrameHeader, payload: Buffer): Buffer | undefined {
  return payload.length >= VIDEO_HEADER_LEN + header.payloadLength
    ? payload.subarray(VIDEO_HEADER_LEN, VIDEO_HEADER_LEN + header.payloadLength)
    : undefined;
}

/**
 * Assemble a recording's frames, in arrival order, into elementary streams: `openVideo` turns each video
 * frame into H.264 and `openAudioFrame` each audio frame into AAC, both in arrival order, and either answers
 * `undefined` to drop the frame. Split pictures are joined through one {@link AccessUnitAssembler}; frames the
 * camera numbered but that never decoded are counted as missing. A camera that leaves its frame number at one
 * value for the whole recording, as a T8201 does, numbers nothing: its `frames` and `fps` are counted from the
 * assembled pictures, and `missingFrames` is 0 because no gap can be seen. Rejects with
 * {@link RecordingDownloadError} `undecodable` when no video frame decodes.
 */
function assembleRecording(
  frames: readonly RecordingFrame[],
  openVideo: (frame: RecordingFrame, header: VideoFrameHeader, payload: Buffer) => Buffer | undefined,
  openAudioFrame: (raw: Buffer) => Buffer | undefined,
): RecordingDownload {
  const assembler = new AccessUnitAssembler();
  const video: Buffer[] = [];
  const audio: Buffer[] = [];
  const numbers = new Set<number>();
  const receivedNumbers = new Set<number>();
  let firstStamp: number | undefined;
  let lastStamp: number | undefined;
  let pictures = 0;
  for (const frame of frames) {
    const { commandId, raw } = frame;
    if (commandId === CommandType.CMD_VIDEO_FRAME) {
      const header = parseVideoFrameHeader(raw);
      if (!header) continue;
      receivedNumbers.add(header.sequence);
      const units = assembler.push(raw, (payload) => openVideo(frame, header, payload));
      for (const unit of units) {
        video.push(unit.data);
        pictures++;
        numbers.add(header.sequence);
        const stamp = raw.readUIntLE(0x0e, 6);
        firstStamp ??= stamp;
        lastStamp = stamp;
      }
    } else if (commandId === CommandType.CMD_AUDIO_FRAME) {
      const aac = openAudioFrame(raw);
      if (aac?.length) audio.push(aac);
    }
  }
  if (!video.length) throw new RecordingDownloadError("undecodable", "no video frame of the recording decoded");
  const durationMs = (lastStamp ?? 0) - (firstStamp ?? 0);
  const videoAndAudio = {
    video: Buffer.concat(video),
    ...(audio.length ? { audio: Buffer.concat(audio) } : {}),
    durationMs,
  };
  if (receivedNumbers.size === 1 && pictures > 1) {
    const fps = durationMs > 0 ? Math.round(((pictures - 1) * 100_000) / durationMs) / 100 : 0;
    return { ...videoAndAudio, frames: pictures, missingFrames: 0, fps };
  }
  const ordered = [...numbers];
  const received = [...receivedNumbers];
  let missingFrames = receivedNumbers.size - numbers.size;
  for (let i = 1; i < received.length; i++) {
    const step = (received[i]! - received[i - 1]!) & 0xffff;
    if (step > 1 && step < 0x8000) missingFrames += step - 1;
  }
  const span = ordered.length > 1 ? (ordered[ordered.length - 1]! - ordered[0]!) & 0xffff : 0;
  return {
    ...videoAndAudio,
    frames: ordered.length,
    missingFrames,
    fps: durationMs > 0 && span > 0 ? Math.round((span * 100_000) / durationMs) / 100 : 0,
  };
}
