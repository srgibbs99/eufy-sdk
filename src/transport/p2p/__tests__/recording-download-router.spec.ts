import { randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { P2PRouterDeps } from "../command-router.js";
import {
  IDR,
  LONG_IDR,
  STANDALONE,
  camera,
  downloadReply,
  keyframe,
  plainFrame,
  sealedFrame,
  slice,
} from "./recording-fixtures.js";
import { standaloneRecordingKey } from "../recording-download.js";
import { ACCOUNT_ID, DEVICE_SN, STATION_SN, connectedSession, routerWithSession } from "./session-fixtures.js";

const RECORDING = "20260101120000";
const CIPHER_ID = 7;

/**
 * A router over a fake HomeBase 2 session that answers a download request with one recording, a keyframe at
 * 5 ms then a plain frame and the finish frame at 25 ms, and a cipher lookup that knows only
 * {@link CIPHER_ID}. `transfers.peak` counts requests the station was serving at once.
 */
function homeBase2(deps: Partial<P2PRouterDeps> = {}, opts: { finish?: boolean } = {}) {
  const cam = camera();
  const key = randomBytes(32);
  const session = connectedSession();
  const sent: unknown[][] = [];
  const transfers = { active: 0, peak: 0 };
  const media = (frame: { commandId: number; signCode: number; raw: Buffer }, channel: number) =>
    session.emit("data", { ...frame, dataType: 3, channel });
  Object.assign(session, {
    sendStringPairCommand: vi.fn((...args: unknown[]) => {
      sent.push(args);
      transfers.peak = Math.max(transfers.peak, ++transfers.active);
      const channel = args[3] as number;
      setTimeout(() => media(keyframe(key, cam.publicKey, IDR, 0, 0), channel), 5);
      setTimeout(() => {
        media(plainFrame(slice(1), 1, 67), channel);
        transfers.active--;
        if (opts.finish === false) return;
        session.emit("data", { commandId: 1304, dataType: 2, signCode: 0, raw: Buffer.alloc(0), channel });
      }, 25);
    }),
  });
  const getCiphers = vi.fn(async (ids: number[]) =>
    ids[0] === CIPHER_ID ? [{ cipher_id: CIPHER_ID, ecc_private_key: cam.eccHex }] : [],
  );
  const router = routerWithSession(session, { deps: { mega: { getCiphers } as never, ...deps } });
  return { media: router.mediaProviderFor(DEVICE_SN), session, sent, getCiphers, transfers };
}

/** The fixture's camera, attached to a station of `model`. */
function attachedTo(model: string): Partial<P2PRouterDeps> {
  return {
    listDevices: () =>
      [
        {
          sn: DEVICE_SN,
          stationSn: STATION_SN,
          channel: 1,
          raw: { parent_sn: STATION_SN, device_channel: 1, member: { admin_user_id: ACCOUNT_ID } },
        },
        { sn: STATION_SN, stationSn: STATION_SN, model, raw: {} },
      ] as never,
  };
}

describe("recording download through the router", () => {
  it("requests the camera's recording on its channel, as the station admin, and decodes it", async () => {
    const { media, sent, getCiphers } = homeBase2();

    const out = await media.downloadRecording!({ recording: RECORDING, cipherId: CIPHER_ID });

    expect(sent).toEqual([[1024, `/media/mmcblk0p1/Camera01/${RECORDING}.dat`, ACCOUNT_ID, 1]]);
    expect(getCiphers).toHaveBeenCalledWith([CIPHER_ID], ACCOUNT_ID, STATION_SN);
    expect(out.video).toEqual(Buffer.concat([IDR, slice(1)]));
    expect(out.frames).toBe(2);
  });

  it("runs one download at a time per station", async () => {
    const { media, sent, transfers } = homeBase2();

    await Promise.all([
      media.downloadRecording!({ recording: RECORDING, cipherId: CIPHER_ID }),
      media.downloadRecording!({ recording: "20260101120100", cipherId: CIPHER_ID }),
    ]);

    expect(sent).toHaveLength(2);
    expect(transfers.peak).toBe(1);
  });

  it("offers no download on a camera whose station is not a HomeBase 2", () => {
    expect(homeBase2(attachedTo("T8030")).media.downloadRecording).toBeUndefined();
    expect(
      homeBase2({
        listDevices: () => [{ sn: DEVICE_SN, stationSn: DEVICE_SN, model: "T8114", raw: {} }] as never,
      }).media.downloadRecording,
    ).toBeUndefined();
  });

  it("rejects an aborted download while it waits its turn, and the next one still waits for the first", async () => {
    const { media, sent, transfers } = homeBase2();
    const controller = new AbortController();

    const first = media.downloadRecording!({ recording: RECORDING, cipherId: CIPHER_ID });
    const queued = media.downloadRecording!({
      recording: "20260101120100",
      cipherId: CIPHER_ID,
      signal: controller.signal,
    });
    const next = media.downloadRecording!({ recording: "20260101120200", cipherId: CIPHER_ID });
    const reason = new Error("stop");
    controller.abort(reason);

    await expect(queued).rejects.toBe(reason);
    await Promise.all([first, next]);
    expect(sent.map((args) => args[1])).toEqual([
      `/media/mmcblk0p1/Camera01/${RECORDING}.dat`,
      "/media/mmcblk0p1/Camera01/20260101120200.dat",
    ]);
    expect(transfers.peak).toBe(1);
  });

  it("keeps the station's turn when a queued download is aborted before the next one is asked for", async () => {
    const { media, sent, transfers } = homeBase2();
    const controller = new AbortController();

    const first = media.downloadRecording!({ recording: RECORDING, cipherId: CIPHER_ID });
    const queued = media.downloadRecording!({
      recording: "20260101120100",
      cipherId: CIPHER_ID,
      signal: controller.signal,
    });
    const reason = new Error("stop");
    controller.abort(reason);
    await expect(queued).rejects.toBe(reason);
    const next = media.downloadRecording!({ recording: "20260101120200", cipherId: CIPHER_ID });

    await Promise.all([first, next]);
    expect(sent).toHaveLength(2);
    expect(transfers.peak).toBe(1);
  });

  it("rejects an abort mid-transfer at once, and the next download waits for the station to finish", async () => {
    const { media, session, sent, transfers } = homeBase2();
    const controller = new AbortController();
    const reason = new Error("stop");
    session.once("data", () => controller.abort(reason));

    const first = media.downloadRecording!({ recording: RECORDING, cipherId: CIPHER_ID, signal: controller.signal });
    await expect(first).rejects.toBe(reason);
    expect(transfers.active).toBe(1);
    const next = await media.downloadRecording!({ recording: "20260101120100", cipherId: CIPHER_ID });

    expect(next.video).toEqual(Buffer.concat([IDR, slice(1)]));
    expect(sent).toHaveLength(2);
    expect(transfers.peak).toBe(1);
  });

  it("rejects incomplete when the station stops without its finish frame", async () => {
    vi.useFakeTimers();
    try {
      const { media } = homeBase2({}, { finish: false });

      const download = media.downloadRecording!({ recording: RECORDING, cipherId: CIPHER_ID });
      const settled = expect(download).rejects.toMatchObject({ reason: "incomplete" });
      await vi.advanceTimersByTimeAsync(16_000);
      await settled;
    } finally {
      vi.useRealTimers();
    }
  });

  it("refuses a recording name the station could not hold", async () => {
    const { media, sent } = homeBase2();

    await expect(media.downloadRecording!({ recording: "../x", cipherId: CIPHER_ID })).rejects.toMatchObject({
      reason: "invalid-recording",
    });
    expect(sent).toHaveLength(0);
  });

  it("refuses when the recording's cipher cannot be obtained", async () => {
    const { media, sent } = homeBase2();

    await expect(media.downloadRecording!({ recording: RECORDING, cipherId: CIPHER_ID + 1 })).rejects.toMatchObject({
      reason: "key-unavailable",
    });
    expect(sent).toHaveLength(0);
  });
});

describe("standalone doorbell recording download through the router", () => {
  const NAME = "h264_video_20260101_120000";

  /**
   * A router over a fake cipher-0 standalone doorbell of `model` that answers a download request with its
   * reply on channel 0, a sealed keyframe and a plain frame on channel 1, then the finish frame on channel 0.
   */
  function doorbell(model = "T8201", p2pDid: string = STANDALONE.p2pDid) {
    const session = connectedSession(false);
    const sent: unknown[][] = [];
    const key = standaloneRecordingKey(STANDALONE.serial, STANDALONE.p2pDid, STANDALONE.code);
    const emit = (frame: { commandId: number; signCode: number; raw: Buffer }, channel: number, dataType = 3) =>
      session.emit("data", { ...frame, data: frame.raw, dataType, channel });
    Object.assign(session, {
      sendStringPairCommand: vi.fn((...args: unknown[]) => {
        sent.push(args);
        setTimeout(() => emit(downloadReply(), 0, 0), 2);
        setTimeout(() => emit(sealedFrame(key, LONG_IDR, 0, 0), 1), 5);
        setTimeout(() => {
          emit(plainFrame(slice(1), 1, 67), 1);
          session.emit("data", { commandId: 1304, dataType: 2, signCode: 0, raw: Buffer.alloc(0), channel: 0 });
        }, 25);
      }),
    });
    const listDevices = () =>
      [
        {
          sn: STANDALONE.serial,
          stationSn: STANDALONE.serial,
          model,
          p2pDid,
          raw: { member: { admin_user_id: ACCOUNT_ID } },
        },
      ] as never;
    const router = routerWithSession(session, { register: false, deps: { listDevices } });
    (router as unknown as { manager: { register(sn: string, value: unknown): void } }).manager.register(
      STANDALONE.serial,
      session,
    );
    return { media: router.mediaProviderFor(STANDALONE.serial), sent };
  }

  it("requests the doorbell's own path as the station admin and opens it with the reply's code", async () => {
    const { media, sent } = doorbell();

    const out = await media.downloadRecording!({ recording: NAME, cipherId: 1 });

    expect(sent).toEqual([[1024, `/mnt/userdata/video/${NAME}.data`, ACCOUNT_ID, 0]]);
    expect(out.video).toEqual(Buffer.concat([LONG_IDR, slice(1)]));
    expect(out.frames).toBe(2);
  });

  it("offers no download on a standalone model whose recording download is unconfirmed", () => {
    expect(doorbell("T8134").media.downloadRecording).toBeUndefined();
  });

  it("refuses a HomeBase 2 recording name", async () => {
    const { media, sent } = doorbell();

    await expect(media.downloadRecording!({ recording: "20260101120000", cipherId: 1 })).rejects.toMatchObject({
      reason: "invalid-recording",
    });
    expect(sent).toHaveLength(0);
  });

  it("refuses when the doorbell's record states no p2p_did", async () => {
    const { media, sent } = doorbell("T8201", "");

    await expect(media.downloadRecording!({ recording: NAME, cipherId: 1 })).rejects.toMatchObject({
      reason: "key-unavailable",
    });
    expect(sent).toHaveLength(0);
  });
});
