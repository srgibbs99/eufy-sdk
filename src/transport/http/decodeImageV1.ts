/**
 * V1 `eufysecurity:` push-thumbnail decoder.
 *
 * Wire format: `eufysecurity:<SERIAL(16)>:<CODE(10)>:<DATA>`. V1 encrypts the first 256 bytes of
 * `DATA` with AES-128-ECB and leaves the remaining JPEG bytes in plaintext. The key is derived from
 * the camera serial, station `p2p_did`, and per-image code. This decoder is verified against a V6
 * production push thumbnail: the decrypted result is a structurally valid, viewable JPEG.
 */
import { createDecipheriv } from "node:crypto";
import { getImageKey } from "../../core/image-key.js";
import { decodeImageV2, isV2Image } from "./decodeImageV2.js";

export const V1_PREFIX = "eufysecurity";

/** True if the blob is a legacy v1 `eufysecurity:` image (NOT the v2 variant). */
export function isV1Image(data: Buffer): boolean {
  return (
    data.length >= 41 &&
    data.subarray(0, 12).toString("latin1") === V1_PREFIX &&
    data.subarray(0, 3).toString("latin1") !== "v2_"
  );
}

/**
 * Decode a v1 `eufysecurity:` blob to a plain JPEG buffer using the station's
 * `p2p_did`. Returns null if the blob isn't v1. Mirrors the legacy decode: parse
 * SERIAL + CODE, derive the key, AES-128-ECB-decrypt the first 256 bytes, splice
 * the decrypted head back in front of the plaintext tail.
 */
export function decodeImageV1(data: Buffer, p2pDid: string): Buffer | null {
  if (!isV1Image(data)) return null;
  const serialNumber = data.subarray(13, 29).toString("latin1");
  const code = data.subarray(30, 40).toString("latin1");
  const otherData = Buffer.from(data.subarray(41));
  const encryptedData = otherData.subarray(0, 256);
  const imageKey = getImageKey(serialNumber, p2pDid, code);
  const cipher = createDecipheriv("aes-128-ecb", Buffer.from(imageKey, "utf-8").subarray(0, 16), null);
  cipher.setAutoPadding(false);
  const decrypted = Buffer.concat([cipher.update(encryptedData), cipher.final()]);
  decrypted.copy(otherData, 0);
  return otherData;
}

/** Decode a recognized v1 (device-key) or v2 (keyless) wrapper; leave other media unchanged. */
export function normalizePushImage(data: Buffer, p2pDid?: string): Buffer {
  if (isV2Image(data)) return decodeImageV2(data) ?? data;
  if (!p2pDid || !isV1Image(data)) return data;
  return decodeImageV1(data, p2pDid) ?? data;
}
