/**
 * The device-key derivation behind eufy's `eufysecurity:` v1 media: the AES-128-ECB key a v1 stored image is
 * sealed under, and the key a standalone camera's downloaded recording seals its keyframes under. Both derive
 * it from the camera serial, the station `p2p_did`, and a 10-digit code the device sends with the media.
 */
import { createHash } from "node:crypto";

const md5 = (s: string) => createHash("md5").update(s, "utf-8").digest("hex");
const sha256 = (s: string) => createHash("sha256").update(s, "utf-8").digest("hex");

/** Derive the numeric id-suffix from the station `p2p_did` — a digit-mixing seed used by the key derivation. */
export function getIdSuffix(p2pDid: string): number {
  let result = 0;
  const match = p2pDid.match(/^[A-Z]+-(\d+)-[A-Z]+$/);
  if (match?.length === 2) {
    const num1 = Number.parseInt(match[1][0]);
    const num2 = Number.parseInt(match[1][1]);
    const num3 = Number.parseInt(match[1][3]);
    const num4 = Number.parseInt(match[1][5]);
    result = num1 + num2 + num3;
    if (num3 < 5) result = result + num3;
    result = result + num4;
  }
  return result;
}

/** Derive the image "base code" from the camera serial + `p2p_did` — first input to {@link getImageKey}. */
export function getImageBaseCode(serialNumber: string, p2pDid: string): string {
  let nr = Number.parseInt(`0x${serialNumber[serialNumber.length - 1]}`);
  nr = (nr + 10) % 10;
  const base = serialNumber.substring(nr);
  return `${base}${getIdSuffix(p2pDid)}`;
}

/** Derive the per-image seed from the `p2p_did` + the image's own code — second input to {@link getImageKey}. */
export function getImageSeed(p2pDid: string, code: string): string {
  const nCode = Number.parseInt(code.substring(2));
  const prefix = 1000 - getIdSuffix(p2pDid);
  return md5(`${prefix}${nCode}`).toUpperCase();
}

/** Derive the AES-128-ECB key for a v1 thumbnail: SHA-256 over the base code + seed, rotated by a hash byte. */
export function getImageKey(serialNumber: string, p2pDid: string, code: string): string {
  const baseCode = getImageBaseCode(serialNumber, p2pDid);
  const seed = getImageSeed(p2pDid, code);
  const hashBytes = [...Buffer.from(sha256(`01${baseCode}${seed}`), "hex")];
  const startByte = hashBytes[10];
  for (let i = 0; i < 32; i++) {
    const byte = hashBytes[i];
    let fixed_byte = startByte;
    if (i < 31) fixed_byte = hashBytes[i + 1];
    if (i === 31 || (i & 1) !== 0) {
      hashBytes[10] = fixed_byte;
      if (126 < byte || 126 < hashBytes[10]) {
        if (byte < hashBytes[10] || byte - hashBytes[10] === 0) hashBytes[i] = hashBytes[10] - byte;
        else hashBytes[i] = byte - hashBytes[10];
      }
    } else if (byte < 125 || fixed_byte < 125) {
      hashBytes[i] = fixed_byte + byte;
    }
  }
  return Buffer.from(hashBytes.slice(16)).toString("hex").toUpperCase();
}
