import { createCipheriv } from "node:crypto";
import { decodeImageV1, isV1Image, normalizePushImage, V1_PREFIX } from "../decodeImageV1.js";
import { getImageKey } from "../../../core/image-key.js";

/** A synthetic v1 wrapper with the production-verified framing and key derivation. */
const SERIAL = "T8010P1234567890";
const CODE = "AB12345678";
const P2P_DID = "ABCDEF-123456-ABCDE";

/** Build a v1 blob whose first 256 DATA bytes are AES-128-ECB encrypted (no padding). */
function makeV1Blob(plaintextData: Buffer): Buffer {
  const key = Buffer.from(getImageKey(SERIAL, P2P_DID, CODE), "utf-8").subarray(0, 16);
  const cipher = createCipheriv("aes-128-ecb", key, null);
  cipher.setAutoPadding(false);
  const head = Buffer.concat([cipher.update(plaintextData.subarray(0, 256)), cipher.final()]);
  const tail = plaintextData.subarray(256);
  const header = Buffer.from(`${V1_PREFIX}:${SERIAL}:${CODE}:`, "latin1");
  return Buffer.concat([header, head, tail]);
}

describe("decodeImageV1 (legacy eufysecurity)", () => {
  const original = Buffer.concat([
    Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
    Buffer.alloc(252, 0x7a),
    Buffer.from("PLAINTEXT-TAIL-SCAN-DATA"),
    Buffer.from([0xff, 0xd9]),
  ]);

  it("detects a v1 blob and rejects v2 / plain", () => {
    const blob = makeV1Blob(original);
    expect(isV1Image(blob)).toBe(true);
    expect(isV1Image(Buffer.from("v2_eufysecurity:T8:1:x"))).toBe(false);
    expect(isV1Image(Buffer.from([0xff, 0xd8, 0xff]))).toBe(false);
  });

  it("round-trips: decrypt recovers the original DATA bytes", () => {
    const blob = makeV1Blob(original);
    const out = decodeImageV1(blob, P2P_DID);
    expect(out).not.toBeNull();
    expect(out!.equals(original)).toBe(true);
    expect(out!.subarray(0, 2)).toEqual(Buffer.from([0xff, 0xd8]));
    expect(out!.subarray(-2)).toEqual(Buffer.from([0xff, 0xd9]));
  });

  it("returns null for a non-v1 buffer", () => {
    expect(decodeImageV1(Buffer.from("v2_eufysecurity:x"), P2P_DID)).toBeNull();
  });

  it("normalizes v1 and leaves unsupported media unchanged", () => {
    const blob = makeV1Blob(original);
    const unsupported = Buffer.from("v2_eufysecurity:x");

    expect(normalizePushImage(blob, P2P_DID)).toEqual(original);
    expect(normalizePushImage(blob)).toBe(blob);
    expect(normalizePushImage(unsupported, P2P_DID)).toBe(unsupported);
  });

  it("key derivation is deterministic for the same inputs", () => {
    expect(getImageKey(SERIAL, P2P_DID, CODE)).toBe(getImageKey(SERIAL, P2P_DID, CODE));
  });
});
