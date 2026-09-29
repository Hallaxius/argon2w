import { describe, expect, test } from "bun:test";
import { bytesToHex, hashRaw } from "../src/index.ts";

const EXPECTED_TAG =
  "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";

function filled(length: number, byte: number): Uint8Array {
  const out = new Uint8Array(length);
  out.fill(byte);
  return out;
}

describe("RFC 9106 section 5.3 KAT (Argon2id)", () => {
  test("hashRaw matches the independent oracle tag", async () => {
    const tag = await hashRaw(filled(32, 0x01), {
      salt: filled(16, 0x02),
      secret: filled(8, 0x03),
      associatedData: filled(12, 0x04),
      timeCost: 3,
      memoryCost: 32,
      parallelism: 4,
      hashLength: 32,
      version: 19,
    });
    expect(tag.length).toBe(32);
    expect(bytesToHex(tag)).toBe(EXPECTED_TAG);
  });
});
