import { describe, expect, test } from "bun:test";
import {
  EXPERIMENTAL_FREE_LOGIN_COSTS,
  bytesToHex,
  hash,
  verify,
} from "../src/index.ts";

function filled(length: number, byte: number): Uint8Array {
  const out = new Uint8Array(length);
  out.fill(byte);
  return out;
}

describe("EXPERIMENTAL_FREE_LOGIN_COSTS (Free login-hasher profile)", () => {
  test("pins the production-measured winner exactly", () => {
    expect(EXPERIMENTAL_FREE_LOGIN_COSTS).toEqual({
      memoryCost: 2048,
      timeCost: 1,
      parallelism: 1,
      hashLength: 32,
    });
  });

  test("is frozen against accidental mutation", () => {
    expect(Object.isFrozen(EXPERIMENTAL_FREE_LOGIN_COSTS)).toBe(true);
  });
  test("handles concurrent hash+verify at the pinned costs", async () => {
    const results = await Promise.all(
      Array.from({ length: 4 }, (_, i) =>
        (async () => {
          const encoded = await hash(`free-pwd-${i}`, {
            ...EXPERIMENTAL_FREE_LOGIN_COSTS,
            salt: filled(16, 20 + i),
          });
          expect(encoded.startsWith("$argon2id$v=19$m=2048,t=1,p=1$")).toBe(
            true,
          );
          expect(await verify(encoded, `free-pwd-${i}`)).toBe(true);
          expect(await verify(encoded, "wrong")).toBe(false);
          return encoded;
        })(),
      ),
    );
    expect(new Set(results).size).toBe(4);
  });
  test("hashes and verifies deterministically at the pinned costs", async () => {
    const salt = filled(16, 9);
    const a = await hash("password", {
      ...EXPERIMENTAL_FREE_LOGIN_COSTS,
      salt,
    });
    expect(a.startsWith("$argon2id$v=19$m=2048,t=1,p=1$")).toBe(true);
    expect(await verify(a, "password")).toBe(true);
    expect(await verify(a, "wrong")).toBe(false);
    const b = await hash("password", {
      ...EXPERIMENTAL_FREE_LOGIN_COSTS,
      salt,
    });
    const tagA = bytesToHex(
      new Uint8Array(Buffer.from(a.split("$")[5] as string, "base64")),
    );
    const tagB = bytesToHex(
      new Uint8Array(Buffer.from(b.split("$")[5] as string, "base64")),
    );
    expect(tagA).toBe(tagB);
  });
});
