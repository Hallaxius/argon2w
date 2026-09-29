import { describe, expect, test } from "bun:test";
import {
  Argon2wError,
  MAX_MEMORY_KIB,
  MAX_PARALLELISM,
  MAX_TIMECOST,
  hash,
  needsRehash,
  parsePHC,
  verify,
} from "../src/index.ts";

const tiny = { timeCost: 1, memoryCost: 8, parallelism: 1 };

async function parts(): Promise<{ salt: string; tag: string }> {
  const encoded = await hash("password", tiny);
  const segs = encoded.split("$");
  return { salt: segs[4] as string, tag: segs[5] as string };
}

function phc(params: string, salt: string, tag: string): string {
  return `$argon2id$v=19$${params}$${salt}$${tag}`;
}

describe("verify() never throws on out-of-range PHC", () => {
  test("huge memory cost returns false", async () => {
    const { salt, tag } = await parts();
    expect(await verify(phc("m=1073741824,t=1,p=1", salt, tag), "password")).toBe(
      false,
    );
  });

  test("zero/tiny memory cost returns false", async () => {
    const { salt, tag } = await parts();
    expect(await verify(phc("m=0,t=1,p=1", salt, tag), "password")).toBe(false);
    expect(await verify(phc("m=1,t=1,p=1", salt, tag), "password")).toBe(false);
  });

  test("zero time cost returns false", async () => {
    const { salt, tag } = await parts();
    expect(await verify(phc("m=8,t=0,p=1", salt, tag), "password")).toBe(false);
  });

  test("zero lanes returns false", async () => {
    const { salt, tag } = await parts();
    expect(await verify(phc("m=8,t=1,p=0", salt, tag), "password")).toBe(false);
  });

  test("short salt returns false", async () => {
    const { tag } = await parts();
    const shortSalt = Buffer.from([1, 2, 3, 4])
      .toString("base64")
      .replace(/=+$/, "");
    expect(await verify(phc("m=8,t=1,p=1", shortSalt, tag), "password")).toBe(
      false,
    );
  });

  test("wrong version and foreign type return false", async () => {
    const { salt, tag } = await parts();
    expect(
      await verify(`$argon2id$v=16$m=8,t=1,p=1$${salt}$${tag}`, "password"),
    ).toBe(false);
    expect(
      await verify(`$argon2i$v=19$m=8,t=1,p=1$${salt}$${tag}`, "password"),
    ).toBe(false);
  });

  test("non-string input returns false", async () => {
    expect(await verify(null as unknown as string, "password")).toBe(false);
  });
});

describe("verify() cost policy", () => {
  test("rejects costs above the policy without hashing", async () => {
    const { salt, tag } = await parts();
    const hostile = phc("m=8,t=2147483648,p=1", salt, tag);
    const started = Date.now();
    expect(await verify(hostile, "password")).toBe(false);
    expect(Date.now() - started).toBeLessThan(5000);
  });

  test("custom policy bounds are enforced", async () => {
    const encoded = await hash("password", {
      timeCost: 3,
      memoryCost: 32,
      parallelism: 2,
    });
    expect(await verify(encoded, "password")).toBe(true);
    expect(await verify(encoded, "password", { maxTimeCost: 1 })).toBe(false);
    expect(await verify(encoded, "password", { maxMemoryKib: 8 })).toBe(false);
    expect(await verify(encoded, "password", { maxParallelism: 1 })).toBe(
      false,
    );
    expect(
      await verify(encoded, "password", {
        maxTimeCost: 3,
        maxMemoryKib: 32,
        maxParallelism: 2,
      }),
    ).toBe(true);
  });

  test("default policy matches the documented hash caps", async () => {
    const encoded = await hash("password", {
      timeCost: MAX_TIMECOST,
      memoryCost: MAX_MEMORY_KIB,
      parallelism: 1,
      hashLength: 16,
      salt: new Uint8Array(16).fill(7),
    });
    expect(await verify(encoded, "password")).toBe(true);
    expect(
      await verify(encoded, "password", {
        maxMemoryKib: MAX_MEMORY_KIB,
        maxTimeCost: MAX_TIMECOST,
        maxParallelism: MAX_PARALLELISM,
      }),
    ).toBe(true);
  });
});

describe("parsePHC() strictness (mirrors upstream decode_string)", () => {
  test("rejects leading zeros like upstream decode_decimal", async () => {
    const { salt, tag } = await parts();
    expect(() =>
      parsePHC(phc("m=08,t=1,p=1", salt, tag)),
    ).toThrow(Argon2wError);
    expect(() =>
      parsePHC(`$argon2id$v=019$m=8,t=1,p=1$${salt}$${tag}`),
    ).toThrow(Argon2wError);
    expect(() =>
      parsePHC(phc("m=8,t=01,p=1", salt, tag)),
    ).toThrow(Argon2wError);
  });

  test("rejects values above UINT32_MAX like DECIMAL_U32", async () => {
    const { salt, tag } = await parts();
    expect(() =>
      parsePHC(phc("m=4294967296,t=1,p=1", salt, tag)),
    ).toThrow(Argon2wError);
    const parsed = parsePHC(phc("m=4294967295,t=1,p=1", salt, tag));
    expect(parsed.memoryCost).toBe(4294967295);
  });

  test("rejects over-long input before matching", () => {
    const big = `$argon2id$v=19$m=8,t=1,p=1$${"A".repeat(1 << 20)}$QQ`;
    expect(() => parsePHC(big)).toThrow(Argon2wError);
  });

  test("leading-zero PHC needs rehash (malformed, never verifies)", async () => {
    const { salt, tag } = await parts();
    const encoded = phc("m=08,t=1,p=1", salt, tag);
    expect(needsRehash(encoded, tiny)).toBe(true);
    expect(await verify(encoded, "password")).toBe(false);
  });
});
