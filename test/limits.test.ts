import { describe, expect, test } from "bun:test";
import {
  Argon2wError,
  MAX_MEMORY_KIB,
  hash,
  hashRaw,
  needsRehash,
  parsePHC,
  verify,
} from "../src/index.ts";
import { getWasm } from "../src/wasm.ts";

function filled(length: number, byte: number): Uint8Array {
  const out = new Uint8Array(length);
  out.fill(byte);
  return out;
}

const tiny = { timeCost: 1, memoryCost: 8, parallelism: 1 };

describe("input validation", () => {
  test("rejects out-of-range parameters with Argon2wError", async () => {
    const salt = filled(16, 1);
    const cases: Array<[string, Record<string, unknown>]> = [
      ["timeCost 0", { ...tiny, timeCost: 0 }],
      ["timeCost 17", { ...tiny, timeCost: 17 }],
      ["memoryCost below 8*p", { ...tiny, memoryCost: 7 }],
      ["parallelism 0", { ...tiny, parallelism: 0 }],
      ["parallelism 17", { ...tiny, parallelism: 17 }],
      ["version 16", { ...tiny, version: 16 }],
      ["salt 7 bytes", { ...tiny, salt: filled(7, 1) }],
      ["salt 1025 bytes", { ...tiny, salt: filled(1025, 1) }],
      ["secret 1025 bytes", { ...tiny, secret: filled(1025, 9) }],
      ["hashLength 3", { ...tiny, hashLength: 3 }],
      ["hashLength 513", { ...tiny, hashLength: 513 }],
    ];
    for (const [label, options] of cases) {
      let error: unknown = null;
      try {
        await hashRaw("password", { salt, ...options });
      } catch (error_) {
        error = error_;
      }
      expect(error instanceof Argon2wError).toBe(true);
    }
  });

  test("rejects oversized memory before allocating", async () => {
    let error: unknown = null;
    try {
      await hashRaw("password", {
        salt: filled(16, 1),
        timeCost: 1,
        memoryCost: 1 << 30,
        parallelism: 1,
      });
    } catch (error_) {
      error = error_;
    }
    expect(error instanceof Argon2wError).toBe(true);
    expect((error as Argon2wError).code).toBe(-30);
  });

  test("accepts an empty password and binary inputs", async () => {
    const salt = filled(16, 2);
    const tag = await hashRaw(new Uint8Array([0, 255, 1, 0]), {
      ...tiny,
      salt,
    });
    expect(tag.length).toBe(32);
    const empty = await hashRaw("", { ...tiny, salt });
    expect(empty.length).toBe(32);
  });

  test("does not normalize Unicode: NFC and NFD differ", async () => {
    const salt = filled(16, 3);
    const nfc = await hashRaw("é", { ...tiny, salt });
    const nfd = await hashRaw("é", { ...tiny, salt });
    expect(Buffer.from(nfc).toString("hex")).not.toBe(
      Buffer.from(nfd).toString("hex"),
    );
    const asBytes = await hashRaw(new TextEncoder().encode("é"), {
      ...tiny,
      salt,
    });
    expect(Buffer.from(nfc).toString("hex")).toBe(
      Buffer.from(asBytes).toString("hex"),
    );
  });
});

describe("needsRehash()", () => {
  test("matches policy, flags drift, type and malformed input", async () => {
    const encoded = await hash("password", {
      timeCost: 1,
      memoryCost: 8,
      parallelism: 1,
    });
    const policy = { timeCost: 1, memoryCost: 8, parallelism: 1 };
    expect(needsRehash(encoded, policy)).toBe(false);
    expect(needsRehash(encoded, { ...policy, memoryCost: 16 })).toBe(true);
    expect(needsRehash(encoded, { ...policy, timeCost: 2 })).toBe(true);
    expect(needsRehash(encoded, { ...policy, parallelism: 2 })).toBe(true);
    expect(needsRehash("garbage", policy)).toBe(true);
    const asI = encoded.replace("$argon2id$", "$argon2i$");
    expect(needsRehash(asI, policy)).toBe(true);
    const parsed = parsePHC(encoded);
    expect(parsed.type).toBe("argon2id");
    expect(parsed.version).toBe(19);
    expect(parsed.memoryCost).toBe(8);
  });
});

describe("memory growth and concurrency", () => {
  test("over-max Wasm allocation fails closed instead of trapping", async () => {
    const wasm = await getWasm();
    expect(wasm.argon2w_alloc(100 * 1024 * 1024)).toBe(0);
  });

  test(`hashes with memoryCost ${MAX_MEMORY_KIB} KiB beyond the 16 MiB initial memory`, async () => {
    const tag = await hashRaw("password", {
      salt: filled(16, 4),
      timeCost: 1,
      memoryCost: MAX_MEMORY_KIB,
      parallelism: 1,
      hashLength: 16,
    });
    expect(tag.length).toBe(16);
  });

  test("concurrent hashes are independent", async () => {    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        hash(`password-${i}`, {
          salt: filled(16, 10 + i),
          timeCost: 1,
          memoryCost: 8,
          parallelism: 1,
        }),
      ),
    );
    expect(new Set(results).size).toBe(8);
    for (let i = 0; i < 8; i += 1) {
      expect(await verify(results[i] as string, `password-${i}`)).toBe(true);
      expect(await verify(results[i] as string, "wrong")).toBe(false);
    }
  });
});
