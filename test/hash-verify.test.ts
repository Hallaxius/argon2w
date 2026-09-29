import { describe, expect, test } from "bun:test";
import { hash, needsRehash, verify } from "../src/index.ts";

function filled(length: number, byte: number): Uint8Array {
  const out = new Uint8Array(length);
  out.fill(byte);
  return out;
}

function b64decode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

describe("hash() PHC encoding", () => {
  test("emits $argon2id$v=19$ with matching salt and tag", async () => {
    const salt = filled(16, 0x02);
    const encoded = await hash("password", {
      salt,
      timeCost: 3,
      memoryCost: 32,
      parallelism: 4,
      hashLength: 32,
    });
    expect(encoded.startsWith("$argon2id$v=19$m=32,t=3,p=4$")).toBe(true);
    const parts = encoded.split("$");
    expect(parts.length).toBe(6);
    expect(b64decode(parts[4] as string).join(",")).toBe(
      Array.from(salt).join(","),
    );
    expect(b64decode(parts[5] as string).length).toBe(32);
  });

  test("generates a random salt by default and differs across calls", async () => {
    const a = await hash("password", {
      timeCost: 1,
      memoryCost: 8,
      parallelism: 1,
    });
    const b = await hash("password", {
      timeCost: 1,
      memoryCost: 8,
      parallelism: 1,
    });
    expect(a).not.toBe(b);
    expect((a as string).split("$")[4]).not.toBe((b as string).split("$")[4]);
  });
});

describe("verify()", () => {
  test("accepts the correct password and rejects a wrong one", async () => {
    const encoded = await hash("correct horse", {
      timeCost: 1,
      memoryCost: 8,
      parallelism: 1,
    });
    expect(await verify(encoded, "correct horse")).toBe(true);
    expect(await verify(encoded, "correct horsf")).toBe(false);
    expect(await verify(encoded, "")).toBe(false);
  });

  test("honors secret and associated data", async () => {
    const secret = filled(8, 0x03);
    const ad = filled(12, 0x04);
    const encoded = await hash("password", {
      timeCost: 1,
      memoryCost: 8,
      parallelism: 1,
      secret,
      associatedData: ad,
    });
    expect(await verify(encoded, "password", { secret, associatedData: ad })).toBe(
      true,
    );
    expect(await verify(encoded, "password")).toBe(false);
    expect(
      await verify(encoded, "password", {
        secret,
        associatedData: filled(12, 0x05),
      }),
    ).toBe(false);
  });

  test("rejects malformed PHC without throwing", async () => {
    expect(await verify("not-a-phc-string", "password")).toBe(false);
    expect(await verify("$argon2id$v=19$m=8,t=1,p=1$abc", "password")).toBe(
      false,
    );
  });

  test("rejects argon2d/argon2i without throwing", async () => {
    const encoded = await hash("password", {
      timeCost: 1,
      memoryCost: 8,
      parallelism: 1,
    });
    for (const variant of ["argon2d", "argon2i"]) {
      const swapped = encoded.replace("$argon2id$", `$${variant}$`);
      expect(await verify(swapped, "password")).toBe(false);
      expect(
        needsRehash(swapped, { timeCost: 1, memoryCost: 8, parallelism: 1 }),
      ).toBe(true);
    }
  });
});
