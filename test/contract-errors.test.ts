import { describe, expect, test } from "bun:test";
import {
  Argon2wError,
  DEFAULT_SALT_BYTES,
  MAX_AD_BYTES,
  MAX_MEMORY_KIB,
  MAX_PASSWORD_BYTES,
  MAX_SALT_BYTES,
  MAX_SECRET_BYTES,
  MIN_SALT_BYTES,
  configureWasm,
  hash,
  resetWasmCache,
  verify,
  type HashOptions,
  type PasswordInput,
  type VerifyOptions,
} from "../src/index.ts";

const FAST = { memoryCost: 8, timeCost: 1, parallelism: 1 } as const;

async function loadWasmBytes(): Promise<Uint8Array> {
  return new Uint8Array(
    await Bun.file(new URL("../src/argon2w.wasm", import.meta.url)).arrayBuffer(),
  );
}

function saltBytesOf(encoded: string): Uint8Array {
  const b64 = encoded.split("$")[4] as string;
  return new Uint8Array(Buffer.from(b64, "base64"));
}

async function expectArgon2wError(
  label: string,
  run: () => unknown | Promise<unknown>,
  code: number,
): Promise<void> {
  try {
    await run();
  } catch (error) {
    const ok =
      error instanceof Argon2wError &&
      error.code === code &&
      error.name === "Argon2wError";
    expect(`${label}: ${ok}`).toBe(`${label}: true`);
    return;
  }
  expect(`${label}: threw`).toBe(`${label}: threw`);
}

describe("verify() option validation", () => {
  const bad: Array<[string, VerifyOptions]> = [
    ["maxMemoryKib non-integer", { maxMemoryKib: 1.5 }],
    ["maxMemoryKib negative", { maxMemoryKib: -1 }],
    ["maxMemoryKib NaN", { maxMemoryKib: Number.NaN }],
    ["maxTimeCost non-integer", { maxTimeCost: 1.5 }],
    ["maxTimeCost negative", { maxTimeCost: -1 }],
    ["maxParallelism non-integer", { maxParallelism: 1.5 }],
    ["maxParallelism negative", { maxParallelism: -1 }],
  ];

  test("rejects out-of-range cost policy bounds with code -30", async () => {
    const encoded = await hash("policy-probe", FAST);
    for (const [label, options] of bad) {
      await expectArgon2wError(
        label,
        () => verify(encoded, "policy-probe", options),
        -30,
      );
    }
  });

  test("accepts zero as a policy bound (0 disables that axis)", async () => {
    const encoded = await hash("policy-zero", FAST);
    expect(
      await verify(encoded, "policy-zero", {
        maxMemoryKib: 0,
        maxTimeCost: 0,
        maxParallelism: 0,
      }),
    ).toBe(false);
  });
});

describe("verify() input contract", () => {
  test("returns false without throwing for unparseable encoded input", async () => {
    expect(await verify("" as string, "pw")).toBe(false);
    expect(await verify(undefined as unknown as string, "pw")).toBe(false);
    expect(await verify("$argon2i$v=19$m=8,t=1,p=1$aaaa$bbbb", "pw")).toBe(false);
  });

  test("returns false for encoded strings above the 1 MiB bound", async () => {
    const oversized = `$argon2id$v=19$m=8,t=1,p=1$${"a".repeat((1 << 20) + 8)}`;
    expect(oversized.length > 1 << 20).toBe(true);
    expect(await verify(oversized, "pw")).toBe(false);
  });

  test("throws code -30 for a non-string, non-Uint8Array password", async () => {
    const encoded = await hash("pw-type", FAST);
    await expectArgon2wError(
      "number password",
      () => verify(encoded, 123 as unknown as PasswordInput),
      -30,
    );
    await expectArgon2wError(
      "null password",
      () => verify(encoded, null as unknown as PasswordInput),
      -30,
    );
    await expectArgon2wError(
      "plain object password",
      () => verify(encoded, {} as unknown as PasswordInput),
      -30,
    );
  });

  test("throws code -30 for secret and associatedData of the wrong type", async () => {
    const encoded = await hash("pw-ad", FAST);
    await expectArgon2wError(
      "string secret",
      () => verify(encoded, "pw", { secret: "s" as unknown as Uint8Array }),
      -30,
    );
    await expectArgon2wError(
      "number associatedData",
      () =>
        verify(encoded, "pw", {
          associatedData: 7 as unknown as Uint8Array,
        }),
      -30,
    );
  });

  test("throws code -30 when a password exceeds MAX_PASSWORD_BYTES", async () => {
    const encoded = await hash("pw-big", FAST);
    await expectArgon2wError(
      "oversized password",
      () => verify(encoded, "x".repeat(MAX_PASSWORD_BYTES + 1)),
      -30,
    );
  });
});

describe("verify() cost gate is enforced in JavaScript", () => {
  test("the same hash verifies under a permissive policy and fails under a narrow one", async () => {
    const encoded = await hash("gate-probe", FAST);
    expect(await verify(encoded, "gate-probe")).toBe(true);

    expect(await verify(encoded, "gate-probe", { maxTimeCost: 0 })).toBe(false);
    expect(await verify(encoded, "gate-probe", { maxMemoryKib: 1 })).toBe(false);
    expect(await verify(encoded, "gate-probe", { maxParallelism: 0 })).toBe(false);

    expect(
      await verify(encoded, "gate-probe", {
        maxTimeCost: FAST.timeCost,
        maxMemoryKib: FAST.memoryCost,
        maxParallelism: FAST.parallelism,
      }),
    ).toBe(true);
  });

  test("a rejected hash still reports a plain mismatch, not a policy error", async () => {
    const encoded = await hash("gate-mismatch", FAST);
    expect(await verify(encoded, "wrong-password")).toBe(false);
    expect(await verify(encoded, "wrong-password", { maxTimeCost: 0 })).toBe(false);
  });
});

describe("hash() option validation", () => {
  test("rejects non-object options", async () => {
    await expectArgon2wError(
      "null options",
      () => hash("pw", null as unknown as HashOptions),
      -30,
    );
    await expectArgon2wError(
      "number options",
      () => hash("pw", 5 as unknown as HashOptions),
      -30,
    );
  });

  test("rejects a salt that is not a Uint8Array", async () => {
    await expectArgon2wError(
      "string salt",
      () => hash("pw", { salt: "saltsalt" as unknown as Uint8Array }),
      -30,
    );
    await expectArgon2wError(
      "number salt",
      () => hash("pw", { salt: 16 as unknown as Uint8Array }),
      -30,
    );
  });

  test("enforces the exported salt bounds on both edges", async () => {
    const atMin = await hash("salt-min", {
      ...FAST,
      salt: new Uint8Array(MIN_SALT_BYTES).fill(7),
    });
    expect(atMin.startsWith("$argon2id$")).toBe(true);

    const atMax = await hash("salt-max", {
      ...FAST,
      salt: new Uint8Array(MAX_SALT_BYTES).fill(9),
    });
    expect(await verify(atMax, "salt-max")).toBe(true);

    await expectArgon2wError(
      "salt below MIN_SALT_BYTES",
      () => hash("pw", { ...FAST, salt: new Uint8Array(MIN_SALT_BYTES - 1) }),
      -30,
    );
    await expectArgon2wError(
      "salt above MAX_SALT_BYTES",
      () => hash("pw", { ...FAST, salt: new Uint8Array(MAX_SALT_BYTES + 1) }),
      -30,
    );
  });

  test("generates a DEFAULT_SALT_BYTES salt when none is supplied", async () => {
    const first = await hash("random-salt", FAST);
    const second = await hash("random-salt", FAST);
    expect(saltBytesOf(first).length).toBe(DEFAULT_SALT_BYTES);
    expect(saltBytesOf(first)).not.toEqual(saltBytesOf(second));
  });

  test("accepts inputs at the exported size ceilings", async () => {
    const bigPassword = "p".repeat(MAX_PASSWORD_BYTES);
    const encoded = await hash(bigPassword, {
      ...FAST,
      associatedData: new Uint8Array(MAX_AD_BYTES).fill(3),
      secret: new Uint8Array(MAX_SECRET_BYTES).fill(4),
    });
    expect(
      await verify(encoded, bigPassword, {
        associatedData: new Uint8Array(MAX_AD_BYTES).fill(3),
        secret: new Uint8Array(MAX_SECRET_BYTES).fill(4),
      }),
    ).toBe(true);
  });

  test("rejects associatedData and secret above their ceilings", async () => {
    await expectArgon2wError(
      "associatedData above MAX_AD_BYTES",
      () => hash("pw", { ...FAST, associatedData: new Uint8Array(MAX_AD_BYTES + 1) }),
      -30,
    );
    await expectArgon2wError(
      "secret above MAX_SECRET_BYTES",
      () => hash("pw", { ...FAST, secret: new Uint8Array(MAX_SECRET_BYTES + 1) }),
      -30,
    );
    await expectArgon2wError(
      "password above MAX_PASSWORD_BYTES",
      () => hash("x".repeat(MAX_PASSWORD_BYTES + 1), FAST),
      -30,
    );
  });

  test("keeps the default memory ceiling distinct from the C backstop", () => {
    expect(MAX_MEMORY_KIB).toBe(32768);
    expect(MAX_MEMORY_KIB).toBeLessThan(65536);
  });
});

describe("configureWasm accepts a compiled WebAssembly.Module", () => {
  test("hashes and verifies through the module path used by Workers", async () => {
    const bytes = await loadWasmBytes();
    resetWasmCache();
    try {
      configureWasm(new WebAssembly.Module(bytes));
      const encoded = await hash("module-path", FAST);
      expect(await verify(encoded, "module-path")).toBe(true);
      expect(await verify(encoded, "other")).toBe(false);
    } finally {
      resetWasmCache();
    }
    configureWasm(bytes);
    const encoded = await hash("module-recovery", FAST);
    expect(await verify(encoded, "module-recovery")).toBe(true);
  });
});
