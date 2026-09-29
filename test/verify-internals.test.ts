import { describe, expect, test } from "bun:test";
import {
  hash,
  isVerifyInputFailure,
  verify,
} from "../src/index.ts";
import {
  getWasm,
  isTrapError,
  memoryBytes,
  readCString,
  resetWasmCache,
} from "../src/wasm.ts";

describe("isVerifyInputFailure() mapping", () => {
  test("input-driven codes map to false", () => {
    for (const code of [
      -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -12, -13, -14, -15, -16,
      -17, -25, -26, -28, -29, -30, -32, -34, -35, -999,
    ]) {
      expect(isVerifyInputFailure(code)).toBe(true);
    }
  });

  test("internal codes do not map to false", () => {
    for (const code of [
      -1, -18, -19, -20, -21, -22, -23, -24, -27, -31, -33,
    ]) {
      expect(isVerifyInputFailure(code)).toBe(false);
    }
  });
});

describe("readCString() bounds", () => {
  test("rejects out-of-range pointers", async () => {
    const wasm = await getWasm();
    expect(() => readCString(wasm, -1)).toThrow(RangeError);
    expect(() => readCString(wasm, memoryBytes(wasm).length + 16)).toThrow(
      RangeError,
    );
  });

  test("rejects missing terminators and invalid bounds", async () => {
    const wasm = await getWasm();
    const ptr = wasm.argon2w_alloc(2);
    expect(ptr).not.toBe(0);
    memoryBytes(wasm).set([65, 66], ptr);
    try {
      expect(() => readCString(wasm, ptr, 2)).toThrow(RangeError);
      expect(() => readCString(wasm, ptr, Number.NaN)).toThrow(RangeError);
    } finally {
      wasm.argon2w_free(ptr, 2);
    }
  });
});

describe("Wasm singleton reset", () => {
  test("isTrapError recognizes trap-class failures only", () => {
    expect(isTrapError(new Error("unreachable executed"))).toBe(true);
    expect(isTrapError(new Error("memory access out of bounds"))).toBe(true);
    expect(
      isTrapError(new Error("table index is out of bounds")),
    ).toBe(true);
    expect(isTrapError(new Error("detached ArrayBuffer"))).toBe(true);
    expect(isTrapError(new Error("argon2w: wasm allocation failed"))).toBe(
      false,
    );
    expect(isTrapError(new Error("password mismatch"))).toBe(false);
  });

  test("resetWasmCache() leaves the library usable", async () => {
    resetWasmCache();
    resetWasmCache();
    const encoded = await hash("post-reset", {
      timeCost: 1,
      memoryCost: 8,
      parallelism: 1,
    });
    expect(await verify(encoded, "post-reset")).toBe(true);
  });
});

describe("policy gate for foreign-type PHC", () => {
  test("argon2i costs above policy return false without hashing", async () => {
    const salt = Buffer.from(new Uint8Array(16).fill(7)).toString("base64");
    const tag = Buffer.from(new Uint8Array(32).fill(9)).toString("base64");
    const hostile =
      `$argon2i$v=19$m=8,t=2147483647,p=1$${salt}$${tag}`.replace(/=+$/, "");
    const started = Date.now();
    expect(await verify(hostile, "password")).toBe(false);
    expect(Date.now() - started).toBeLessThan(5000);
  });
});
