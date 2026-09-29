import { describe, expect, test } from "bun:test";
import { configureWasm, hash, resetWasmCache } from "../src/index.ts";

async function loadWasmBytes(): Promise<Uint8Array> {
  return new Uint8Array(
    await Bun.file(new URL("../src/argon2w.wasm", import.meta.url)).arrayBuffer(),
  );
}

describe("eager instantiation at configureWasm()", () => {
  test("starts compilation immediately, before any hash/getWasm call", async () => {
    const bytes = await loadWasmBytes();
    const original = WebAssembly.compile;
    let compileCalls = 0;
    WebAssembly.compile = ((input: Parameters<typeof original>[0]) => {
      compileCalls += 1;
      return original(input);
    }) as typeof WebAssembly.compile;
    try {
      resetWasmCache();
      configureWasm(bytes);
      await new Promise((resolve) => setTimeout(resolve, 25));
      expect(compileCalls).toBeGreaterThanOrEqual(1);
    } finally {
      WebAssembly.compile = original;
      resetWasmCache();
    }
    configureWasm(bytes);
    const encoded = await hash("eager-smoke", {
      timeCost: 1,
      memoryCost: 8,
      parallelism: 1,
    });
    expect(encoded.startsWith("$argon2id$v=19$m=8,t=1,p=1$")).toBe(true);
  });

  test("eager failure is swallowed, never unhandled, and recovers", async () => {
    const rejections: unknown[] = [];
    const onUnhandled = (reason: unknown) => {
      rejections.push(reason);
    };
    process.on("unhandledRejection", onUnhandled);
    try {
      resetWasmCache();
      configureWasm(new Uint8Array([1, 2, 3]));
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(rejections).toEqual([]);
      const bytes = await loadWasmBytes();
      resetWasmCache();
      configureWasm(bytes);
      const encoded = await hash("eager-recover", {
        timeCost: 1,
        memoryCost: 8,
        parallelism: 1,
      });
      expect(encoded.startsWith("$argon2id$v=19$")).toBe(true);
      expect(rejections).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandled);
      resetWasmCache();
      configureWasm(await loadWasmBytes());
    }
  });
});
