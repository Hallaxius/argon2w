import { describe, expect, test } from "bun:test";
import { configureWasm, hash, resetWasmCache, verify } from "../src/index.ts";

async function loadWasmBytes(): Promise<Uint8Array> {
  return new Uint8Array(
    await Bun.file(new URL("../src/argon2w.wasm", import.meta.url)).arrayBuffer(),
  );
}

const FAST = { memoryCost: 8, timeCost: 1, parallelism: 1 } as const;

describe("configureWasm input contract", () => {
  test("rejects sources that are neither a Module nor a Uint8Array", async () => {
    const bytes = await loadWasmBytes();
    configureWasm(bytes);
    try {
      for (const bad of [
        "not-a-module",
        42,
        null,
        undefined,
        {},
        [1, 2, 3],
        new DataView(new ArrayBuffer(4)),
      ]) {
        const threw = (() => {
          try {
            configureWasm(bad as unknown as Uint8Array);
            return false;
          } catch (error) {
            return error instanceof TypeError;
          }
        })();
        expect(`configureWasm(${typeof bad}): ${threw}`).toBe(
          `configureWasm(${typeof bad}): true`,
        );
      }
    } finally {
      resetWasmCache();
      configureWasm(bytes);
    }
  });

  test("rejects an empty Uint8Array", async () => {
    const bytes = await loadWasmBytes();
    configureWasm(bytes);
    try {
      const threw = (() => {
        try {
          configureWasm(new Uint8Array(0));
          return false;
        } catch (error) {
          return error instanceof TypeError;
        }
      })();
      expect(`empty bytes: ${threw}`).toBe("empty bytes: true");
    } finally {
      resetWasmCache();
      configureWasm(bytes);
    }
  });

  test("defensively copies the bytes so later caller mutation cannot corrupt the module", async () => {
    const bytes = await loadWasmBytes();
    const copy = new Uint8Array(bytes);
    configureWasm(copy);
    try {
      copy.fill(0);
      const encoded = await hash("mutation-probe", FAST);
      expect(await verify(encoded, "mutation-probe")).toBe(true);
    } finally {
      resetWasmCache();
      configureWasm(bytes);
    }
  });

  test("still accepts bytes, a compiled Module, and recovers between configurations", async () => {
    const bytes = await loadWasmBytes();
    resetWasmCache();
    configureWasm(bytes);
    const fromBytes = await hash("bytes-path", FAST);
    expect(await verify(fromBytes, "bytes-path")).toBe(true);

    resetWasmCache();
    configureWasm(await WebAssembly.compile(bytes));
    const fromModule = await hash("module-path", FAST);
    expect(await verify(fromModule, "module-path")).toBe(true);

    resetWasmCache();
    configureWasm(bytes);
    const afterReset = await hash("recovered", FAST);
    expect(await verify(afterReset, "recovered")).toBe(true);
  });
});
