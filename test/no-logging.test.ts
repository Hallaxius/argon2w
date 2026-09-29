import { describe, expect, test } from "bun:test";
import { hash, hashRaw, verify } from "../src/index.ts";

describe("no sensitive logging", () => {
  test("hash/hashRaw/verify never call console sinks", async () => {
    const calls: unknown[][] = [];
    const methods = ["log", "warn", "error", "debug", "info"] as const;
    const originals = methods.map((m) => console[m]);
    for (const m of methods) {
      console[m] = (...args: unknown[]) => {
        calls.push(args);
      };
    }
    try {
      const sentinel = "S3cr3t-sentinel-pw";
      const salt = new TextEncoder().encode("sentinel-salt-00");
      const encoded = await hash(sentinel, {
        salt,
        timeCost: 1,
        memoryCost: 8,
        parallelism: 1,
      });
      await verify(encoded, sentinel);
      await verify(encoded, "wrong");
      await hashRaw(sentinel, {
        salt,
        timeCost: 1,
        memoryCost: 8,
        parallelism: 1,
      });
    } finally {
      methods.forEach((m, i) => {
        console[m] = originals[i] as never;
      });
    }
    expect(calls.length).toBe(0);
  });
});
