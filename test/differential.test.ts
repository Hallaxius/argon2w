import { describe, expect, test } from "bun:test";
import { bytesToHex, hash, hashRaw, verify } from "../src/index.ts";

const NATIVE_SMALL_TAG =
  "559af654b5f0df84a0245c92b04030a10b2a940ca856d0af0da84210c117e2d6";
const NATIVE_SMALL_PHC =
  "$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHQwMQ$VZr2VLXw34SgJFySsEAwoQsqlAyoVtCvDahCEMEX4tY";

describe("native/Wasm differential", () => {
  test("small vector tag matches the native oracle byte for byte", async () => {
    const tag = await hashRaw("password", {
      salt: new TextEncoder().encode("somesalt01"),
      timeCost: 1,
      memoryCost: 8,
      parallelism: 1,
      hashLength: 32,
    });
    expect(bytesToHex(tag)).toBe(NATIVE_SMALL_TAG);
  });

  test("native PHC verifies under Wasm, wrong password does not", async () => {
    expect(await verify(NATIVE_SMALL_PHC, "password")).toBe(true);
    expect(await verify(NATIVE_SMALL_PHC, "wrongpwd")).toBe(false);
  });

  test("Wasm PHC for the same inputs matches the native PHC exactly", async () => {
    const encoded = await hash("password", {
      salt: new TextEncoder().encode("somesalt01"),
      timeCost: 1,
      memoryCost: 8,
      parallelism: 1,
      hashLength: 32,
    });
    expect(encoded).toBe(NATIVE_SMALL_PHC);
  });
});
