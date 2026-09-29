import { describe, expect, test } from "bun:test";
import { hash, needsRehash, parsePHC, verify } from "../src/index.ts";

let state = 0x12345678;
function rnd(n: number): number {
  state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
  return state % n;
}

function bytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    out[i] = rnd(256);
  }
  return out;
}

const MEMORYS = [8, 16, 32];
const TIMES = [1, 2, 3];
const LANES = [1, 2, 4];

describe("hash/verify/PHC properties (50 fixed seeds)", () => {
  test("round-trip, mismatch, PHC costs and policy hold on every case", async () => {
    for (let i = 0; i < 50; i += 1) {
      const parallelism = LANES[rnd(LANES.length)] as number;
      const drawn = MEMORYS[rnd(MEMORYS.length)] as number;
      const memoryCost = drawn >= 8 * parallelism ? drawn : 8 * parallelism;
      const timeCost = TIMES[rnd(TIMES.length)] as number;
      const hashLength = 4 + rnd(61);
      const salt = bytes(8 + rnd(25));
      const password = bytes(1 + rnd(64));
      const useSecret = rnd(2) === 0;
      const useAd = rnd(2) === 0;
      const secret = useSecret ? bytes(rnd(33)) : undefined;
      const associatedData = useAd ? bytes(rnd(64)) : undefined;

      const encoded = await hash(password, {
        salt,
        timeCost,
        memoryCost,
        parallelism,
        hashLength,
        ...(secret === undefined ? {} : { secret }),
        ...(associatedData === undefined ? {} : { associatedData }),
      });
      expect(await verify(encoded, password, { secret, associatedData })).toBe(
        true,
      );
      const wrong = Uint8Array.from(password);
      wrong[0] = (wrong[0] as number) ^ 0xff;
      expect(await verify(encoded, wrong, { secret, associatedData })).toBe(
        false,
      );

      const parsed = parsePHC(encoded);
      expect(parsed.type).toBe("argon2id");
      expect(parsed.version).toBe(19);
      expect(parsed.memoryCost).toBe(memoryCost);
      expect(parsed.timeCost).toBe(timeCost);
      expect(parsed.parallelism).toBe(parallelism);
      const policy = { memoryCost, timeCost, parallelism };
      expect(needsRehash(encoded, policy)).toBe(false);
      expect(needsRehash(encoded, { ...policy, timeCost: timeCost + 1 })).toBe(
        true,
      );
    }
  });
});
