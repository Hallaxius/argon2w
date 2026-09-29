import { describe, expect, test } from "bun:test";
import {
  Argon2wError,
  assessRehash,
  createProfile,
  EXPERIMENTAL_FREE_LOGIN_COSTS,
  hash,
  hashRaw,
  needsRehash,
  parsePHC,
  profiles,
  verify,
} from "../src/index.ts";

const salt = new Uint8Array(16).fill(7);

describe("named password profiles", () => {
  test("exports the six immutable cost configurations", () => {
    expect(Object.keys(profiles)).toEqual([
      "experimental", "m8t2", "m16t2", "standard", "m32t3", "m32t4",
    ]);
    expect(profiles.experimental).toBe(EXPERIMENTAL_FREE_LOGIN_COSTS);
    expect(Object.isFrozen(profiles)).toBe(true);
    for (const profile of Object.values(profiles)) {
      expect(Object.isFrozen(profile)).toBe(true);
      expect(profile.parallelism).toBe(1);
      expect(profile.hashLength).toBe(32);
    }
    expect([profiles.experimental, profiles.m8t2, profiles.m16t2, profiles.standard, profiles.m32t3, profiles.m32t4].map(
      ({ memoryCost, timeCost }) => [memoryCost, timeCost],
    )).toEqual([[2048, 1], [8192, 2], [16384, 2], [19456, 3], [32768, 3], [32768, 4]]);
  });

  test("each selection encodes exactly its requested m/t/p and verifies", async () => {
    for (const name of Object.keys(profiles) as Array<keyof typeof profiles>) {
      const selected = profiles[name];
      const encoded = await hash("profile-password", { profile: name, salt });
      expect(parsePHC(encoded)).toMatchObject({
        type: "argon2id", version: 19,
        memoryCost: selected.memoryCost,
        timeCost: selected.timeCost,
        parallelism: selected.parallelism,
      });
      expect(await verify(encoded, "profile-password")).toBe(true);
      expect(await verify(encoded, "wrong-password")).toBe(false);
      expect(assessRehash(encoded, name)).toBe("matches");
    }
  });

  test("raw tags preserve per-call salt and secret independently of profile", async () => {
    const secret = new Uint8Array([3, 4, 5]);
    const options = { salt, secret, profile: "experimental" as const };
    const fromProfile = await hashRaw("profile-password", options);
    const explicit = await hashRaw("profile-password", { salt, secret, ...profiles.experimental });
    expect(fromProfile).toEqual(explicit);
    expect(await hashRaw("profile-password", { ...options, secret: new Uint8Array([8]) })).not.toEqual(explicit);
  });

  test("keeps custom costs and verification limits independent", async () => {
    const custom = createProfile({ memoryCost: 8192, timeCost: 3, parallelism: 2, hashLength: 24 });
    expect(Object.isFrozen(custom)).toBe(true);
    const encoded = await hash("custom-password", { ...custom, salt });
    expect(parsePHC(encoded)).toMatchObject({ memoryCost: 8192, timeCost: 3, parallelism: 2 });
    expect(await verify(encoded, "custom-password")).toBe(true);
    expect(await verify(encoded, "custom-password", { maxTimeCost: 2 })).toBe(false);
    expect(assessRehash(encoded, custom)).toBe("matches");
    expect(needsRehash(encoded, { memoryCost: 8192, timeCost: 3, parallelism: 2 })).toBe(false);
  });

  test("rejects unknown, inherited, and mixed profile options instead of silently overriding costs", async () => {
    for (const profile of ["unknown", "toString", "__proto__", 10]) {
      await expect(hash("pw", { profile } as never)).rejects.toBeInstanceOf(Argon2wError);
    }
    await expect(hash("pw", { profile: "standard", timeCost: 1 })).rejects.toThrow("cannot be combined");
    await expect(hashRaw("pw", { profile: "m8t2", hashLength: 16 })).rejects.toThrow("cannot be combined");
    expect(() => assessRehash("invalid", "__proto__" as never)).toThrow(Argon2wError);
  });

  test("rejects invalid custom costs and copies caller-owned values", () => {
    const source = { memoryCost: 8192, timeCost: 2, parallelism: 1, hashLength: 32 };
    const custom = createProfile(source);
    source.memoryCost = 8;
    expect(custom.memoryCost).toBe(8192);
    expect(() => createProfile({ ...source, parallelism: 2 })).toThrow(Argon2wError);
    expect(() => createProfile({ ...source, timeCost: 17 })).toThrow(Argon2wError);
    expect(() => createProfile(null as never)).toThrow(Argon2wError);
  });
});

describe("rehash assessment", () => {
  test("distinguishes stronger, weaker, and mixed parameters without recommending a downgrade", async () => {
    const stronger = await hash("pw", { memoryCost: 16384, timeCost: 3, salt });
    const weaker = await hash("pw", { profile: "m8t2", salt });
    const mixed = await hash("pw", { memoryCost: 16384, timeCost: 1, salt });
    expect(assessRehash(stronger, "m8t2")).toBe("above-target");
    expect(needsRehash(stronger, profiles.m8t2)).toBe(true);
    expect(assessRehash(weaker, "standard")).toBe("below-target");
    expect(assessRehash(mixed, "m8t2")).toBe("different-parameters");
    expect(assessRehash("not-phc", "standard")).toBe("unparseable");
    expect(assessRehash(stronger.replace("argon2id", "argon2i"), "standard")).toBe("unparseable");
  });
});
