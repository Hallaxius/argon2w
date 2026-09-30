import { assessRehash, createProfile, hash, hashRaw, needsRehash, profiles, verify } from "@hallaxius/argon2w";
import type wasmModule from "@hallaxius/argon2w/wasm";

const wasmTypeCheck: typeof wasmModule | undefined = undefined;

async function main(): Promise<void> {
  const encoded: string = await hash("type-check-pw", {
    timeCost: 1,
    memoryCost: 8,
    parallelism: 1,
  });
  const ok: boolean = await verify(encoded, "type-check-pw");
  const stale: boolean = needsRehash(encoded, {
    timeCost: 1,
    memoryCost: 8,
    parallelism: 1,
  });
  const tag: Uint8Array = await hashRaw("type-check-pw", {
    salt: new Uint8Array(16).fill(7),
    timeCost: 1,
    memoryCost: 8,
    parallelism: 1,
  });
  const preset: string = await hash("type-check-pw", { profile: "experimental" });
  const assessment: string = assessRehash(preset, "experimental");
  const custom = createProfile({ ...profiles.m8t2 });
  const customHash: string = await hash("type-check-pw", { ...custom });
  if (!ok || stale || tag.length !== 32 || assessment !== "matches" || assessRehash(customHash, custom) !== "matches") {
    throw new Error("consumer typecheck failed");
  }
  console.log("consumer types OK");
}

await main();
