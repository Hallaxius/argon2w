import { hash, verify } from "@hallaxius/argon2w";

for (const specifier of [
  "@hallaxius/argon2w/wasm",
  "@hallaxius/argon2w/dist/argon2w.wasm",
]) {
  if (!import.meta.resolve(specifier).endsWith("/dist/argon2w.wasm")) {
    throw new Error(`Wasm subpath resolution failed: ${specifier}`);
  }
}

const encoded = await hash("type-check-pw", {
  timeCost: 1,
  memoryCost: 8192,
  parallelism: 1,
});
const ok = await verify(encoded, "type-check-pw");
if (!ok) {
  throw new Error("consumer check failed");
}
console.log("consumer ESM OK");
