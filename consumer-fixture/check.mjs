import { hash, verify } from "@hallaxius/argon2w";
if (!import.meta.resolve('@hallaxius/argon2w/dist/argon2w.wasm').endsWith('/argon2w.wasm')) {
  throw new Error('Wasm subpath resolution failed');
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
