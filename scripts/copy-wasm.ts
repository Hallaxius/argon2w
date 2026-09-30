import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
mkdirSync(join(root, "dist"), { recursive: true });
copyFileSync(join(root, "src", "argon2w.wasm"), join(root, "dist", "argon2w.wasm"));
copyFileSync(
  join(root, "src", "wasm-asset.d.ts"),
  join(root, "dist", "wasm-asset.d.ts"),
);
console.log("copied src/argon2w.wasm -> dist/argon2w.wasm");
console.log("copied src/wasm-asset.d.ts -> dist/wasm-asset.d.ts");
