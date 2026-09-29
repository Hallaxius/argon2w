import { readFileSync } from "node:fs";

const file = process.argv[2];
if (!file) {
  console.error("usage: inspect-wasm.mjs <file>");
  process.exit(2);
}
const bytes = readFileSync(file);
const mod = await WebAssembly.compile(bytes);
console.log(`file: ${file}`);
console.log(`size: ${bytes.length}`);
console.log("imports:");
for (const imp of WebAssembly.Module.imports(mod)) {
  console.log(`  ${imp.module}.${imp.name} : ${imp.kind}`);
}
console.log("exports:");
for (const exp of WebAssembly.Module.exports(mod)) {
  console.log(`  ${exp.name} : ${exp.kind}`);
}
