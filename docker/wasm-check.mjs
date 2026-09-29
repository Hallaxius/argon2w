import { readFileSync } from "node:fs";

const file = process.argv[2];
if (!file) {
  console.error("usage: wasm-check.mjs <argon2w.wasm>");
  process.exit(2);
}

let failures = 0;
function check(label, actual, expected) {
  const ok = actual === expected;
  console.log(`${ok ? "ok" : "FAIL"} ${label}`);
  if (!ok) {
    failures += 1;
  }
}

const bytes = readFileSync(file);
console.log(`wasm size: ${bytes.length}`);
const mod = await WebAssembly.compile(bytes);

const imports = WebAssembly.Module.imports(mod).map(
  (i) => `${i.module}.${i.name}:${i.kind}`,
);
check("imports allowlist", JSON.stringify(imports), JSON.stringify([
  "env.emscripten_notify_memory_growth:function",
]));

const expNames = WebAssembly.Module.exports(mod).map((e) => e.name);
const required = [
  "memory",
  "argon2w_alloc",
  "argon2w_free",
  "argon2w_error_message",
  "argon2w_hash_raw",
  "argon2w_encoded_len",
  "argon2w_hash_encoded",
  "argon2w_verify",
];
for (const name of required) {
  check(`export present ${name}`, expNames.includes(name), true);
}
const unexpected = expNames.filter(
  (n) =>
    !required.includes(n) &&
    !/^(__indirect_function_table|table|setThrew|_initialize|_?emscripten_|stack)/.test(n),
);
check("no unexpected exports", JSON.stringify(unexpected), JSON.stringify([]));

const instance = await WebAssembly.instantiate(mod, {
  env: { emscripten_notify_memory_growth: () => {} },
});
const wasm = instance.exports;
if (typeof wasm._initialize === "function") {
  wasm._initialize();
}
const mem = () => new Uint8Array(wasm.memory.buffer);
const hex = (u8) => Buffer.from(u8).toString("hex");
function readCString(ptr) {
  const bytes = mem();
  if (!Number.isSafeInteger(ptr) || ptr < 0 || ptr >= bytes.length) {
    throw new RangeError("invalid Wasm C-string pointer");
  }
  let end = ptr;
  while (end < bytes.length && bytes[end] !== 0) {
    end += 1;
  }
  if (end === bytes.length) {
    throw new RangeError("unterminated Wasm C string");
  }
  return Buffer.from(bytes.subarray(ptr, end)).toString();
}

function allocCopy(data) {
  if (data.length === 0) {
    return 0;
  }
  const ptr = wasm.argon2w_alloc(data.length);
  if (ptr === 0) {
    throw new Error("alloc failed");
  }
  mem().set(data, ptr);
  return ptr;
}
const fill = (n, b) => new Uint8Array(n).fill(b);
const msg = (code) => readCString(wasm.argon2w_error_message(code));

function hashRaw(pwd, salt, secret, ad, t, m, lanes, outlen, type = 2, version = 19) {
  const pp = allocCopy(pwd);
  const sp = allocCopy(salt);
  const kp = allocCopy(secret);
  const ap = allocCopy(ad);
  const op = wasm.argon2w_alloc(outlen);
  const code = wasm.argon2w_hash_raw(
    type, version, pp, pwd.length, sp, salt.length,
    kp, secret.length, ap, ad.length, t, m, lanes, op, outlen,
  );
  let tag = null;
  if (code === 0) {
    tag = hex(mem().slice(op, op + outlen));
  }
  for (const [p, s] of [[pp, pwd.length], [sp, salt.length], [kp, secret.length], [ap, ad.length], [op, outlen]]) {
    if (p !== 0) {
      wasm.argon2w_free(p, s);
    }
  }
  return { code, tag };
}

const rfc = hashRaw(fill(32, 1), fill(16, 2), fill(8, 3), fill(12, 4), 3, 32, 4, 32);
check("rfc code", rfc.code, 0);
check(
  "rfc tag",
  rfc.tag,
  "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
);

const small = hashRaw(
  new TextEncoder().encode("password"),
  new TextEncoder().encode("somesalt01"),
  new Uint8Array(0), new Uint8Array(0), 1, 8, 1, 32,
);
check("small code", small.code, 0);
check(
  "small tag",
  small.tag,
  "559af654b5f0df84a0245c92b04030a10b2a940ca856d0af0da84210c117e2d6",
);

const badVersion = hashRaw(fill(4, 0), fill(16, 2), fill(0, 0), fill(0, 0), 1, 8, 1, 32, 2, 16);
check("bad version rejected", badVersion.code !== 0, true);
console.log(`  version msg: ${msg(badVersion.code)}`);
const badSalt = hashRaw(fill(4, 0), fill(7, 2), fill(0, 0), fill(0, 0), 1, 8, 1, 32);
check("short salt rejected", badSalt.code !== 0, true);
check("error message non-empty", msg(badSalt.code).length > 0, true);

const pwd = new TextEncoder().encode("correct horse");
const salt = fill(16, 7);
const pp = allocCopy(pwd);
const sp = allocCopy(salt);
const op = wasm.argon2w_alloc(32);
const elen = wasm.argon2w_encoded_len(1, 8, 1, 16, 32);
check("encoded_len sane", elen > 32 && elen < 512, true);
const ep = wasm.argon2w_alloc(elen);
const hcode = wasm.argon2w_hash_encoded(
  2, 19, pp, pwd.length, sp, 16, 0, 0, 0, 0, 1, 8, 1, op, 32, ep, elen,
);
check("hash_encoded code", hcode, 0);
const wiped = mem().slice(pp, pp + pwd.length);
check("password buffer wiped after hash", hex(wiped), "00".repeat(pwd.length));
const phc = readCString(ep);
check(
  "phc shape",
  /^\$argon2id\$v=19\$m=8,t=1,p=1\$[^$]+\$[^$]+$/.test(phc),
  true,
);
const ep2bytes = new TextEncoder().encode(phc);
const ep2nul = new Uint8Array(ep2bytes.length + 1);
ep2nul.set(ep2bytes, 0);
const ep2 = allocCopy(ep2nul);
const pp2 = allocCopy(pwd);
const vok = wasm.argon2w_verify(ep2, pp2, pwd.length, 0, 0, 0, 0);
check("verify ok", vok, 0);
const wrong = allocCopy(new TextEncoder().encode("wrong password"));
const vbad = wasm.argon2w_verify(
  ep2, wrong, "wrong password".length, 0, 0, 0, 0,
);
check("verify mismatch rejected", vbad !== 0, true);

const before = wasm.memory.buffer.byteLength;
const big = hashRaw(fill(4, 0), fill(16, 4), fill(0, 0), fill(0, 0), 1, 32768, 1, 16);
const after = wasm.memory.buffer.byteLength;
check("big-mem code", big.code, 0);
check("memory grew", after > before, true);
check("memory fits 32 MiB", after >= 32768 * 1024, true);
const again = hashRaw(fill(4, 0), fill(16, 2), fill(0, 0), fill(0, 0), 1, 8, 1, 32);
check("post-growth hash ok", again.code, 0);
const over = hashRaw(fill(4, 0), fill(16, 5), fill(0, 0), fill(0, 0), 1, 70000, 1, 16);
check("over-ceiling hash_raw rejected", over.code, -15);
const overTime = hashRaw(fill(4, 0), fill(16, 5), fill(0, 0), fill(0, 0), 0xffffffff, 8, 1, 16);
check("over-ceiling time rejected", overTime.code, -13);
const overLanes = hashRaw(fill(4, 0), fill(16, 5), fill(0, 0), fill(0, 0), 1, 8, 0xffffffff, 16);
check("over-ceiling lanes rejected", overLanes.code, -17);
const overPhc = "$argon2id$v=19$m=1073741824,t=1,p=1$c29tZXNhbHQwMQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const overBytes = new TextEncoder().encode(overPhc);
const overNul = new Uint8Array(overBytes.length + 1);
overNul.set(overBytes, 0);
const overPtr = allocCopy(overNul);
const overPwd = allocCopy(new TextEncoder().encode("password01"));
check(
  "over-ceiling verify rejected",
  wasm.argon2w_verify(overPtr, overPwd, 10, 0, 0, 0, 0),
  -15,
);

const oomPtr = wasm.argon2w_alloc(100 * 1024 * 1024);
check("over-max alloc returns NULL", oomPtr, 0);

if (failures > 0) {
  console.error(`${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("wasm-check: all green");
