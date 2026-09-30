# argon2w

[![npm version](https://img.shields.io/npm/v/%40hallaxius%2Fargon2w?label=npm)](https://www.npmjs.com/package/@hallaxius/argon2w)
[![CI](https://img.shields.io/github/actions/workflow/status/Hallaxius/argon2w/ci.yaml?branch=main&label=CI)](https://github.com/Hallaxius/argon2w/actions/workflows/ci.yaml)
[![Apache-2.0 license](https://img.shields.io/github/license/Hallaxius/argon2w)](LICENSE)

Argon2id password hashing for **Cloudflare Workers and Node.js**. Built on the PHC Argon2 reference implementation compiled to a standalone SIMD WebAssembly module, argon2w returns standard PHC strings for storage and verifies them without a native addon.

### Highlights

- **Portable:** use the same async API in Node.js 24+ and Cloudflare Workers.
- **No native addon or runtime dependencies:** the compiled `.wasm` ships with the package; consumers do not need Bun or Emscripten.
- **PHC-compatible:** hashes use the standard Argon2id PHC string format and a fresh random salt by default.
- **Explicit costs:** named profiles, custom parameters, bounded verification, and rehash assessment are available.

## Install

```sh
npm install @hallaxius/argon2w
# or: pnpm add @hallaxius/argon2w
# or: yarn add @hallaxius/argon2w
# or: bun add @hallaxius/argon2w
```

The package is ESM-only; there is no CommonJS build, so use `import` or a dynamic `import()` from CommonJS code.

## Hash and verify

```js
import { hash, verify } from "@hallaxius/argon2w";

const encoded = await hash("correct horse battery staple", { profile: "standard" });

const authenticated = await verify(encoded, "correct horse battery staple");
if (!authenticated) throw new Error("Invalid credentials");
```

Store `encoded` as the password verifier, never the password itself.

`hash()` generates a fresh 16-byte salt unless you supply one. Its defaults are `m=19456` KiB, `t=3`, `p=1`, with a 32-byte tag. The result is an Argon2id v=19 (`0x13`) PHC string — store the entire string.

`verify()` returns `false` for a wrong password, a malformed PHC string, or one exceeding the configured cost limits. Invalid API arguments and internal failures can throw, so handle errors at your application boundary.

## Node.js

Node.js 24 or newer loads the packaged `.wasm` asset automatically. The `hash()` and `verify()` example above works without calling `configureWasm()`; configure it only when the automatic file-based fallback is unavailable.

## Profiles

Pick a named profile instead of remembering the numbers:

```js
import { createProfile, hash, profiles } from "@hallaxius/argon2w";

const encoded = await hash("password", { profile: "m16t2" });
const available = Object.keys(profiles);

const custom = createProfile({
  memoryCost: 8192,
  timeCost: 3,
  parallelism: 2,
  hashLength: 32,
});
const other = await hash("password", { ...custom });
```

| Profile | Memory (KiB) | Passes (`t`) | Lanes (`p`) | Tag (bytes) |
| --- | ---: | ---: | ---: | ---: |
| `experimental` | 2048 | 1 | 1 | 32 |
| `m8t2` | 8192 | 2 | 1 | 32 |
| `m16t2` | 16384 | 2 | 1 | 32 |
| `standard` | 19456 | 3 | 1 | 32 |
| `m32t3` | 32768 | 3 | 1 | 32 |
| `m32t4` | 32768 | 4 | 1 | 32 |

Names describe costs. They are not a security certification or a CPU-time guarantee. Omitting `profile` uses the original defaults, and explicit `timeCost`, `memoryCost`, `parallelism` and `hashLength` still work. Do not combine a named profile with explicit cost fields — the call throws rather than silently overriding parameters. A custom profile is an immutable, validated cost object; spread it into `hash()` or `hashRaw()` and pass `salt`, `secret` or `associatedData` separately on each call.

## Rehash policy

```js
import { assessRehash, needsRehash, verify } from "@hallaxius/argon2w";

const ok = await verify(encoded, password);
if (ok && needsRehash(encoded, { memoryCost: 19456, timeCost: 3, parallelism: 1 })) {
  const upgraded = await hash(password, { profile: "standard" });
}

const assessment = assessRehash(encoded, "standard");
```

`assessRehash(encoded, profileNameOrCustomProfile)` returns `"matches"`, `"below-target"`, `"above-target"`, `"different-parameters"` or `"unparseable"`. It compares encoded **m/t/p** costs and Argon2id version, not tag length or password validity. Call `verify()` first and migrate only a verified password. `above-target` means keep the stronger hash rather than downgrade it.

`needsRehash()` keeps its original exact-field comparison and can return `true` even for a hash that is above the target.

## Cloudflare Workers

Import the public Wasm subpath and configure it once at startup. The subpath resolves to a `WebAssembly.Module`:

```js
import argon2Wasm from "@hallaxius/argon2w/wasm";
import { configureWasm, hash, verify } from "@hallaxius/argon2w";

configureWasm(argon2Wasm);

export default {
  async fetch(request) {
    const ok = await verify(encodedFromYourDatabase, passwordFromRequest);
    return new Response(ok ? "OK" : "FAIL", { status: ok ? 200 : 401 });
  },
};
```

Wrangler's default module rules load `.wasm` imports as compiled Wasm modules, so no extra rule is needed in a standard Worker config. If you define custom module rules that shadow the defaults, preserve a `CompiledWasm` rule for the package asset:

```toml
[[rules]]
type = "CompiledWasm"
globs = ["**/*.wasm"]
fallthrough = true
```

The previous `@hallaxius/argon2w/dist/argon2w.wasm` path remains available as a compatibility alias; new code should use `/wasm` instead of depending on the package's internal `dist` layout.

The package includes a TypeScript declaration for `@hallaxius/argon2w/wasm`, so no project-local module declaration is needed with a resolver that honors package `exports`. Wrangler resolves the `workerd` export to a small wrapper that imports the Wasm asset relatively.

Hash when setting a password and verify a *stored* PHC string when authenticating. Do not hash on every request.

`configureWasm()` also accepts raw Wasm bytes (`Uint8Array`) and starts instantiation eagerly, so the first call does not pay compilation. Call it once during module initialization. `resetWasmCache()` discards a cached instance after an out-of-band trap; the normal entry points already reset themselves on trap-class failures.

See [Node.js](#nodejs) for the automatic file-based Wasm loading behavior in Node.

## Choosing costs

`parallelism` is the encoded Argon2 lane count, not a count of Worker threads. The official `ARGON2_NO_THREADS` build runs lanes serially but does **not** rewrite `p` to 1.

Costs are the main driver of CPU time. Test against your real traffic and your plan's CPU budget before committing to a profile. A Free-plan measurement at the `experimental` costs recorded one hash-concurrency event at 11 ms against a 10 ms ceiling, with no CPU-limit exceptions in that run. That is a measurement of one workload, not a guarantee for yours.

The library never silently lowers `m`, `t` or `p` in response to a plan limit, load, or an error. A request that does not fit your budget fails visibly rather than quietly hashing with weaker parameters.

## API reference

Memory sizes are in **KiB**. Passwords may be a string (UTF-8 encoded) or `Uint8Array`.

| API | Result | Details |
| --- | --- | --- |
| `hash(password, options?)` | `Promise<string>` | Encoded Argon2id PHC string; random salt unless `options.salt` is provided. |
| `hashRaw(password, options?)` | `Promise<Uint8Array>` | Raw tag. Pass an explicit salt if you need reproducibility; this format carries no costs or salt. |
| `profiles` | Frozen named configurations | Inspect available names and costs; `HashOptions.profile` selects one by name. |
| `createProfile(costs)` | Frozen cost object | Validates and copies custom m/t/p/tag length; spread into `hash()` or `hashRaw()`. |
| `assessRehash(encoded, target)` | Assessment string | Compares m/t/p without treating an above-target hash as an upgrade candidate. Throws `Argon2wError` for an invalid `target`; returns `"unparseable"` for any `encoded` that is not a well-formed Argon2id v1.3 string. |
| `verify(encoded, password, options?)` | `Promise<boolean>` | Enforces cost limits before expensive work. Supply the same `secret` and `associatedData` used at hash time. |
| `parsePHC(encoded)` | `{ type, version, memoryCost, timeCost, parallelism }` | Parses cost fields. Does not authenticate a password or validate the tag. Throws for malformed structure. |
| `needsRehash(encoded, policy)` | `boolean` | `true` for invalid, wrong-type or wrong-version strings, or a mismatch on the policy fields you supply. Does not verify a password. |
| `configureWasm(moduleOrBytes)` | `void` | Configure the Wasm source and start eager instantiation. |
| `resetWasmCache()` | `void` | Discard the cached instance for recovery. |
| `bytesToHex(bytes)` | `string` | Lowercase hex for raw tags. |
| `isVerifyInputFailure(code)` | `boolean` | Maps a C return code from `verify()`. **Inverted from the intuitive reading:** `true` means a benign input-driven failure, which `verify()` turns into `false`; `false` means an internal error, which `verify()` rethrows. Unknown codes default to `true`. |

Invalid arguments throw `Argon2wError` with a numeric `code`.

### HashOptions

| Field | Default | Range |
| --- | --- | --- |
| `profile` | — | One of the six profile names |
| `memoryCost` | 19456 | `max(8, 8 × parallelism)` to 32768 KiB |
| `timeCost` | 3 | 1 to 16 |
| `parallelism` | 1 | 1 to 16 |
| `hashLength` | 32 | 4 to 512 bytes |
| `salt` | random, 16 bytes | 8 to 1024 bytes |
| `secret` | — | up to 1024 bytes |
| `associatedData` | — | up to 1 MiB |
| `version` | 19 | 19 only |

Password input is limited to 1 MiB.

### VerifyOptions

| Field | Default | Notes |
| --- | --- | --- |
| `maxMemoryKib` | 32768 | Rejects a PHC above this before any allocation |
| `maxTimeCost` | 16 | `0` disables the check, making `verify()` return `false` for every PHC |
| `maxParallelism` | 16 | Same `0` behaviour |
| `secret` | — | Must match the value used at hash time |
| `associatedData` | — | Must match the value used at hash time |

Each limit accepts any integer from 0 to 4294967295. Keep these at or below the module's own boundary of 65536 if you need a stored hash with higher costs to remain verifiable — the module rejects anything above that as an ordinary `false`, indistinguishable from a wrong password. Choose limits appropriate to your request budget; never accept untrusted PHC costs without bounds.

### Rehash policy

`needsRehash()` takes optional `memoryCost`, `timeCost`, `parallelism` and `version` fields and compares only what you supply. Because a non-v1.3 string is already rejected, `version` never changes the result.

Neither `needsRehash()` nor `assessRehash()` inspects the tag length, so a hash stored with a dangerously short `hashLength` is reported as `matches`. Verify the password first, then apply your own minimum tag length before rehashing.

The exported `MIN_*` / `MAX_*` constants describe the JavaScript boundaries. The WebAssembly module additionally enforces 65536 on memory and time cost as a backstop, so those constants are not the module's absolute ceiling.

## Reporting issues

Use [Discussions](https://github.com/Hallaxius/argon2w/discussions) for questions and deployment guidance. Use [Issues](https://github.com/Hallaxius/argon2w/issues) for reproducible failures; include your runtime, the parameters you used, and a minimal test case — without real passwords or stored PHC strings.

For contribution setup and local checks, see [CONTRIBUTING.md](CONTRIBUTING.md). To report a security vulnerability, follow [SECURITY.md](SECURITY.md) rather than opening a public issue.
