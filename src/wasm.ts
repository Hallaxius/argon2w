export interface Argon2wExports {
  memory: WebAssembly.Memory;
  _initialize(): void;
  argon2w_alloc(size: number): number;
  argon2w_free(ptr: number, size: number): void;
  argon2w_error_message(code: number): number;
  argon2w_hash_raw(
    type: number,
    version: number,
    pwd: number,
    pwdlen: number,
    salt: number,
    saltlen: number,
    secret: number,
    secretlen: number,
    ad: number,
    adlen: number,
    tCost: number,
    mCost: number,
    lanes: number,
    out: number,
    outlen: number,
  ): number;
  argon2w_encoded_len(
    tCost: number,
    mCost: number,
    lanes: number,
    saltlen: number,
    outlen: number,
  ): number;
  argon2w_hash_encoded(
    type: number,
    version: number,
    pwd: number,
    pwdlen: number,
    salt: number,
    saltlen: number,
    secret: number,
    secretlen: number,
    ad: number,
    adlen: number,
    tCost: number,
    mCost: number,
    lanes: number,
    out: number,
    outlen: number,
    encoded: number,
    encodedlen: number,
  ): number;
  argon2w_verify(
    encoded: number,
    pwd: number,
    pwdlen: number,
    secret: number,
    secretlen: number,
    ad: number,
    adlen: number,
  ): number;
}

let configured:
  | { kind: "module"; module: WebAssembly.Module }
  | { kind: "bytes"; bytes: Uint8Array }
  | null = null;
let instancePromise: Promise<Argon2wExports> | null = null;

export function toOwned(data: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(data.length);
  out.set(data);
  return out;
}

export function configureWasm(source: WebAssembly.Module | Uint8Array): void {
  if (source instanceof WebAssembly.Module) {
    configured = { kind: "module", module: source };
  } else {
    if (!(source instanceof Uint8Array)) {
      throw new TypeError(
        "argon2w: configureWasm expects a WebAssembly.Module or a " +
          "Uint8Array of Wasm bytes",
      );
    }
    if (source.length === 0) {
      throw new TypeError("argon2w: configureWasm received an empty Uint8Array");
    }
    configured = { kind: "bytes", bytes: toOwned(source) };
  }
  instancePromise = null;
  void getWasm().catch(() => undefined);
}

async function resolveBytes(): Promise<Uint8Array<ArrayBuffer>> {
  if (configured !== null && configured.kind === "bytes") {
    return toOwned(configured.bytes);
  }
  const proc = (globalThis as { process?: { versions?: { node?: unknown } } })
    .process;
  if (typeof proc?.versions?.node !== "string") {
    throw new Error(
      "argon2w: no Wasm source configured and the runtime cannot read " +
        "argon2w.wasm from disk; call configureWasm(moduleOrBytes) " +
        "explicitly (required on Cloudflare Workers: import the .wasm file and pass it).",
    );
  }
  const fsSpecifier = "node:fs/promises";
  const pathSpecifier = "node:path";
  const urlSpecifier = "node:url";
  const fs = (await import(fsSpecifier)) as {
    readFile(path: string): Promise<Uint8Array>;
  };
  const path = (await import(pathSpecifier)) as {
    dirname(path: string): string;
    join(...parts: string[]): string;
  };
  const url = (await import(urlSpecifier)) as {
    fileURLToPath(url: string | URL): string;
  };
  const here = path.dirname(url.fileURLToPath(import.meta.url));
  const candidates = [
    path.join(here, "argon2w.wasm"),
    path.join(here, "..", "src", "argon2w.wasm"),
  ];
  for (const file of candidates) {
    try {
      return toOwned(new Uint8Array(await fs.readFile(file)));
    } catch {}
  }
  throw new Error(
    "argon2w: unable to locate argon2w.wasm; call configureWasm(moduleOrBytes) " +
      "explicitly (required on Cloudflare Workers: import the .wasm file and pass it).",
  );
}

function instantiate(
  module: WebAssembly.Module,
): Argon2wExports {
  const imports = {
    env: {
      emscripten_notify_memory_growth: () => {},
    },
  };
  const instance = new WebAssembly.Instance(module, imports);
  const exports = instance.exports as unknown as Argon2wExports;
  if (typeof exports._initialize === "function") {
    exports._initialize();
  }
  return exports;
}

export async function getWasm(): Promise<Argon2wExports> {
  if (instancePromise === null) {
    const pending = (async () => {
      if (configured !== null && configured.kind === "module") {
        return instantiate(configured.module);
      }
      const bytes = await resolveBytes();
      const compiled = await WebAssembly.compile(bytes);
      return instantiate(compiled);
    })();
    void pending.catch(() => {
      if (instancePromise === pending) {
        instancePromise = null;
      }
    });
    instancePromise = pending;
  }
  return instancePromise;
}

export function resetWasmCache(): void {
  instancePromise = null;
}

export function isTrapError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /unreachable|memory access out of bounds|table index is out of bounds|detached/i.test(
    message,
  );
}

export function memoryBytes(wasm: Argon2wExports): Uint8Array {
  return new Uint8Array(wasm.memory.buffer);
}

export function readCString(
  wasm: Argon2wExports,
  ptr: number,
  maxLength: number = 1 << 20,
): string {
  const mem = memoryBytes(wasm);
  if (!Number.isInteger(ptr) || ptr < 0 || ptr >= mem.length) {
    throw new RangeError(`argon2w: CString pointer ${ptr} out of range`);
  }
  if (!Number.isInteger(maxLength) || maxLength < 0) {
    throw new RangeError(`argon2w: invalid CString length ${maxLength}`);
  }
  const limit = Math.min(mem.length, ptr + maxLength);
  let end = ptr;
  while (end < limit && mem[end] !== 0) {
    end += 1;
  }
  if (end === limit) {
    throw new RangeError(`argon2w: unterminated CString at ${ptr}`);
  }
  return new TextDecoder().decode(mem.slice(ptr, end));
}
