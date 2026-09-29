import {
  configureWasm,
  getWasm,
  isTrapError,
  memoryBytes,
  readCString,
  resetWasmCache,
  toOwned,
  type Argon2wExports,
} from "./wasm.ts";

export { configureWasm, resetWasmCache };

export const ARGON2_VERSION_13 = 19;
const ARGON2_TYPE_ID = 2;

export const MAX_PASSWORD_BYTES = 1 << 20;
export const MIN_SALT_BYTES = 8;
export const MAX_SALT_BYTES = 1024;
export const MAX_SECRET_BYTES = 1024;
export const MAX_AD_BYTES = 1 << 20;
export const MIN_TAG_BYTES = 4;
export const MAX_TAG_BYTES = 512;
export const MIN_TIMECOST = 1;
export const MAX_TIMECOST = 16;
export const MIN_PARALLELISM = 1;
export const MAX_PARALLELISM = 16;
export const MIN_MEMORY_KIB = 8;
export const MAX_MEMORY_KIB = 32768;
export const DEFAULT_SALT_BYTES = 16;

export const EXPERIMENTAL_FREE_LOGIN_COSTS: Readonly<{
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  hashLength: number;
}> = Object.freeze({
  memoryCost: 2048,
  timeCost: 1,
  parallelism: 1,
  hashLength: 32,
});

export const profiles = Object.freeze({
  experimental: EXPERIMENTAL_FREE_LOGIN_COSTS,
  m8t2: Object.freeze({ memoryCost: 8192, timeCost: 2, parallelism: 1, hashLength: 32 }),
  m16t2: Object.freeze({ memoryCost: 16384, timeCost: 2, parallelism: 1, hashLength: 32 }),
  standard: Object.freeze({ memoryCost: 19456, timeCost: 3, parallelism: 1, hashLength: 32 }),
  m32t3: Object.freeze({ memoryCost: 32768, timeCost: 3, parallelism: 1, hashLength: 32 }),
  m32t4: Object.freeze({ memoryCost: 32768, timeCost: 4, parallelism: 1, hashLength: 32 }),
});

export type ProfileName = keyof typeof profiles;

export interface PasswordProfile {
  readonly memoryCost: number;
  readonly timeCost: number;
  readonly parallelism: number;
  readonly hashLength: number;
}

export function createProfile(costs: PasswordProfile): Readonly<PasswordProfile> {
  if (costs === null || typeof costs !== "object") {
    throw new Argon2wError(-30, "profile must be an object");
  }
  const parallelism = checkInt("parallelism", costs.parallelism, MIN_PARALLELISM, MAX_PARALLELISM);
  const profile = {
    memoryCost: checkInt("memoryCost", costs.memoryCost, Math.max(MIN_MEMORY_KIB, 8 * parallelism), MAX_MEMORY_KIB),
    timeCost: checkInt("timeCost", costs.timeCost, MIN_TIMECOST, MAX_TIMECOST),
    parallelism,
    hashLength: checkInt("hashLength", costs.hashLength, MIN_TAG_BYTES, MAX_TAG_BYTES),
  };
  return Object.freeze(profile);
}

export type PasswordInput = string | Uint8Array;

export interface HashOptions {
  profile?: ProfileName;
  timeCost?: number;
  memoryCost?: number;
  parallelism?: number;
  hashLength?: number;
  salt?: Uint8Array;
  secret?: Uint8Array;
  associatedData?: Uint8Array;
  version?: number;
}

export class Argon2wError extends Error {
  readonly code: number;
  constructor(code: number, message: string) {
    super(`argon2w: ${message} (code ${code})`);
    this.name = "Argon2wError";
    this.code = code;
  }
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

function toBytes(
  input: PasswordInput,
  label: string,
  max: number,
): Uint8Array<ArrayBuffer> {
  const bytes =
    typeof input === "string" ? new TextEncoder().encode(input) : input;
  if (!(bytes instanceof Uint8Array)) {
    throw new Argon2wError(-30, `${label} must be a string or Uint8Array`);
  }
  if (bytes.length > max) {
    throw new Argon2wError(-30, `${label} exceeds ${max} bytes`);
  }
  return toOwned(bytes);
}

function toOwnedOption(
  value: Uint8Array | undefined,
  label: string,
  max: number,
): Uint8Array<ArrayBuffer> {
  const bytes = value ?? new Uint8Array(0);
  if (!(bytes instanceof Uint8Array)) {
    throw new Argon2wError(-30, `${label} must be a Uint8Array`);
  }
  checkInt(`${label} length`, bytes.length, 0, max);
  return toOwned(bytes);
}

interface ResolvedParams {
  pwd: Uint8Array<ArrayBuffer>;
  salt: Uint8Array<ArrayBuffer>;
  secret: Uint8Array<ArrayBuffer>;
  ad: Uint8Array<ArrayBuffer>;
  tCost: number;
  mCost: number;
  lanes: number;
  outlen: number;
}

function checkInt(name: string, value: number, min: number, max: number): number {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Argon2wError(-30, `${name} must be an integer in [${min}, ${max}]`);
  }
  return value;
}

function resolveParams(
  password: PasswordInput,
  options: HashOptions = {},
): ResolvedParams {
  if (options === null || typeof options !== "object") {
    throw new Argon2wError(-30, "options must be an object");
  }
  let costs: HashOptions = options;
  if (options.profile !== undefined) {
    if (typeof options.profile !== "string" || !Object.hasOwn(profiles, options.profile)) {
      throw new Argon2wError(-30, "unknown hash profile");
    }
    if ([options.memoryCost, options.timeCost, options.parallelism, options.hashLength].some((value) => value !== undefined)) {
      throw new Argon2wError(-30, "profile cannot be combined with explicit costs");
    }
    costs = { ...options, ...profiles[options.profile] };
  }
  const pwd = toBytes(password, "password", MAX_PASSWORD_BYTES);
  const rawSalt =
    options.salt === undefined
      ? crypto.getRandomValues(new Uint8Array(DEFAULT_SALT_BYTES))
      : options.salt;
  if (!(rawSalt instanceof Uint8Array)) {
    throw new Argon2wError(-30, "salt must be a Uint8Array");
  }
  checkInt("salt length", rawSalt.length, MIN_SALT_BYTES, MAX_SALT_BYTES);
  const salt = toOwned(rawSalt);
  const secret = toOwnedOption(options.secret, "secret", MAX_SECRET_BYTES);
  const ad = toOwnedOption(
    options.associatedData,
    "associatedData",
    MAX_AD_BYTES,
  );
  const version = options.version ?? ARGON2_VERSION_13;
  if (version !== ARGON2_VERSION_13) {
    throw new Argon2wError(-26, "only Argon2 version 19 (0x13) is supported");
  }
  const tCost = checkInt(
    "timeCost",
    costs.timeCost ?? 3,
    MIN_TIMECOST,
    MAX_TIMECOST,
  );
  const lanes = checkInt(
    "parallelism",
    costs.parallelism ?? 1,
    MIN_PARALLELISM,
    MAX_PARALLELISM,
  );
  const mCost = checkInt(
    "memoryCost",
    costs.memoryCost ?? 19456,
    Math.max(MIN_MEMORY_KIB, 8 * lanes),
    MAX_MEMORY_KIB,
  );
  const outlen = checkInt(
    "hashLength",
    costs.hashLength ?? 32,
    MIN_TAG_BYTES,
    MAX_TAG_BYTES,
  );
  return { pwd, salt, secret, ad, tCost, mCost, lanes, outlen };
}

interface Allocations {
  ptrs: Array<{ ptr: number; size: number }>;
}

function allocCopy(
  wasm: Argon2wExports,
  data: Uint8Array,
  track: Allocations,
): number {
  if (data.length === 0) {
    return 0;
  }
  const ptr = wasm.argon2w_alloc(data.length);
  if (ptr === 0) {
    throw new Argon2wError(-22, "wasm allocation failed");
  }
  track.ptrs.push({ ptr, size: data.length });
  memoryBytes(wasm).set(data, ptr);
  return ptr;
}

function freeAll(wasm: Argon2wExports, track: Allocations): void {
  for (const { ptr, size } of track.ptrs) {
    try {
      wasm.argon2w_free(ptr, size);
    } catch {
    }
  }
  track.ptrs.length = 0;
}

function throwIfError(wasm: Argon2wExports, code: number): void {
  if (code !== 0) {
    const ptr = wasm.argon2w_error_message(code);
    throw new Argon2wError(code, readCString(wasm, ptr));
  }
}

export async function hash(
  password: PasswordInput,
  options: HashOptions = {},
): Promise<string> {
  const params = resolveParams(password, options);
  const wasm = await getWasm();
  const track: Allocations = { ptrs: [] };
  try {
    const pwdPtr = allocCopy(wasm, params.pwd, track);
    const saltPtr = allocCopy(wasm, params.salt, track);
    const secretPtr = allocCopy(wasm, params.secret, track);
    const adPtr = allocCopy(wasm, params.ad, track);
    const outPtr = wasm.argon2w_alloc(params.outlen);
    if (outPtr === 0) {
      throw new Argon2wError(-22, "wasm allocation failed");
    }
    track.ptrs.push({ ptr: outPtr, size: params.outlen });
    const encodedLen = wasm.argon2w_encoded_len(
      params.tCost,
      params.mCost,
      params.lanes,
      params.salt.length,
      params.outlen,
    );
    if (encodedLen <= 0 || encodedLen > 1 << 20) {
      throw new Argon2wError(-30, "invalid encoded length");
    }
    const encodedPtr = wasm.argon2w_alloc(encodedLen);
    if (encodedPtr === 0) {
      throw new Argon2wError(-22, "wasm allocation failed");
    }
    track.ptrs.push({ ptr: encodedPtr, size: encodedLen });
    const code = wasm.argon2w_hash_encoded(
      ARGON2_TYPE_ID,
      ARGON2_VERSION_13,
      pwdPtr,
      params.pwd.length,
      saltPtr,
      params.salt.length,
      secretPtr,
      params.secret.length,
      adPtr,
      params.ad.length,
      params.tCost,
      params.mCost,
      params.lanes,
      outPtr,
      params.outlen,
      encodedPtr,
      encodedLen,
    );
    throwIfError(wasm, code);
    return readCString(wasm, encodedPtr);
  } catch (error) {
    if (isTrapError(error)) {
      resetWasmCache();
    }
    throw error;
  } finally {
    params.pwd.fill(0);
    params.salt.fill(0);
    params.secret.fill(0);
    params.ad.fill(0);
    freeAll(wasm, track);
  }
}

export interface VerifyOptions {
  secret?: Uint8Array;
  associatedData?: Uint8Array;
  maxMemoryKib?: number;
  maxTimeCost?: number;
  maxParallelism?: number;
}

export function isVerifyInputFailure(code: number): boolean {
  switch (code) {
    case -22:
    case -31:
    case -33:
    case -1:
    case -18:
    case -19:
    case -20:
    case -21:
    case -23:
    case -24:
    case -27:
      return false;
    default:
      return true;
  }
}

export async function verify(
  encoded: string,
  password: PasswordInput,
  options: VerifyOptions = {},
): Promise<boolean> {
  if (typeof encoded !== "string" || encoded.length > 1 << 20) {
    return false;
  }
  const maxMemoryKib = options.maxMemoryKib ?? MAX_MEMORY_KIB;
  const maxTimeCost = options.maxTimeCost ?? MAX_TIMECOST;
  const maxParallelism = options.maxParallelism ?? MAX_PARALLELISM;
  checkInt("maxMemoryKib", maxMemoryKib, 0, 4294967295);
  checkInt("maxTimeCost", maxTimeCost, 0, 4294967295);
  checkInt("maxParallelism", maxParallelism, 0, 4294967295);
  try {
    const gate = parsePHC(encoded);
    if (
      gate.memoryCost > maxMemoryKib ||
      gate.timeCost > maxTimeCost ||
      gate.parallelism > maxParallelism
    ) {
      return false;
    }
  } catch {
  }
  const pwd = toBytes(password, "password", MAX_PASSWORD_BYTES);
  const secret = toOwnedOption(options.secret, "secret", MAX_SECRET_BYTES);
  const ad = toOwnedOption(
    options.associatedData,
    "associatedData",
    MAX_AD_BYTES,
  );
  const wasm = await getWasm();
  const track: Allocations = { ptrs: [] };
  const encodedBytes = new TextEncoder().encode(encoded);
  const encodedNul = new Uint8Array(encodedBytes.length + 1);
  encodedNul.set(encodedBytes, 0);
  encodedBytes.fill(0);
  try {
    const encodedPtr = allocCopy(wasm, encodedNul, track);
    const pwdPtr = allocCopy(wasm, pwd, track);
    const secretPtr = allocCopy(wasm, secret, track);
    const adPtr = allocCopy(wasm, ad, track);
    const code = wasm.argon2w_verify(
      encodedPtr,
      pwdPtr,
      pwd.length,
      secretPtr,
      secret.length,
      adPtr,
      ad.length,
    );
    if (!isVerifyInputFailure(code)) {
      throwIfError(wasm, code);
    }
    return code === 0;
  } catch (error) {
    if (isTrapError(error)) {
      resetWasmCache();
    }
    throw error;
  } finally {
    pwd.fill(0);
    secret.fill(0);
    ad.fill(0);
    encodedNul.fill(0);
    freeAll(wasm, track);
  }
}

export interface ParsedPHC {
  type: string;
  version: number;
  memoryCost: number;
  timeCost: number;
  parallelism: number;
}

const PHC_RE =
  /^\$(argon2(?:d|i|id))\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$/;

function parseDecimalU32(text: string | undefined, label: string): number {
  if (text === undefined || !/^(0|[1-9][0-9]*)$/.test(text)) {
    throw new Argon2wError(-32, `malformed PHC ${label}`);
  }
  if (text.length > 10) {
    throw new Argon2wError(-32, `malformed PHC ${label}`);
  }
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value > 4294967295) {
    throw new Argon2wError(-32, `malformed PHC ${label}`);
  }
  return value;
}

export function parsePHC(encoded: string): ParsedPHC {
  if (typeof encoded !== "string" || encoded.length > 1 << 20) {
    throw new Argon2wError(-32, "malformed PHC string");
  }
  const match = PHC_RE.exec(encoded);
  if (match === null) {
    throw new Argon2wError(-32, "malformed PHC string");
  }
  const type = match[1] ?? "";
  const version = parseDecimalU32(match[2], "version");
  const memoryCost = parseDecimalU32(match[3], "memory cost");
  const timeCost = parseDecimalU32(match[4], "time cost");
  const parallelism = parseDecimalU32(match[5], "parallelism");
  return { type, version, memoryCost, timeCost, parallelism };
}

export interface Policy {
  timeCost?: number;
  memoryCost?: number;
  parallelism?: number;
  version?: number;
}

export function needsRehash(encoded: string, policy: Policy): boolean {
  let parsed: ParsedPHC;
  try {
    parsed = parsePHC(encoded);
  } catch {
    return true;
  }
  if (parsed.type !== "argon2id" || parsed.version !== ARGON2_VERSION_13) {
    return true;
  }
  if (policy.version !== undefined && parsed.version !== policy.version) {
    return true;
  }
  if (
    policy.memoryCost !== undefined &&
    parsed.memoryCost !== policy.memoryCost
  ) {
    return true;
  }
  if (policy.timeCost !== undefined && parsed.timeCost !== policy.timeCost) {
    return true;
  }
  if (
    policy.parallelism !== undefined &&
    parsed.parallelism !== policy.parallelism
  ) {
    return true;
  }
  return false;
}

export type RehashAssessment =
  | "matches"
  | "below-target"
  | "above-target"
  | "different-parameters"
  | "unparseable";

export function assessRehash(
  encoded: string,
  target: ProfileName | PasswordProfile,
): RehashAssessment {
  const profile =
    typeof target === "string"
      ? Object.hasOwn(profiles, target)
        ? profiles[target as ProfileName]
        : undefined
      : createProfile(target);
  if (profile === undefined) {
    throw new Argon2wError(-30, "unknown hash profile");
  }
  let parsed: ParsedPHC;
  try {
    parsed = parsePHC(encoded);
  } catch {
    return "unparseable";
  }
  if (parsed.type !== "argon2id" || parsed.version !== ARGON2_VERSION_13) {
    return "unparseable";
  }
  const memory = parsed.memoryCost - profile.memoryCost;
  const time = parsed.timeCost - profile.timeCost;
  const lanes = parsed.parallelism - profile.parallelism;
  if (memory === 0 && time === 0 && lanes === 0) {
    return "matches";
  }
  if (memory >= 0 && time >= 0 && lanes >= 0) {
    return "above-target";
  }
  if (memory <= 0 && time <= 0 && lanes <= 0) {
    return "below-target";
  }
  return "different-parameters";
}

export async function hashRaw(
  password: PasswordInput,
  options: HashOptions = {},
): Promise<Uint8Array> {
  const params = resolveParams(password, options);
  const wasm = await getWasm();
  const track: Allocations = { ptrs: [] };
  try {
    const pwdPtr = allocCopy(wasm, params.pwd, track);
    const saltPtr = allocCopy(wasm, params.salt, track);
    const secretPtr = allocCopy(wasm, params.secret, track);
    const adPtr = allocCopy(wasm, params.ad, track);
    const outPtr = wasm.argon2w_alloc(params.outlen);
    if (outPtr === 0) {
      throw new Argon2wError(-22, "wasm allocation failed");
    }
    track.ptrs.push({ ptr: outPtr, size: params.outlen });
    const code = wasm.argon2w_hash_raw(
      ARGON2_TYPE_ID,
      ARGON2_VERSION_13,
      pwdPtr,
      params.pwd.length,
      saltPtr,
      params.salt.length,
      secretPtr,
      params.secret.length,
      adPtr,
      params.ad.length,
      params.tCost,
      params.mCost,
      params.lanes,
      outPtr,
      params.outlen,
    );
    throwIfError(wasm, code);
    const tag = memoryBytes(wasm).slice(outPtr, outPtr + params.outlen);
    return tag;
  } catch (error) {
    if (isTrapError(error)) {
      resetWasmCache();
    }
    throw error;
  } finally {
    params.pwd.fill(0);
    params.salt.fill(0);
    params.secret.fill(0);
    params.ad.fill(0);
    freeAll(wasm, track);
  }
}
