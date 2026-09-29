#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
upstream="${repo_root}/upstream/phc-winner-argon2"
output="${repo_root}/src/argon2w.wasm"
EMSDK_IMAGE="${EMSDK_IMAGE:-emscripten/emsdk@sha256:e077d54e2b8970575ebc4f185ac1de0b95c05f2b266134d4ba27449af7aebf65}"

docker run --rm \
  --network none \
  --user "$(id -u):$(id -g)" \
  -v "${repo_root}:/work:ro" \
  -v "${repo_root}/src:/out" \
  "${EMSDK_IMAGE}" \
  emcc \
    -std=c89 \
    -Oz \
    -Wall \
    -Werror \
    -msimd128 \
    -mavx2 \
    -flto \
    -DARGON2_NO_THREADS \
    -I/work/upstream/phc-winner-argon2/include \
    -I/work/upstream/phc-winner-argon2/src \
    /work/upstream/phc-winner-argon2/src/argon2.c \
    /work/upstream/phc-winner-argon2/src/core.c \
    /work/upstream/phc-winner-argon2/src/blake2/blake2b.c \
    /work/upstream/phc-winner-argon2/src/thread.c \
    /work/upstream/phc-winner-argon2/src/encoding.c \
    /work/upstream/phc-winner-argon2/src/opt.c \
    /work/c/argon2w.c \
    -sSTANDALONE_WASM=1 \
    --no-entry \
    "-sEXPORTED_FUNCTIONS=['_argon2w_alloc','_argon2w_free','_argon2w_error_message','_argon2w_hash_raw','_argon2w_encoded_len','_argon2w_hash_encoded','_argon2w_verify']" \
    -sALLOW_MEMORY_GROWTH=1 \
    -sINITIAL_MEMORY=16777216 \
    -sMAXIMUM_MEMORY=67108864 \
    -sSTACK_SIZE=1048576 \
    -Wl,--export-memory \
    -o /out/argon2w.wasm

sha256sum "${output}"
ls -l "${output}"
