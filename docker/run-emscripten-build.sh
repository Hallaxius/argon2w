#!/usr/bin/env sh
set -eu

WORK=/tmp/emscripten-build
rm -rf "${WORK}"
mkdir -p "${WORK}/out"

emcc -std=c89 -Oz -Wall -Werror -msimd128 -mavx2 -flto -DARGON2_NO_THREADS \
  -I/repo/upstream/phc-winner-argon2/include \
  -I/repo/upstream/phc-winner-argon2/src \
  /repo/upstream/phc-winner-argon2/src/argon2.c \
  /repo/upstream/phc-winner-argon2/src/core.c \
  /repo/upstream/phc-winner-argon2/src/blake2/blake2b.c \
  /repo/upstream/phc-winner-argon2/src/thread.c \
  /repo/upstream/phc-winner-argon2/src/encoding.c \
  /repo/upstream/phc-winner-argon2/src/opt.c \
  /repo/c/argon2w.c \
  -sSTANDALONE_WASM=1 \
  --no-entry \
  "-sEXPORTED_FUNCTIONS=['_argon2w_alloc','_argon2w_free','_argon2w_error_message','_argon2w_hash_raw','_argon2w_encoded_len','_argon2w_hash_encoded','_argon2w_verify']" \
  -sALLOW_MEMORY_GROWTH=1 \
  -sINITIAL_MEMORY=16777216 \
  -sMAXIMUM_MEMORY=67108864 \
  -sSTACK_SIZE=1048576 \
  '-Wl,--export-memory' \
  -o "${WORK}/out/argon2w.wasm"

echo "--- rebuilt artifact ---"
sha256sum "${WORK}/out/argon2w.wasm"
ls -l "${WORK}/out/argon2w.wasm"
echo "--- committed artifact ---"
sha256sum /repo/src/argon2w.wasm

if ! cmp "${WORK}/out/argon2w.wasm" /repo/src/argon2w.wasm; then
  echo "FAIL: rebuilt wasm is not byte-identical to the committed src/argon2w.wasm"
  echo "      if the change is intended, update the committed artifact and the pin below"
  exit 1
fi
echo "emscripten-build: rebuild is byte-identical to the committed artifact"

EXPECTED=b0b2bb2311f34a498579ac343c0bd36ceff27c2a618ab18a30eb4d044cde64da
ACTUAL=$(sha256sum "${WORK}/out/argon2w.wasm" | cut -d' ' -f1)
if [ "${ACTUAL}" != "${EXPECTED}" ]; then
  echo "FAIL: rebuilt wasm ${ACTUAL} != pinned ${EXPECTED}"
  exit 1
fi
echo "emscripten-build: matches the pinned SHA-256"
