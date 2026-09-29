#!/usr/bin/env sh
set -eu

UPSTREAM=/repo/upstream/phc-winner-argon2
WORK=/tmp/native-sanitizers
rm -rf "${WORK}"
mkdir -p "${WORK}/out"
cp -r "${UPSTREAM}" "${WORK}/up"

export ASAN_OPTIONS=detect_leaks=1:abort_on_error=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1

echo "--- sanitizer KAT (address,undefined; opt.c AVX2; no-threads) ---"
gcc -std=c89 -O1 -g -Wall -Werror -mavx2 -DARGON2_NO_THREADS \
  -fsanitize=address,undefined -fno-sanitize-recover=all \
  -I"${WORK}/up/include" -I"${WORK}/up/src" \
  "${WORK}/up/src/argon2.c" \
  "${WORK}/up/src/core.c" \
  "${WORK}/up/src/blake2/blake2b.c" \
  "${WORK}/up/src/thread.c" \
  "${WORK}/up/src/encoding.c" \
  "${WORK}/up/src/opt.c" \
  /repo/c/argon2w.c \
  /repo/docker/kat-native.c \
  -o "${WORK}/out/kat-asan"
"${WORK}/out/kat-asan" > "${WORK}/out/kat-asan.log"
grep -q "tag=0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659" "${WORK}/out/kat-asan.log"
grep -q "verify-ok status=0" "${WORK}/out/kat-asan.log"
echo "kat-asan: clean (no sanitizer findings, KAT markers match)"
echo "native-sanitizers: all green"
