#!/usr/bin/env sh
set -eu

UPSTREAM=/repo/upstream/phc-winner-argon2
WORK=/tmp/phc-fuzz-smoke
rm -rf "${WORK}"
mkdir -p "${WORK}/out"
cp -r "${UPSTREAM}" "${WORK}/up"

export ASAN_OPTIONS=detect_leaks=1:abort_on_error=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1

gcc -std=c89 -O1 -g -Wall -Werror -DARGON2_NO_THREADS \
  -fsanitize=address,undefined -fno-sanitize-recover=all \
  -I"${WORK}/up/include" -I"${WORK}/up/src" \
  "${WORK}/up/src/argon2.c" \
  "${WORK}/up/src/core.c" \
  "${WORK}/up/src/blake2/blake2b.c" \
  "${WORK}/up/src/thread.c" \
  "${WORK}/up/src/encoding.c" \
  "${WORK}/up/src/ref.c" \
  /repo/c/argon2w.c \
  /repo/docker/fuzz-verify.c \
  -o "${WORK}/out/fuzz-verify"

pass=0
total=0
for f in /repo/docker/fuzz-corpus/*; do
  total=$((total + 1))
  printf '== %s -> ' "$f"
  if timeout 60 "${WORK}/out/fuzz-verify" "$f"; then
    pass=$((pass + 1))
  else
    echo "FAIL: abort or unexpected exit for $f"
    exit 1
  fi
done
echo "phc-fuzz-smoke: ${pass}/${total} inputs handled without abort"
