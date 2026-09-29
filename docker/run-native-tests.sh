#!/usr/bin/env sh
set -eu

UPSTREAM=/repo/upstream/phc-winner-argon2
WORK=/tmp/native-tests
rm -rf "${WORK}"
mkdir -p "${WORK}/out"
cp -r "${UPSTREAM}" "${WORK}/up"

echo "--- compilers ---"
gcc --version | head -n 1
echo "--- wrapper KAT: ref.c, ARGON2_NO_THREADS ---"
gcc -std=c89 -O2 -Wall -Werror -DARGON2_NO_THREADS \
  -I"${WORK}/up/include" -I"${WORK}/up/src" \
  "${WORK}/up/src/argon2.c" \
  "${WORK}/up/src/core.c" \
  "${WORK}/up/src/blake2/blake2b.c" \
  "${WORK}/up/src/thread.c" \
  "${WORK}/up/src/encoding.c" \
  "${WORK}/up/src/ref.c" \
  /repo/c/argon2w.c \
  /repo/docker/kat-native.c \
  -o "${WORK}/out/kat-native"

"${WORK}/out/kat-native" > "${WORK}/out/kat-native.log"
grep -q "status=0 tag=0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659" "${WORK}/out/kat-native.log"
grep -q "status=0 tag=559af654b5f0df84a0245c92b04030a10b2a940ca856d0af0da84210c117e2d6" "${WORK}/out/kat-native.log"
grep -q 'status=0 phc=$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHQwMQ$VZr2VLXw34SgJFySsEAwoQsqlAyoVtCvDahCEMEX4tY' "${WORK}/out/kat-native.log"
grep -q "verify-ok status=0" "${WORK}/out/kat-native.log"
grep -q "verify-bad status=-35" "${WORK}/out/kat-native.log"
echo "kat-native: all markers match"
sh /repo/docker/run-profile-oracle.sh

echo "--- upstream regression: make test NO_THREADS=1 ---"
cd "${WORK}/up"
make test NO_THREADS=1 CC=gcc > "${WORK}/out/upstream.log" 2>&1
echo 'upstream make test: PASS (synthetic input output suppressed)'
echo "native-tests: all green"
