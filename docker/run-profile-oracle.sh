#!/bin/sh
set -eu
cd /repo
gcc -std=c89 -O2 -Wall -Werror -DARGON2_NO_THREADS \
  -Iupstream/phc-winner-argon2/include -Iupstream/phc-winner-argon2/src \
  upstream/phc-winner-argon2/src/argon2.c upstream/phc-winner-argon2/src/core.c \
  upstream/phc-winner-argon2/src/blake2/blake2b.c \
  upstream/phc-winner-argon2/src/thread.c upstream/phc-winner-argon2/src/encoding.c \
  upstream/phc-winner-argon2/src/ref.c docker/profile-oracle.c -o /tmp/profile-oracle
OUT="${1:-/tmp/profile-oracle.bin}"
/tmp/profile-oracle "${OUT}"
if [ "$#" = 0 ]; then
  cmp "${OUT}" /repo/test/fixtures/profile-oracle.bin
  echo "native profile oracle: PASS (oracle output matches test/fixtures/profile-oracle.bin)"
else
  echo "native profile oracle: wrote ${OUT} (comparison skipped, explicit output path given)"
fi
