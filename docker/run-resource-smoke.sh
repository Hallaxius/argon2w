#!/usr/bin/env sh
set -eu

WORK=/tmp/resource-smoke
rm -rf "${WORK}"
mkdir -p "${WORK}"
mkdir -p "${WORK}/docker"
cp -r /repo/src /repo/test "${WORK}/"
cp -r /repo/docker/fuzz-corpus "${WORK}/docker/"
cd "${WORK}"

echo "--- bun ---"
bun --version
echo "--- full suite, run 1 ---"
timeout 300 bun test
echo "--- limits (growth + concurrency), 2 more repetitions ---"
timeout 300 bun test test/limits.test.ts
timeout 300 bun test test/limits.test.ts
echo "resource-smoke: all green"
