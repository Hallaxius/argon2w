#!/usr/bin/env sh
set -eu

echo "--- node ---"
node --version
echo "--- allowlist inspection ---"
node /repo/scripts/inspect-wasm.mjs /repo/src/argon2w.wasm > /tmp/inspect-wasm.txt
cat /tmp/inspect-wasm.txt
grep -q "env.emscripten_notify_memory_growth : function" /tmp/inspect-wasm.txt
echo "--- ABI checks ---"
node /repo/docker/wasm-check.mjs /repo/src/argon2w.wasm
echo "wasm-tests: all green"
