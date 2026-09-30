#!/usr/bin/env sh
set -eu

WORK=/tmp/bun-consumer
rm -rf "${WORK}"
mkdir -p "${WORK}/pkg" "${WORK}/fixture"

echo "--- pack from a clean copy (prepack rebuilds dist from source) ---"
cp /repo/package.json /repo/tsconfig.build.json /repo/README.md "${WORK}/pkg/"
cp -r /repo/src /repo/scripts "${WORK}/pkg/"
cd "${WORK}/pkg"
bun pm pack --dry-run
bun pm pack
echo "--- packed wasm matches the committed artifact ---"
sha256sum dist/argon2w.wasm /repo/src/argon2w.wasm
cmp dist/argon2w.wasm /repo/src/argon2w.wasm
echo "packed wasm: byte-identical to src/argon2w.wasm"
set -- hallaxius-argon2w-*.tgz
if [ ! -f "$1" ] || [ "$#" -ne 1 ]; then
  echo "FAIL: expected exactly one argon2w tarball, found $#"
  exit 1
fi
TARBALL=$1
echo "tarball: ${TARBALL}"
sha256sum "${TARBALL}"
ls -l "${TARBALL}"
echo "--- tarball contents ---"
tar -tzf "${TARBALL}"
tar -tzf "${TARBALL}" | grep -q "package/dist/index.js"
tar -tzf "${TARBALL}" | grep -q "package/dist/index.d.ts"
tar -tzf "${TARBALL}" | grep -q "package/dist/argon2w.wasm"
tar -tzf "${TARBALL}" | grep -q "package/dist/wasm-asset.d.ts"
tar -tzf "${TARBALL}" | grep -q "package/dist/wasm-entry.js"
tar -tzf "${TARBALL}" | grep -q "package/dist/wasm.js"
tar -tzf "${TARBALL}" | grep -q "package/dist/index.js.map"
tar -tzf "${TARBALL}" | grep -q "package/README.md"
if tar -tzf "${TARBALL}" | grep -qE "package/(src|test|c|upstream|poc|scripts|docker|consumer-fixture)/"; then
  echo "FAIL: tarball leaks sources/tests"
  exit 1
fi
if tar -tzf "${TARBALL}" | grep -vE "\.d\.ts$" | grep -qE "package/.*\.(ts|tsx|c|h|hpp|cc|cpp)$"; then
  echo "FAIL: tarball leaks TypeScript/C sources"
  exit 1
fi
MAPS=$(tar -tzf "${TARBALL}" | grep -c 'package/dist/.*\.js\.map$')
if [ "${MAPS}" -ne 3 ]; then
  echo "FAIL: expected exactly 3 dist source maps, found ${MAPS}"
  exit 1
fi
for f in dist/index.js.map dist/wasm.js.map dist/wasm-entry.js.map; do
  if grep -q '"sourcesContent"' "${WORK}/pkg/${f}"; then
    echo "source map self-contained: ${f}"
  else
    echo "FAIL: ${f} has no sourcesContent"
    exit 1
  fi
done
echo "tarball allowlist: clean"

echo "--- offline install in a clean fixture ---"
cp /repo/consumer-fixture/check.mjs /repo/consumer-fixture/check-types.mts \
   /repo/consumer-fixture/tsconfig.json /repo/consumer-fixture/wrangler.toml \
   /repo/consumer-fixture/worker.mjs "${WORK}/fixture/"
printf '{"name":"argon2w-consumer-check","version":"1.0.0","type":"module","dependencies":{"@hallaxius/argon2w":"file:%s/%s"}}' \
  "${WORK}/pkg" "${TARBALL}" > "${WORK}/fixture/package.json"
cd "${WORK}/fixture"
bun install --offline

echo "--- node ESM runtime ---"
node check.mjs

echo "--- strict tsc (skipLibCheck false) ---"
tsc -p tsconfig.json
if ! node --experimental-strip-types check-types.mts > "${WORK}/types.log" 2>&1; then
  cat "${WORK}/types.log"
  echo "FAIL: check-types.mts runtime assertions did not pass"
  exit 1
fi
cat "${WORK}/types.log"
echo "consumer type assertions: passed at runtime"

echo "--- wrangler deploy --dry-run ---"
if ! wrangler deploy --dry-run --outdir "${WORK}/fixture/.dryrun" > "${WORK}/dryrun.log" 2>&1; then
  cat "${WORK}/dryrun.log"
  echo "FAIL: wrangler deploy --dry-run failed"
  exit 1
fi
cat "${WORK}/dryrun.log"
grep -qE "Total Upload|bundle" "${WORK}/dryrun.log"
echo "bun-consumer: all green"
