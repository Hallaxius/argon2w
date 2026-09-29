# Pinned upstream source for argon2w

- Project: [`P-H-C/phc-winner-argon2`](https://github.com/P-H-C/phc-winner-argon2)
- Revision: `f57e61e19229e23c4445b85494dbf7c07de721cb` (master snapshot dated 2021-06-25; not a release)
- Source archive: <https://codeload.github.com/P-H-C/phc-winner-argon2/tar.gz/f57e61e19229e23c4445b85494dbf7c07de721cb>
- Downloaded archive SHA-256: `AC8C1D819A3B5DA231B6549D79E02D0D41DC29469BD0DAE94E775C62CB369E0A`

## Verification

`upstream/phc-winner-argon2` is byte-identical to the POC's validated copy at
`poc/vendor/phc-winner-argon2` (65 files; per-file SHA-256 trees compared, only
difference is `poc/vendor/UPSTREAM.md` which is POC metadata, not upstream source).
The POC already validated this snapshot: native build, Wasm build of the reference
variant (`src/ref.c`, `ARGON2_NO_THREADS`, lanes preserved), and the independent
RFC 9106 §5.3 KAT via `argon2_ctx`. See `poc/README.md` for the original evidence.

## Provenance revalidation (2026-09-28, this review)

- Upstream is the reference C implementation (PHC winner), ~5.3k stars,
  maintenance-mode stable: no release tags exist (master snapshots only), so
  pinning the commit SHA is the correct practice. No CVE or security advisory
  against the reference implementation was found (upstream CHANGELOG entries
  uniformly state "no security issue"; Snyk reports no known issues for the
  `argon2` npm binding lineage).
- The vendored copy is byte-identical to the POC-validated tree (65 files,
  per-file SHA-256 compared; only metadata differs) and is never modified
  (`c/` wrapper + `src/` TS only). No upstream code was vendored or changed
  in this review — only the narrow wrapper (`argon2w_wipe`, saturation,
  empty-salt fall-through), which ships in `c/`, not `upstream/`.

## Usage rules

- Do not modify files under `upstream/phc-winner-argon2`. All product code goes in
  `c/` (narrow wrapper) and `src/` (TypeScript).
- The build selects the upstream optimized implementation (`src/opt.c`) explicitly
  since 0.1.1, compiled with `-O3 -msimd128 -mavx2 -flto` to its official AVX2
  path (`fill_block` only; same algorithm, no parameter changes). The initial
  0.1.0 artifact used the reference implementation (`src/ref.c`); the native
  differential oracle (`docker/profile-oracle.c`) still runs against `ref.c`.
- Variant selection: Argon2id only in v1. The wrapper rejects other types instead of
  silently substituting.
- Review `upstream/phc-winner-argon2/LICENSE` (dual CC0 / Apache-2.0, with `src/blake2`
  and `src/encoding.c` notices) before release; see `NOTICE` in the packed tarball.
