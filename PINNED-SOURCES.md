# Pinned sources

## Assessed repository

| Item | Value |
|---|---|
| Repository | postfiatorg/postfiatd |
| Pinned commit (LIVE main HEAD at build start) | `0085a1ff885d6a446369cf73a4430f75af22be55` |
| Commit date | 2026-10-10T16:53:26Z |
| Commit subject | Merge pull request #50 from postfiatorg/hotfix/upstream-hardening-1.0.9 — 1.0.9: backport the upstream 3.4.1 payment engine overflow fix |
| Tree size | 1,947 paths (1,783 blobs + 164 trees) |
| Pin method | GitHub API `GET /repos/postfiatorg/postfiatd/commits/main` at build start, 2026-11-27; re-fetched live, not carried over from an earlier pin (the same commit was already HEAD) |
| Vendored evidence | `evidence/pinned-sources/` — verbatim copies of the 31 cited files; each file verified against the pinned tree by git blob SHA-1 and size (see `evidence/pinned-tree-manifest.json`); full path list in `evidence/pinned-tree-paths.txt` |

## Vendored files (all at the pinned commit)

See `evidence/pinned-tree-manifest.json` for the per-file blob SHA-1,
byte size, and SHA-256. Files: `src/xrpld/app/misc/detail/ValidatorKeys.cpp`,
`src/xrpld/app/misc/ValidatorKeys.h`, `src/xrpld/app/misc/detail/Manifest.cpp`,
`src/xrpld/app/misc/Manifest.h`, `src/xrpld/app/misc/detail/ValidatorList.cpp`,
`src/xrpld/app/misc/ValidatorList.h`, `src/xrpld/app/misc/detail/ValidatorSite.cpp`,
`src/xrpld/app/misc/ValidatorSite.h`, `include/xrpl/protocol/Seed.h`,
`include/xrpl/protocol/SecretKey.h`, `src/libxrpl/protocol/Seed.cpp`,
`src/libxrpl/protocol/SecretKey.cpp`, `src/xrpld/core/detail/Config.cpp`,
`docs/ValidatorKeyUpdate.md`, `docs/NodeSetup.md`, `docs/Docker.md`,
`docs/DeploymentWorkflows.md`, `docs/consensus.md`,
`docs/0010-ledger-replay/README.md`, `docs/MANIFEST_FLOOD_HOTFIX.md`,
`cfg/postfiatd-mainnet-full.cfg`, `cfg/postfiatd-example.cfg`,
`cfg/validators-mainnet.txt`, `.github/workflows/deploy.yml`,
`.github/workflows/destroy.yml`, `scripts/docker-entrypoint.sh`,
`scripts/docker-compose-validator.yml`, `Dockerfile`,
`src/test/app/ValidatorKeys_test.cpp`, `src/test/app/Manifest_test.cpp`,
`cmake/RippledValidatorKeys.cmake`.

## External dependency pin (in-tree)

| Item | Value |
|---|---|
| validator-keys-tool | Fetched by CMake FetchContent, pinned to commit `05742108d4b7c0b7d9a97c073acd690d2c75a2b4` (2025-09-05, "Last working commit before namespace rename") — `cmake/RippledValidatorKeys.cmake` line 9. The tool is the documented way to create keys and tokens (`docs/NodeSetup.md` lines 259-264). |

## Specifications and references relied on

| Specification | Version / status | Used for |
|---|---|---|
| XRPL validator keys and tokens (upstream rippled docs, as referenced by the pinned tree's own docs) | Current | Two-tier key model (master + ephemeral signing key), token invalidation on rotation, revocation by max-sequence manifest |
| NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management | Current | Key backup, key compromise response, and key destruction guidance (recommendations, not postfiatd behaviour) |
| NIST SP 800-130, A Framework for Designing Cryptographic Key Management Systems | Current | Key lifecycle and backup policy framing for the runbooks |

## What was NOT measured

No validator host, no live network, and no postfiatd binary were present
on the build machine and none were used. All recovery behaviour in this
pack is modelled in software (SIMULATED) from the pinned source; the time
a real rebuild takes on a real host and the time a ledger re-sync takes
are UNTESTABLE here. The drills prove the *logic* of recovery (identity
restoration, sequence continuity, UNL re-admission, silent-failure modes),
not its wall-clock duration on production hardware. See
`docs/methodology.md` and `docs/claim-evidence-index.md`.
