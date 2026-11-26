# Claim-to-evidence index

Pinned commit: `0085a1ff885d6a446369cf73a4430f75af22be55`.
Labels: MEASURED / SIMULATED / UNTESTABLE / ANALYSIS.
Evidence paths are relative to the pack root unless they name a file
inside `evidence/pinned-sources/` (the vendored pinned tree).
Bare tree-relative paths — `src/...`, `include/...`, `cfg/...`,
`scripts/...`, `Dockerfile`, `.github/...`, and the pinned-tree documents
`docs/NodeSetup.md`, `docs/ValidatorKeyUpdate.md`,
`docs/DeploymentWorkflows.md`, `docs/Docker.md`, `docs/consensus.md`,
`docs/MANIFEST_FLOOD_HOTFIX.md`, `docs/0010-ledger-replay/README.md` — refer to files in the pinned postfiatd tree and
resolve under `evidence/pinned-sources/` with the same relative path (e.g.
`docs/NodeSetup.md` means
`evidence/pinned-sources/docs/NodeSetup.md`). This pack's own documents
are cited with their pack-root path (`docs/runbook-*.md`,
`docs/methodology.md`, `inventory/...`, `findings/...`).

## Pinned source

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-01 | Pinned commit is the LIVE main HEAD, 2026-10-10, 1.0.9 | MEASURED | `PINNED-SOURCES.md`; `evidence/pinned-tree-manifest.json`; `outputs/inventory_check.json` PIN-02 |
| C-02 | 31 vendored files are byte-identical to the pinned tree (blob SHA-1 + size) | MEASURED | `evidence/pinned-tree-manifest.json`; PIN-01; `outputs/inventory_check.json` |
| C-03 | Tree has 1,947 paths (1,783 blobs + 164 trees) | MEASURED | `evidence/pinned-tree-paths.txt`; PIN-01 |
| C-04 | No tree file outside vendored third-party code is about backup, restore, disaster recovery, or snapshots | MEASURED | `evidence/pinned-tree-paths.txt`; REC-29; `outputs/inventory_check.json` |

## Master keys and identity

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-10 | Master keys live in `validator-keys.json` at `/root/.ripple/validator-keys.json` in the container | MEASURED | `docs/NodeSetup.md` line 291; `docs/ValidatorKeyUpdate.md` line 75; REC-01 |
| C-11 | `validator-keys.json` is deleted on container restart or recreate | MEASURED | `docs/ValidatorKeyUpdate.md` line 16; `docs/NodeSetup.md` lines 361-366; REC-02 |
| C-12 | Without a backup the operator loses token generation, domain update, and revocation, and must create a new identity | MEASURED | `docs/NodeSetup.md` lines 375-380; REC-03 |
| C-13 | Seed path derives the key pair directly and sets manifest sequence 0 | MEASURED | `src/xrpld/app/misc/detail/ValidatorKeys.cpp` line 88; REC-04 |
| C-14 | Token path requires the derived public key to equal the manifest signing key, then adopts the manifest sequence | MEASURED | `src/xrpld/app/misc/detail/ValidatorKeys.cpp` lines 50, 60; REC-05 |
| C-15 | Seed and token sections are mutually exclusive; both set is fatal | MEASURED | `src/xrpld/app/misc/detail/ValidatorKeys.cpp` line 35; `src/xrpld/core/detail/Config.cpp` lines 637-639; REC-06 |
| C-16 | A validation seed is a 128-bit value | MEASURED | `src/libxrpl/protocol/Seed.cpp` line 56; REC-27 |

## Manifest sequence rules

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-20 | Each new token invalidates all previous tokens and carries a higher sequence | MEASURED | `docs/NodeSetup.md` line 274; `docs/ValidatorKeyUpdate.md` lines 64, 239-240; REC-07 |
| C-21 | A manifest with sequence not strictly greater than cached is disposed as stale | MEASURED | `src/xrpld/app/misc/detail/Manifest.cpp` line 411; REC-08 |
| C-22 | Revocation is a manifest with sequence 0xFFFFFFFF; no higher sequence is possible | MEASURED | `src/xrpld/app/misc/detail/Manifest.cpp` lines 236-240; `src/xrpld/app/misc/Manifest.h` lines 71-76; REC-09 |
| C-23 | Upstream tests confirm the stale rule and max-sequence acceptance | MEASURED | `src/test/app/Manifest_test.cpp` lines 1015-1043; REC-10 |
| C-24 | A seed-only restore produces a stale manifest that peers ignore | SIMULATED | `outputs/drill.json` DR-03; `docs/runbook-key-loss.md` |
| C-25 | A rotated token (sequence 4) is accepted and the old token (sequence 3) becomes stale | SIMULATED | `outputs/drill.json` DR-04 |
| C-26 | A max-sequence revocation is accepted and later manifests are stale | SIMULATED | `outputs/drill.json` DR-06 |

## Config, UNL, and deployment

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-30 | Node database is NuDB at `/var/lib/postfiatd/db/nudb`; book-keeping databases under `/var/lib/postfiatd/db` | MEASURED | `cfg/postfiatd-mainnet-full.cfg` lines 1477-1484; REC-12 |
| C-31 | The trusted-validator file defaults to `validators.txt`; a missing default is tolerated, a missing explicit path is fatal | MEASURED | `src/xrpld/core/detail/Config.cpp` lines 913-969; REC-13 |
| C-32 | The mainnet validators file trusts one publisher key and a testnet list URL | MEASURED | `cfg/validators-mainnet.txt` lines 56, 59; REC-14 |
| C-33 | With fewer than 3 publishers the list threshold is 1 | MEASURED | `src/xrpld/app/misc/detail/ValidatorList.cpp` lines 210-212; REC-15 |
| C-34 | Every redeploy deletes the postfiatd-config volume; the token is then re-injected from GitHub Secrets by host IP | MEASURED | `.github/workflows/deploy.yml` lines 153, 403, 663 and 255-286; REC-17, REC-18 |
| C-35 | The destroy workflow removes all volumes and `/opt/postfiatd` | MEASURED | `.github/workflows/destroy.yml` lines 70, 73, 77; REC-20 |
| C-36 | Config and ledger data live in named Docker volumes on the host | MEASURED | `scripts/docker-compose-validator.yml` lines 13-14, 39-40; REC-21 |
| C-37 | The entrypoint performs no key generation, restore, or token handling | MEASURED | `scripts/docker-entrypoint.sh` (no key/token/seed strings); REC-22 |
| C-38 | A tokenless config starts the node but it does not validate | SIMULATED | `outputs/drill.json` DR-07; `src/xrpld/core/detail/Config.cpp` lines 676-678; REC-28 |
| C-39 | A validator absent from peers' UNL has its validations ignored, with no local error | SIMULATED | `outputs/drill.json` DR-08 |

## Ledger data and wallet.db

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-40 | Ledger replay re-acquires state from the network (skip list + deltas) | MEASURED | `docs/0010-ledger-replay/README.md`; REC-24 |
| C-41 | `wallet.db` holds manifests; the hotfix doc orders a backup before destructive restarts and forbids deleting it as a recovery procedure | MEASURED | `docs/MANIFEST_FLOOD_HOTFIX.md` lines 45, 114; REC-23 |
| C-42 | A ledger snapshot whose hash matches no validated ledger cannot seed the node database; re-sync duration is UNTESTABLE | SIMULATED / UNTESTABLE | `outputs/drill.json` DR-09 |

## Recovery verdicts and findings

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-50 | 7 recovery artifacts: 2 RESTORABLE, 1 REGENERABLE, 2 PARTIAL, 1 RESTORABLE-or-LOST, 1 RESYNC | ANALYSIS | `outputs/recovery_coverage.json`; `inventory/recovery-artifact-inventory.md` |
| C-51 | A complete off-host backup restores identity, token, config, and UNL; ledger history is re-synced, not restored | SIMULATED | `outputs/drill.json` DR-01; `docs/runbook-host-loss.md` |
| C-52 | A token-only backup restores validation but loses rotation and revocation | SIMULATED | `outputs/drill.json` DR-02 |
| C-53 | Master-key loss with no backup is unrecoverable; only a new identity plus publisher action remains | SIMULATED | `outputs/drill.json` DR-05; `docs/runbook-key-loss.md` |
| C-54 | An on-host-only backup is destroyed by the same event it was meant to survive | SIMULATED | `outputs/drill.json` DR-10 |
| C-55 | 12 findings (1 Critical, 4 High, 4 Medium, 2 Low, 1 Informational) | ANALYSIS | `findings/findings-register.md` |
| C-56 | Lab drill model times vary run to run with CPU load (observed ranges across two runs: full rebuild 0.128–0.619 s, rotation 0.365–0.471 s, revocation 0.584–1.393 s, key-loss determination 0.010–0.011 s); all cases complete in under ~1.5 s of model time. Model steps only, not operator or sync time | MEASURED | `outputs/run_all.log` (timing lines for the committed run); `outputs/drill.json` (outcomes only — timings are not in the JSON) |

## Reproduction

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-60 | Fresh-clone reproduction from the pack alone ran to completion: all outputs byte-identical | MEASURED | `outputs/reproduction/COMPARISON.md`; `scripts/clean_reproduce.sh` |
| C-61 | `verify_digests.sh` passes on all digest-covered files | MEASURED | `SHA256SUMS`; run `sh scripts/verify_digests.sh` |
| C-62 | A CI workflow runs the fresh-clone check on push | MEASURED | `.github/workflows/reproduce.yml` |
