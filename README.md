# Validator disaster-recovery and key-backup drill pack

A lab-runnable assessment of whether a postfiatd validator can recover
from total host loss using only its documented backup artifacts, at pinned
postfiatd commit `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10,
1.0.9), with runnable drills, a severity-ranked silent-failure register,
and three timed recovery runbooks.

## Headline results

- **Master-key loss without an off-host backup is permanent identity
  loss**: `validator-keys.json` is deleted on container restart, and
  without a backup the operator loses token generation, domain update,
  and revocation — a new identity is the only remedy (finding F-01).
- **A seed-only backup silently fails**: the seed path sets manifest
  sequence 0, peers already cached a higher sequence, and the rebuilt
  validator's validations are ignored with no local error (finding F-02,
  drill DR-03).
- **A token-only backup masquerades as full recovery**: validation
  resumes, but rotation and revocation need the master key, which is
  gone (finding F-03, drill DR-02).
- **Every redeploy deletes the config volume** and re-injects the token
  from GitHub Secrets; a failed injection leaves a healthy-looking node
  that does not validate (finding F-04, drill DR-07).
- **Recovery coverage: 7 artifacts** — 2 RESTORABLE, 1 REGENERABLE,
  2 PARTIAL, 1 RESTORABLE-or-LOST, 1 RESYNC (`outputs/recovery_coverage.json`).
- **12 findings** (1 Critical, 4 High, 4 Medium, 2 Low, 1 Informational)
  in `findings/findings-register.md`, including 7 silent-failure modes.
- **Harness: 32/32 inventory checks pass; 11/11 drill cases pass**
  (drill model times: all cases under ~1.5 s on the build machine, varying
  run to run with CPU load — model steps only, not operator or sync time).
- **Fresh-clone reproduction: byte-identical** — see
  `outputs/reproduction/COMPARISON.md`. A CI workflow
  (`.github/workflows/reproduce.yml`) runs the same check on push.

## What is in this pack

| Path | Contents |
|---|---|
| `PINNED-SOURCES.md` | Pinned commit, vendored-file manifest, external dependency pin, specifications |
| `inventory/recovery-artifact-inventory.md` | Every rebuild artifact with location, backup status, and recovery verdict |
| `inventory/backup-integrity.md` | How keys are backed up today, integrity gaps, blast radius of a leak |
| `findings/findings-register.md` | 12 severity-ranked findings with assets, prerequisites, impact, evidence |
| `docs/runbook-host-loss.md` | Timed runbook: total host loss, rebuild from an off-host backup |
| `docs/runbook-key-compromise.md` | Timed runbook: signing-key compromise, rotation, revocation |
| `docs/runbook-key-loss.md` | Timed runbook: master-key loss with no backup (new identity) |
| `docs/claim-evidence-index.md` | Every substantive claim with label and evidence pointer |
| `docs/methodology.md` | Pinning, static analysis, models, label discipline, limitations |
| `scripts/run_all.sh` | Runs the full harness, preserves unedited outputs |
| `scripts/verify_digests.sh` | Verifies every deterministic shipped file against `SHA256SUMS` (excludes `outputs/run_all.log` and `outputs/reproduction/COMPARISON.md` — see `docs/methodology.md`) |
| `scripts/clean_reproduce.sh` | Fresh-clone reproduction from the pack alone (no network, no other repo, no Conan, no package manager) |
| `scripts/harness/` | `inventory_check.py`, `drill.py`, `recovery_coverage.py`, `ecdsa.py` (pure-Python ECDSA, stdlib only) |
| `.github/workflows/reproduce.yml` | CI: runs the fresh-clone check on push |
| `evidence/pinned-sources/` | Verbatim copies of the 31 cited pinned files |
| `evidence/pinned-tree-manifest.json` | Per-file blob SHA-1, size, SHA-256 for the vendored files |
| `evidence/pinned-tree-paths.txt` | Full 1,947-path listing of the pinned tree |
| `outputs/` | Unedited harness outputs (`*.json`, `run_all.log`) |
| `outputs/reproduction/COMPARISON.md` | Fresh-clone byte-comparison result |
| `SHA256SUMS` | Full SHA-256 digests of every deterministic shipped file (excludes `outputs/run_all.log` and `outputs/reproduction/COMPARISON.md`) |

## How to run

```sh
sh scripts/run_all.sh          # run the full harness; outputs land in outputs/
sh scripts/verify_digests.sh   # verify every deterministic shipped file against SHA256SUMS
sh scripts/clean_reproduce.sh  # fresh-clone reproduction; writes outputs/reproduction/COMPARISON.md
```

Requirements: Python 3 (standard library only) and `sha256sum`. No
network, no hardware, no package manager, no other repository.

## Labels

Every substantive claim is labelled: **MEASURED** (verified against
the pinned source or produced by executing the harness), **SIMULATED**
(software model of specified behaviour — no live validator involved),
**UNTESTABLE** (would need a live validator host, network access, or
operator/publisher action that was not available), **ANALYSIS**
(interpretation or recommendation).

No live-validator measurement is claimed anywhere in this pack. The build
machine has no validator host and no postfiatd binary; all recovery
behaviour is modelled in software and labelled SIMULATED, and rebuild
and re-sync durations on real hardware are UNTESTABLE.

## Pinned sources

- postfiatd `0085a1ff885d6a446369cf73a4430f75af22be55` (LIVE main HEAD,
  2026-10-10, 1.0.9), fetched via the GitHub API at build start.
- validator-keys-tool pinned to `05742108d4b7c0b7d9a97c073acd690d2c75a2b4`.
- References: XRPL validator keys/tokens documentation as cited by the
  pinned tree's own docs; NIST SP 800-57 Part 1 Rev. 5; NIST SP 800-130.
