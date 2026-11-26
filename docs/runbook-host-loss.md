# Runbook: total host loss — rebuild from an off-host backup

Scenario: the validator host is gone (hardware failure, destroyed
container host, or a destroy-workflow run). The operator has an off-host
backup bundle. Goal: restore the same validator identity and resume
validation.

Labels: MEASURED = measured in the lab drill; ESTIMATE = operator-time
judgement, not measured; UNTESTABLE = cannot be measured in the lab.
Lab model times below are the cryptographic/model steps on the build
machine (pure-Python secp256k1), NOT wall-clock operator time.

## Preconditions

- An off-host backup bundle containing, at minimum: `validator-keys.json`
  (master secret + current sequence), the validator token, `postfiatd.cfg`,
  `validators.txt`, and the `wallet.db` copy if one was taken.
- A replacement host with Docker and the postfiatd image.
- Access to GitHub Secrets (fallback token source) and to the UNL
  publisher site.

## Phases

| # | Phase | What it proves | Lab model time (MEASURED) | Operator time |
|---|---|---|---|---|
| 0 | Confirm total loss: no local artifact survives | The destroy workflow removes all volumes and `/opt/postfiatd` (REC-20); an on-host-only backup is destroyed by the same event (drill DR-10) | 0.166–0.215 s (DR-10, two runs) | ESTIMATE: minutes |
| 1 | Verify bundle completeness + digests | All 6 artifacts present, digests match (drill DR-01) | part of 0.128–0.619 s (DR-01) | ESTIMATE: minutes |
| 2 | Restore identity from the master secret | Same node ID as before (drill DR-01) | part of 0.128–0.619 s (DR-01) | ESTIMATE: minutes |
| 3 | Restore and verify the token | Both manifest signatures valid, sequence continuous (drill DR-01) | part of 0.128–0.619 s (DR-01) | ESTIMATE: minutes |
| 4 | Restore config + validators.txt, check UNL | Own key in the publisher list (drill DR-01) | part of 0.128–0.619 s (DR-01) | ESTIMATE: minutes |
| 5 | Start the node; ledger re-sync | Ledger base usable if the snapshot hash is a validated hash (drill DR-01); catch-up sync time is UNTESTABLE | — | UNTESTABLE (network-dependent) |
| 6 | Confirm validation resumes | Validations appear on the network; this is the only proof that matters | — | ESTIMATE: observe 1–2 consensus rounds |

Measured lab model time for the full rebuild drill (DR-01): **0.128–0.619 s observed across two runs** (0.619 s first run, 0.128 s second run — shared-CPU variance).
That number covers only the cryptographic and check steps. Real recovery
is dominated by provisioning, copying, and ledger sync — none of which
the lab can time.

## Verification gates (do not skip)

1. Bundle completeness 6/6 before touching the replacement host. A missing
   `validator-keys.json` changes the outcome to DR-02 (partial) or DR-05
   (unrecoverable) — know which one you are in before you start.
2. Node ID after restore must equal the pre-loss node ID. A different node
   ID means the wrong master secret was restored.
3. Token sequence must equal the backed-up sequence. A lower sequence
   means the backup predates a rotation — expect a stale disposition
   (F-08).
4. Own key must be in the UNL. If it is not, stop: the node will sign
   validations peers ignore (F-05, drill DR-08).
5. Validations visible on the network. A healthy-looking node that does
   not validate is the failure mode of DR-07 — check the network, not
   just the process.

## Failure branches

- Bundle has the token but no `validator-keys.json` → DR-02: validation
  resumes, but rotation and revocation are lost. Treat the validator as
  degraded; plan a controlled identity migration.
- Bundle has only the seed → DR-03: do NOT rebuild from the seed alone;
  the sequence resets to 0 and peers ignore the validator. Recover the
  sequence from an external record first, or treat as key loss.
- No bundle at all → key-loss runbook (`docs/runbook-key-loss.md`).
- Snapshot hash matches no validated ledger → DR-09: full re-sync; time
  UNTESTABLE.
