# Findings register — validator disaster recovery and key backup

Pinned commit: `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10, 1.0.9).
Severity is assessed from exploitability and impact on the validator's
ability to recover and keep validating; it is ANALYSIS, not a measured
quantity. Evidence pointers are MEASURED (pinned source) or SIMULATED
(drill model). No finding claims a live-validator measurement that was
not performed.

Counts: 1 Critical, 4 High, 4 Medium, 2 Low, 1 Informational.

## F-01 — CRITICAL — Master-key loss without an off-host backup is permanent identity loss

- Affected assets: the validator identity itself (master key pair), and
  every capability that flows from it: token generation, domain update,
  revocation.
- Prerequisites: none. The loss event is a container restart, a host
  failure, or a destroy-workflow run without a prior off-host backup.
- Impact: the validator cannot be rebuilt as the same identity. The
  operator must create a completely new identity and get it listed by the
  UNL publisher — a new trust relationship, not a recovery. All prior
  reputation, domain attestation, and list presence are gone.
- Evidence (MEASURED): `validator-keys.json` is deleted on restart /
  recreate (`docs/ValidatorKeyUpdate.md` line 16); without a backup the
  operator loses token generation, domain update, and revocation
  (`docs/NodeSetup.md` lines 375-380); the destroy workflow removes all
  volumes and `/opt/postfiatd` (REC-20).
- Model (SIMULATED): drill DR-05 — no master key means no new token, no
  revocation, no domain update; only remedy is a new identity with a
  different node ID.

## F-02 — HIGH — A seed-only backup silently fails: sequence resets to 0 and peers ignore the validator

- Affected assets: any validator rebuilt from a seed backup without the
  sequence state.
- Prerequisites: the operator backed up the 128-bit seed (or the seed
  phrase) but not `validator-keys.json`.
- Impact: the rebuilt node starts, looks healthy, and signs validations —
  and peers ignore every one of them, because the seed path sets manifest
  sequence 0 while peers already cached a higher sequence. The failure is
  silent locally; it is visible only as missing validations on the
  network.
- Evidence (MEASURED): seed path sets sequence 0
  (`ValidatorKeys.cpp` line 88); a manifest with sequence not strictly
  greater than cached is stale (`Manifest.cpp` line 411); the sequence
  lives only in `validator-keys.json` (`docs/ValidatorKeyUpdate.md`
  line 75).
- Model (SIMULATED): drill DR-03 — rebuilt token sequence 0, peer
  disposition stale, zero validations accepted.

## F-03 — HIGH — A token-only backup masquerades as a full recovery

- Affected assets: any validator whose "backup" is the validator token
  alone.
- Prerequisites: the operator backed up the token (or relies on GitHub
  Secrets) but lost the master key.
- Impact: validation resumes — the token verifies — so the recovery looks
  complete. But rotation and revocation both need the master key, which is
  gone. The gap is discovered only at the next rotation or compromise,
  the worst possible moment.
- Evidence (MEASURED): token path needs only the token to validate
  (REC-05); rotation and revocation need the master key (REC-25, REC-26).
- Model (SIMULATED): drill DR-02 — validation resumes, rotation and
  revocation impossible; verdict PARTIAL.

## F-04 — HIGH — A failed token injection after a redeploy leaves a silently non-validating node

- Affected assets: every validator deployed by the CI workflow.
- Prerequisites: the deploy wipes the config volume, then injects the
  token from GitHub Secrets by host IP; the injection fails (wrong IP,
  missing secret, SSH failure).
- Impact: the node starts with a valid config and no validator keys. It
  runs, serves RPC, looks healthy — and validates nothing. Pathfinding is
  also off without a seed or token (`Config.cpp` lines 676-678).
- Evidence (MEASURED): config volume deleted on every redeploy
  (`.github/workflows/deploy.yml` lines 153, 403, 663); wipe precedes
  injection in script order (REC-19); token injected from Secrets by host
  IP (REC-18).
- Model (SIMULATED): drill DR-07 — no keys loaded, node starts, zero
  validations, no local error.

## F-05 — HIGH — The mainnet validator list trusts one publisher at a testnet URL; a wrong list silently un-trusts the validator

- Affected assets: every validator's UNL membership; the network's trust
  in a rebuilt validator.
- Prerequisites: the rebuilt node fetches or is configured with the wrong
  list (wrong publisher key, stale file, or the testnet URL serving
  unexpected content).
- Impact: the validator signs, but peers do not trust it because its key
  is not on their UNL. Nothing in the local log says so. With one
  publisher the threshold is 1, so a single wrong publisher key decides
  the outcome.
- Evidence (MEASURED): mainnet file has one publisher key and a testnet
  URL (`cfg/validators-mainnet.txt` lines 56, 59); threshold is 1 with
  fewer than 3 publishers (`ValidatorList.cpp` lines 210-212).
- Model (SIMULATED): drill DR-08 — own key absent from the list,
  validations ignored, no local error.

## F-06 — MEDIUM — Ledger data has no backup artifact; rebuild requires a re-sync of UNTESTABLE duration

- Affected assets: node database (NuDB), ledger history.
- Prerequisites: total host loss.
- Impact: the rebuilt node must re-acquire ledger state from peers via
  ledger replay. The mechanism exists (REC-24), but how long a re-sync
  takes on a real host is not measurable in the lab and is not bounded
  anywhere in the tree. A snapshot whose hash matches no validated ledger
  cannot seed the database at all.
- Evidence (MEASURED): `[node_db]` NuDB at `/var/lib/postfiatd/db/nudb`
  (REC-12); no backup artifact covers ledger data (REC-29); ledger
  replay fetches skip lists and deltas from the network (REC-24).
- Model (SIMULATED): drill DR-09 — snapshot hash not in the validated
  set, re-sync required, duration UNTESTABLE.

## F-07 — MEDIUM — Master keys are plaintext; encryption of backups is advisory only

- Affected assets: every `validator-keys.json` backup copy.
- Prerequisites: the operator copies the backup to any unencrypted
  medium.
- Impact: whoever holds the file holds the validator identity. Nothing in
  the tree encrypts the file, checks that a backup is encrypted, or
  verifies a backup at all. The guidance ("encrypted USB drive, secure
  vault, etc.") is advice, not a control.
- Evidence (MEASURED): the file is plaintext JSON; the only encryption
  mentions are advisory (`docs/NodeSetup.md` lines 367-372;
  `docs/ValidatorKeyUpdate.md` lines 43-48); no verification step exists
  (REC-30).
- Model (SIMULATED): not modelled — a process finding, not a code path.

## F-08 — MEDIUM — Every rotation invalidates all previous tokens, so an old backup restored after a rotation is silently stale

- Affected assets: any backup restored after a key rotation.
- Prerequisites: the operator rotates the signing key (routine practice,
  every 6-12 months per the guide), then later restores an older backup.
- Impact: the restored token carries a lower sequence than the one peers
  cached and is stale. The node looks healthy and does not validate.
  Backups are therefore only valid until the next rotation, and nothing in
  the tree versions, timestamps, or expires them.
- Evidence (MEASURED): each new token invalidates all previous tokens
  (REC-07); stale rule (REC-08).
- Model (SIMULATED): drill DR-04 — old token replayed after rotation is
  stale.

## F-09 — MEDIUM — Revocation requires the master key, so a lost master key cannot be revoked

- Affected assets: a compromised signing key whose master key is lost.
- Prerequisites: master-key loss (same event as F-01) combined with a
  compromised signing key.
- Impact: the operator cannot publish a revocation for the compromised
  key, because revocation is a max-sequence manifest signed by the master
  key. The compromised signing key stays trusted until the UNL publisher
  removes the validator — an external action with UNTESTABLE timing.
- Evidence (MEASURED): revocation is sequence 0xFFFFFFFF signed by the
  master key (REC-09, REC-26).
- Model (SIMULATED): drill DR-06 — revocation works only with the master
  key; drill DR-05 — without it, revocation is impossible.

## F-10 — LOW — wallet.db holds manifests but is not part of the documented validator backup

- Affected assets: cached manifests, including revocations.
- Prerequisites: total host loss.
- Impact: manifests re-arrive from peers, so the loss is recoverable —
  but revocations held only in `wallet.db` can be lost, and the hotfix doc
  explicitly orders a backup before destructive restarts and forbids
  deleting `wallet.db` as a recovery procedure. The validator backup
  procedure does not mention it.
- Evidence (MEASURED): REC-23.
- Model (SIMULATED): drill DR-01 includes `wallet.db` in the complete
  bundle; its absence does not block validation.

## F-11 — LOW — No backup cadence, verification, or restore test anywhere

- Affected assets: every backup an operator believes they have.
- Prerequisites: none — this is the steady state.
- Impact: the only cadence guidance is "Regularly backup your
  configuration and keys" (REC-30). No schedule, no checksum, no test
  restore. A corrupted, truncated, or stale backup is discovered only
  when it is needed, under pressure.
- Evidence (MEASURED): REC-29, REC-30.
- Model (SIMULATED): not modelled — a process finding.

## F-12 — INFORMATIONAL — Config and UNL are regenerable; the identity is the only irreplaceable artifact

- Affected assets: `postfiatd.cfg`, `validators.txt`.
- Prerequisites: none.
- Impact: none directly — this is the good news that bounds the other
  findings. The config is regenerable from the example config, and the
  UNL is re-fetchable from the publisher site. Only the master secret and
  its sequence state are irreplaceable. A backup strategy that protects
  exactly those two things covers the catastrophic case.
- Evidence (MEASURED): REC-12, REC-13, REC-14, REC-15.
- Model (SIMULATED): drill DR-01 — config and UNL restore cleanly from
  the bundle.
