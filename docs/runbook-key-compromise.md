# Runbook: signing-key compromise — rotate, then revoke if needed

Scenario: the ephemeral signing key is suspected compromised (or routine
rotation is due). The master key is safe and available in
`validator-keys.json`. Goal: move validation to a new signing key without
losing trust, and revoke if the master key itself is compromised.

Labels: MEASURED = measured in the lab drill; ESTIMATE = operator-time
judgement, not measured; UNTESTABLE = cannot be measured in the lab.

## Preconditions

- `validator-keys.json` restored into the container (`docker cp` from the
  off-host backup — the file is deleted on container restart).
- The `validator-keys` tool available in the container.
- The current manifest sequence known (it lives in `validator-keys.json`).

## Phases

| # | Phase | What it proves | Lab model time (MEASURED) | Operator time |
|---|---|---|---|---|
| 1 | Generate a new token (`validator-keys create_token`, or `set_domain` for domain + key together) | New signing key, sequence incremented by one (REC-25; `docs/ValidatorKeyUpdate.md` lines 104, 116) | part of 0.365 s (DR-04) | ESTIMATE: minutes |
| 2 | Verify the new manifest | Both signatures valid, sequence 4 > cached 3, peer disposition accepted (drill DR-04) | part of 0.365 s (DR-04) | — |
| 3 | Deploy the new token, restart, confirm validation resumes | New token accepted; old token replayed afterwards is stale (drill DR-04) | — | ESTIMATE: minutes + 1–2 consensus rounds |
| 4 | Back up the updated `validator-keys.json` immediately | The file now contains the new sequence number (`docs/ValidatorKeyUpdate.md` lines 43-48); an old backup is now stale (F-08) | — | ESTIMATE: minutes |
| 5 | If the MASTER key is compromised: publish a revocation | Max-sequence manifest (0xFFFFFFFF) signed by the master key; peers drop trust permanently (drill DR-06) | 0.584 s (DR-06) | ESTIMATE: minutes; propagation UNTESTABLE |

Measured lab model times: rotation drill (DR-04) **0.365–0.471 s**;
revocation drill (DR-06) **0.584–1.393 s** (observed ranges across two
runs; shared-CPU variance). Both cover only the cryptographic/model steps.

## Verification gates

1. New sequence is exactly old sequence + 1. A jump or a repeat means
   the wrong `validator-keys.json` was restored.
2. Old token is stale after rotation. If the old token is still accepted,
   the new token did not propagate — do not assume the rotation worked.
3. Back up the updated file before doing anything else. The pre-rotation
   backup is now a silent-failure backup (F-08).
4. Revocation is terminal and needs the master key. If the master key is
   lost, revocation is impossible (F-09) — go to the key-loss runbook.

## Failure branches

- No `validator-keys.json` available → rotation is impossible; the token
  alone cannot sign a new manifest. Treat as key loss
  (`docs/runbook-key-loss.md`).
- New token rejected as stale → the sequence used was not higher than the
  cached one; the wrong sequence state was restored. Stop and re-check
  the backup's sequence before retrying.
- Master key compromised AND lost → cannot revoke; the only remedy is a
  new identity plus UNL publisher action (F-01, F-09).
