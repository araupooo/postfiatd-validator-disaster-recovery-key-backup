# Runbook: master-key loss — no backup

Scenario: the master key is gone — no `validator-keys.json` backup, no
seed backup, or the backup is unreadable. Goal: establish a new validator
identity and regain trust. There is no recovery of the old identity; this
runbook is damage control.

Labels: MEASURED = measured in the lab drill; ESTIMATE = operator-time
judgement, not measured; UNTESTABLE = cannot be measured in the lab.

## Preconditions

- Accepted: the old identity is unrecoverable (drill DR-05 proves the
  three impossibilities below). Do not spend time searching for a
  recovery path that does not exist.
- Access to the `validator-keys` tool and to the UNL publisher process.

## What is impossible (prove it first, then move on)

| Capability | Why it is gone | Evidence |
|---|---|---|
| Generate a new token for the old identity | Needs the master key to sign the manifest | REC-25; drill DR-05 |
| Revoke the old identity | Revocation is a max-sequence manifest signed by the master key | REC-09, REC-26; drill DR-05, DR-06 |
| Update the old identity's domain | `set_domain` signs a new manifest with the master key | REC-25; drill DR-05 |

Lab model time for proving the three impossibilities (DR-05): **0.010–0.011 s** (two runs).

## Phases

| # | Phase | What it proves | Lab model time (MEASURED) | Operator time |
|---|---|---|---|---|
| 1 | Confirm the loss: search every backup location for `validator-keys.json` or the seed | No recovery path exists; the seed alone does NOT recover the sequence (DR-03) | 0.085–0.088 s (DR-03, what-not-to-do) | ESTIMATE: hours — be thorough, this is the last chance |
| 2 | Create a new identity (`validator-keys create_keys`) | New master key pair, new node ID, new public key | — | ESTIMATE: minutes |
| 3 | Create a token for the new identity and set the domain | New manifest, sequence 0, domain attestation | — | ESTIMATE: minutes |
| 4 | Get the new public key listed by the UNL publisher | Peers trust the new key; the old key is no longer yours to retire | — | UNTESTABLE (publisher process, external) |
| 5 | Back up the new `validator-keys.json` off-host, encrypted, with its SHA-256 recorded, before the first restart | The new identity does not repeat the old failure | — | ESTIMATE: minutes |
| 6 | Confirm the new validator validates on the network | Validations appear under the new node ID | — | ESTIMATE: 1–2 consensus rounds after listing |

## Verification gates

1. Do NOT rebuild from a seed alone. A seed-only restore resets the
   sequence to 0 and peers dispose the manifest as stale (F-02, drill
   DR-03) — it wastes the rebuild window and looks like progress.
2. The new node ID must differ from the old one. If it is the same, the
   "new" keys are the old keys, and the loss was misdiagnosed.
3. The old identity is never formally retired (revocation is impossible
   without the master key). Tell the UNL publisher explicitly so the old
   key is removed from the list rather than left to linger.
4. Back up before the first restart. The new `validator-keys.json` is
   deleted on container restart exactly like the old one (REC-02).

## What not to do

- Do not reuse the old domain attestation file for the new identity
  without re-running `set_domain`: the attestation is bound to the old
  public key.
- Do not keep validating under the old token while "sorting it out": if
  the master key is merely lost (not compromised) the old token still
  validates, but it cannot be rotated or revoked — it is a dead end, and
  every hour spent on it delays the new identity.
- Do not treat this runbook as a recovery: it is a re-creation. The
  honest label for the outcome is "new identity", not "recovered".
