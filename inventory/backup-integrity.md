# Key-backup integrity assessment

Pinned commit: `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10, 1.0.9).
Claims are MEASURED unless labelled otherwise. Evidence pointers are
inventory-check IDs (`outputs/inventory_check.json`) and pinned-tree
paths (relative to the tree, resolving under `evidence/pinned-sources/`).

## How keys are backed up today

There is exactly one documented backup mechanism for the master key: a
manual `docker cp` of `validator-keys.json` out of the container to a
secure offline location, performed by the operator before any container
restart (`docs/NodeSetup.md` lines 361-372; `docs/ValidatorKeyUpdate.md`
lines 16, 43-48). The guidance says to store the backup on an encrypted
USB drive or in a secure vault, and never to keep the file on the
validator machine after backing it up. There is no automated backup, no
backup schedule, no backup verification step, and no restore test anywhere
in the tree (REC-29, REC-30).

The validator token is backed up differently: it is not backed up at all
by the operator. It lives as a GitHub Secret and is re-injected on every
redeploy (`.github/workflows/deploy.yml` lines 100-110, 255-286). The
config volume that held it is deleted first (REC-17).

## Integrity findings

### 1. Plaintext master keys, encryption advisory only

`validator-keys.json` is a plaintext JSON file holding the master secret.
The docs advise storing the backup on "an encrypted USB drive, secure
vault, etc." — advice, not enforcement. Nothing in the tree encrypts the
file, checks that a backup is encrypted, or verifies a backup at all. A
backup copied to an unencrypted disk, a shared drive, or a chat message is
a full compromise of the validator identity, with no control in the tree
that would catch it. (Finding F-07.)

### 2. The backup is a single manual step with no verification

The procedure is: copy the file, store it offline, done. There is no
checksum recorded, no test restore, no second copy required, and no
expiry/rotation of the backup itself. A corrupted, truncated, or stale
copy is discovered only when it is needed — at rebuild time, under
pressure. The sequence number inside the file is the only freshness
signal, and nothing tells the operator to record it separately. (Finding
F-11.)

### 3. Token-only backups look complete and are not

A backup containing only the validator token restores validation: the
token verifies and the node validates (drill DR-02). But rotation and
revocation both need the master key, which is gone. An operator who
backed up "the validator credentials" as the token alone will discover
the gap only at the next rotation or compromise — the worst possible
moment. (Finding F-03.)

### 4. Seed-only backups lose the sequence

A 128-bit seed re-derives the same master key pair (REC-27), so a seed
backup feels sufficient. It is not: the seed path sets manifest sequence
0 (REC-04), and peers already cached a higher sequence, so the rebuilt
manifest is disposed as stale and the validator's validations are ignored
(REC-08, drill DR-03). The sequence lives only in `validator-keys.json`
(REC-07). A seed backup without a sequence record is a silent-failure
backup. (Finding F-02.)

### 5. Rotation invalidates old backups silently

Each new token invalidates all previous tokens (REC-07). An old backup
restored after a rotation carries a lower sequence than the one peers
cached and is stale (drill DR-04). Backups are therefore only valid until
the next rotation; nothing in the tree versions, timestamps, or expires
them. An operator restoring "the backup" after a rotation gets a healthy
looking node that does not validate. (Finding F-08.)

### 6. Revocation needs the very key that may be lost

Revocation is a max-sequence manifest signed by the master key (REC-09,
REC-26). If the master key is compromised, the operator can revoke — but
only if the master key is still available. If the master key is lost (the
same event that forces a rebuild), revocation of the compromised signing
key is impossible, and the old identity can never be formally retired.
(Finding F-09.)

### 7. The deploy pipeline is the real backup for tokens — and a risk

Tokens live in GitHub Secrets and are injected over SSH by host IP
(REC-18). That makes Secrets the single source of truth for validator
identity material in production. The pack cannot assess the Secrets'
own backup, rotation, or access control — that state is UNTESTABLE from
the tree. If a secret is deleted or the host-IP mapping drifts, the
deploy injects nothing and the validator starts tokenless (drill DR-07).
(Finding F-04.)

### 8. Ledger data and wallet.db are outside the backup

No procedure backs up the node database or `wallet.db` (REC-29). Ledger
state is re-synced (REC-24); `wallet.db` manifests re-arrive from peers,
but revocations held only there can be lost (REC-23). This is acceptable
for ledger data (re-sync is the designed path) but means the rebuild
depends on peer availability and takes an UNTESTABLE amount of time.
(Finding F-06.)

## Blast radius of a leaked backup

| Leaked artifact | Attacker gains | Remedy | Needs |
|---|---|---|---|
| `validator-keys.json` (master secret) | Full validator identity: can issue tokens, rotate signing keys, revoke the identity | Revoke the master key (max-sequence manifest) and create a new identity | Master key (which the attacker also has — race) |
| Validator token only | Validation as the validator until the next rotation | Rotate the signing key (new token, higher sequence) | Master key |
| Validation seed only | Same as master secret (seed derives the master key) | Same as master-key leak | Master key / seed |
| `postfiatd.cfg` | Config, peer list, no keys | Re-issue config | Nothing secret |
| `validators.txt` | Public trust list | None needed | Nothing secret |

A leaked master secret is the worst case: the attacker can rotate the
signing key themselves and issue valid tokens, and the operator's only
counter is a revocation race with the same key. There is no documented
incident procedure for this in the tree.

## What "good" would look like

1. Two off-host copies of `validator-keys.json`, encrypted, with recorded
   SHA-256 digests and a scheduled test restore.
2. The current manifest sequence recorded out-of-band with every backup.
3. A backup checklist that distinguishes token-only, seed-only, and full
   backups and states what each can and cannot restore.
4. A documented rotation procedure that re-backs-up immediately after
   every token change (the guide already says to back up the updated file
   — `docs/ValidatorKeyUpdate.md` lines 43-48 — but nothing enforces it).
5. A documented incident procedure for a leaked master key, including the
   revocation race and the new-identity path.
