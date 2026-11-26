# Disaster-recovery artifact inventory

Pinned commit: `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10, 1.0.9).
Every row is MEASURED (inventory check ID in the last column) unless marked
otherwise. Paths are relative to the pinned postfiatd tree and resolve under
`evidence/pinned-sources/`.

## What a validator needs to rebuild after total host loss

| # | Artifact | Where it lives | Backed up by any documented procedure? | Recovery verdict | Evidence |
|---|---|---|---|---|---|
| A-1 | Master secret (`validator-keys.json`) | `/root/.ripple/validator-keys.json` inside the container | Only by a manual `docker cp` the operator performs before a restart | RESTORABLE-or-LOST | REC-01, REC-02, REC-03 |
| A-2 | Validator token (signed manifest) | `[validator_token]` in `postfiatd.cfg`; source of truth is GitHub Secrets in the deploy workflow | Yes — re-injected from GitHub Secrets on every redeploy; also regenerable from the master key | RESTORABLE | REC-05, REC-07, REC-17, REC-18 |
| A-3 | Manifest sequence state | Inside `validator-keys.json`; nowhere else | Only as part of the `validator-keys.json` backup | PARTIAL | REC-04, REC-07 |
| A-4 | `postfiatd.cfg` (config) | `/etc/postfiatd/postfiatd.cfg` (`postfiatd-config` volume) | No — the volume is deleted on every redeploy; regenerable from the example config except token/seed sections | REGENERABLE | REC-12, REC-17, REC-18 |
| A-5 | `validators.txt` / UNL publisher list | `validators.txt` in the config directory; fetched from the publisher site | Yes — re-fetchable from the publisher site | RESTORABLE | REC-13, REC-14, REC-15 |
| A-6 | Node database / ledger data (NuDB) | `/var/lib/postfiatd/db/nudb` (`postfiatd-data` volume) | No — no backup artifact covers ledger data | RESYNC | REC-12, REC-24, REC-29 |
| A-7 | `wallet.db` (cached manifests, incl. revocations) | Node database directory | Only the hotfix doc orders a backup before destructive restarts | PARTIAL | REC-23, REC-29 |

Full per-artifact verdicts: `outputs/recovery_coverage.json`
(7 artifacts: 2 RESTORABLE, 1 REGENERABLE, 2 PARTIAL, 1 RESTORABLE-or-LOST,
1 RESYNC).

## Artifact details

### A-1 — Master secret

The master key pair is the permanent validator identity. It is created by
the `validator-keys` tool and stored in `validator-keys.json` at
`/root/.ripple/validator-keys.json` inside the container
(`docs/NodeSetup.md` line 291). The file is deleted whenever the container
is restarted or recreated (`docs/ValidatorKeyUpdate.md` line 16;
`docs/NodeSetup.md` lines 361-366). The documented backup is a manual
`docker cp` to a secure offline location before any restart
(`docs/NodeSetup.md` lines 367-372). Without that backup the operator loses
the ability to generate new tokens, update the domain, and revoke
compromised keys, and must create a completely new validator identity
(`docs/NodeSetup.md` lines 375-380). The master secret is a 128-bit seed
(`src/libxrpl/protocol/Seed.cpp` line 56); a seed alone re-derives the same
key pair, but it carries no sequence state (see A-3).

### A-2 — Validator token

The token is a signed manifest authorising an ephemeral signing key for the
validator identity. The token path in
`src/xrpld/app/misc/detail/ValidatorKeys.cpp` verifies the derived public
key equals the manifest signing key and adopts the manifest sequence
(REC-05). Each new token invalidates all previous tokens and carries a
higher sequence number (`docs/NodeSetup.md` line 274;
`docs/ValidatorKeyUpdate.md` lines 64, 239-240). In deployment the token is
never persisted: every redeploy deletes the config volume and re-injects
the token from GitHub Secrets over SSH, selected by host IP and network
(`.github/workflows/deploy.yml` lines 153, 255-286; REC-17, REC-18). A
token alone restores validation but not rotation or revocation (drill
DR-02).

### A-3 — Manifest sequence state

The current sequence number lives in `validator-keys.json`
(`docs/ValidatorKeyUpdate.md` line 75: the file "must already exist and
contain your validator's master key pair and the current sequence number").
The seed path sets sequence 0 (`ValidatorKeys.cpp` line 88), so a
seed-only restore produces a manifest peers dispose as stale
(`Manifest.cpp` line 411; drill DR-03). There is no out-of-band sequence
record anywhere in the tree.

### A-4 — Config

`postfiatd.cfg` lives in the `postfiatd-config` named Docker volume
(`scripts/docker-compose-validator.yml` lines 13, 39). The deploy workflow
deletes that volume on every redeploy (REC-17), so the running config is
rebuilt each time from the compose file plus the injected token. The
example config (`cfg/postfiatd-example.cfg`) documents every section, so a
config is regenerable except for the token/seed sections, which must come
from a backup or from Secrets.

### A-5 — Validator list / UNL

The trusted-validator file defaults to `validators.txt` in the config
directory (`src/xrpld/core/detail/Config.cpp` line 249; mainnet config
`[validators_file] validators.txt`). The mainnet file trusts exactly one
publisher key (`ED6B26F2D0832180FDEA23F626DC40A5297D2C86FD5F22EA8C5373CDFC29876366`)
and fetches the list from `https://postfiat.org/testnet_vl.json`
(`cfg/validators-mainnet.txt` lines 56, 59) — a testnet URL in the mainnet
file. With one publisher the list threshold is 1
(`ValidatorList.cpp` lines 210-212). A locally configured list never
expires (`ValidatorList.cpp` line 961). A rebuilt node with the wrong list
is silently untrusted (drill DR-08).

### A-6 — Ledger data

The node database is NuDB at `/var/lib/postfiatd/db/nudb`
(`cfg/postfiatd-mainnet-full.cfg` lines 1477-1479), inside the
`postfiatd-data` volume. No backup artifact in the tree covers ledger data
(REC-29). Ledger state is re-acquired from peers: the ledger replayer
fetches a skip list and ledger deltas from the network
(`docs/0010-ledger-replay/README.md`; REC-24). Re-sync duration is
UNTESTABLE in the lab (drill DR-09).

### A-7 — wallet.db

`wallet.db` holds cached manifests, including revocations
(`docs/MANIFEST_FLOOD_HOTFIX.md` lines 22, 100). The hotfix doc orders a
`wallet.db` backup before any destructive restart and states "Do not
delete wallet.db as a recovery procedure" (lines 45, 114). It is not part
of the documented validator backup, so it is usually lost with the host;
its loss is recoverable (manifests re-arrive from peers) but revocations
held only there can be lost.

## What the inventory does NOT cover

- Live host state: the build machine has no validator host, so volume
  contents, running config, and actual backup files on operator machines
  are UNTESTABLE here.
- The GitHub Secrets holding the validator tokens: their existence is
  MEASURED from the workflow file, but their contents and rotation state
  are UNTESTABLE from this pack.
- Ledger re-sync duration: UNTESTABLE (network-dependent).
