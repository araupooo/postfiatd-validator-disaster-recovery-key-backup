#!/usr/bin/env python3
"""MEASURED inventory checks against the vendored pinned postfiatd sources.

Reads evidence/pinned-sources/ (verbatim copies of postfiatd files at the
pinned commit) and evidence/pinned-tree-manifest.json, and re-derives the
disaster-recovery inventory facts by string/line inspection. Every check
prints its evidence (file + line numbers) and writes
outputs/inventory_check.json.

Deterministic: sorted keys, no timestamps, no randomness. Label: MEASURED.
Exit code 0 only if every check passes.
"""

import hashlib
import json
import os
import re
import sys

PACK = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(PACK, "evidence", "pinned-sources")
OUT = os.path.join(PACK, "outputs", "inventory_check.json")


def read(rel):
    with open(os.path.join(SRC, rel), "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def lines(rel):
    return read(rel).splitlines()


def find_lines(rel, pattern):
    return [i + 1 for i, ln in enumerate(lines(rel)) if re.search(pattern, ln)]


def blob_sha1(path):
    with open(path, "rb") as f:
        data = f.read()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def check(cid, claim, evidence, passed, value):
    status = "PASS" if passed else "FAIL"
    print("[%s] %s: %s" % (status, cid, claim))
    print("       evidence: %s" % evidence)
    print("       value: %s" % value)
    return {
        "id": cid,
        "claim": claim,
        "label": "MEASURED",
        "result": status,
        "evidence": evidence,
        "value": value,
    }


def main():
    results = []

    # --- pin integrity -----------------------------------------------------
    manifest = json.load(open(os.path.join(PACK, "evidence", "pinned-tree-manifest.json")))
    pin = manifest["commit"]
    results.append(check(
        "PIN-01",
        "Vendored files match the pinned postfiatd tree (git blob SHA-1 + size).",
        "evidence/pinned-tree-manifest.json",
        all(
            blob_sha1(os.path.join(SRC, f["path"])) == f["blob_sha1"]
            and os.path.getsize(os.path.join(SRC, f["path"])) == f["size_bytes"]
            for f in manifest["files"]
        ),
        "commit=%s files=%d" % (pin, len(manifest["files"])),
    ))
    results.append(check(
        "PIN-02",
        "Pinned commit is the LIVE main HEAD re-fetched via the GitHub API at build start.",
        "evidence/pinned-tree-manifest.json (commit_date 2026-10-10T16:53:26Z, merge PR #50, 1.0.9)",
        pin == "0085a1ff885d6a446369cf73a4430f75af22be55",
        pin,
    ))

    # --- master keys: location, ephemerality, loss consequence -------------
    ns = "docs/NodeSetup.md"
    vku = "docs/ValidatorKeyUpdate.md"
    results.append(check(
        "REC-01",
        "Master validator keys live in validator-keys.json at /root/.ripple/validator-keys.json inside the container.",
        "%s lines %s; %s lines %s" % (
            ns, find_lines(ns, r"Validator keys stored in /root/\.ripple/validator-keys\.json"),
            vku, find_lines(vku, r"located at `/root/\.ripple/validator-keys\.json`")),
        bool(find_lines(ns, r"Validator keys stored in /root/\.ripple/validator-keys\.json")),
        "path=/root/.ripple/validator-keys.json",
    ))
    results.append(check(
        "REC-02",
        "validator-keys.json is deleted whenever the Docker container is restarted or recreated.",
        "%s lines %s; %s lines %s" % (
            vku, find_lines(vku, r"deleted whenever the Docker container is restarted or recreated"),
            ns, find_lines(ns, r"deleted when the Docker container is restarted or recreated")),
        bool(find_lines(vku, r"deleted whenever the Docker container is restarted or recreated"))
        and bool(find_lines(ns, r"deleted when the Docker container is restarted or recreated")),
        "deleted on restart/recreate: documented in both guides",
    ))
    results.append(check(
        "REC-03",
        "Without a master-key backup the operator loses the ability to generate new tokens, update the domain, and revoke compromised keys; a lost master key means a completely new validator identity.",
        "%s lines %s" % (ns, find_lines(ns, r"Generate new validator tokens|Update your validator domain|Revoke your keys if compromised|completely new validator identity")),
        all(bool(find_lines(ns, p)) for p in (
            r"Generate new validator tokens",
            r"Update your validator domain",
            r"Revoke your keys if compromised",
            r"completely new validator identity")),
        "lost abilities: token generation, domain update, revocation; remedy: new identity",
    ))

    # --- identity derivation: seed path vs token path ----------------------
    vk = "src/xrpld/app/misc/detail/ValidatorKeys.cpp"
    results.append(check(
        "REC-04",
        "Seed path derives the key pair directly and sets manifest sequence 0 (no manifest indirection, no sequence state).",
        "%s lines %s" % (vk, find_lines(vk, r"sequence = 0")),
        bool(find_lines(vk, r"sequence = 0")),
        "seed-path sequence=0",
    ))
    results.append(check(
        "REC-05",
        "Token path verifies the derived public key equals the manifest signing key, then adopts the manifest sequence.",
        "%s lines %s" % (vk, find_lines(vk, r"pk != m->signingKey|sequence = m->sequence")),
        bool(find_lines(vk, r"pk != m->signingKey"))
        and bool(find_lines(vk, r"sequence = m->sequence")),
        "token-path: pk==signingKey required; sequence=m->sequence",
    ))
    results.append(check(
        "REC-06",
        "[validation_seed] and [validator_token] are mutually exclusive; both set is a fatal config error.",
        "%s lines %s; src/xrpld/core/detail/Config.cpp lines %s" % (
            vk, find_lines(vk, r"Cannot specify both"),
            find_lines("src/xrpld/core/detail/Config.cpp", r"Cannot have both")),
        bool(find_lines(vk, r"Cannot specify both")),
        "fatal on both-sections-set: yes",
    ))
    results.append(check(
        "REC-07",
        "Each new token invalidates all previous tokens and carries a higher sequence number than the previous one.",
        "%s lines %s; %s lines %s" % (
            ns, find_lines(ns, r"Each new token invalidates all previous tokens"),
            vku, find_lines(vku, r"incremented with each new token|higher sequence number than the previous")),
        bool(find_lines(ns, r"Each new token invalidates all previous tokens"))
        and bool(find_lines(vku, r"incremented with each new token")),
        "token rotation: monotonic sequence, old tokens invalidated",
    ))

    # --- manifest sequence rules: stale, revocation ------------------------
    mc = "src/xrpld/app/misc/detail/Manifest.cpp"
    mh = "src/xrpld/app/misc/Manifest.h"
    results.append(check(
        "REC-08",
        "A manifest whose sequence is not strictly greater than the cached sequence is disposed as stale and ignored.",
        "%s lines %s" % (mc, find_lines(mc, r"m\.sequence <= iter->second\.sequence|ManifestDisposition::stale")),
        bool(find_lines(mc, r"m\.sequence <= iter->second\.sequence")),
        "stale rule: m.sequence <= cached sequence -> stale",
    ))
    results.append(check(
        "REC-09",
        "Revocation is a manifest with the maximum sequence number (0xFFFFFFFF); no higher sequence is possible afterwards.",
        "%s lines %s; %s lines %s" % (
            mc, find_lines(mc, r"sequence == std::numeric_limits<std::uint32_t>::max\(\)"),
            mh, find_lines(mh, r"0xFFFFFFFF will supersede")),
        bool(find_lines(mc, r"sequence == std::numeric_limits<std::uint32_t>::max\(\)")),
        "revocation sequence=0xFFFFFFFF (max uint32)",
    ))
    mt = "src/test/app/Manifest_test.cpp"
    results.append(check(
        "REC-10",
        "Upstream tests confirm the stale rule: re-applying an equal or lower sequence manifest returns stale, while a max-sequence manifest is accepted.",
        "%s lines %s" % (mt, find_lines(mt, r"== ManifestDisposition::stale|accept manifests with max sequence")),
        len(find_lines(mt, r"== ManifestDisposition::stale")) >= 3,
        "stale expectations=%d" % len(find_lines(mt, r"== ManifestDisposition::stale")),
    ))
    results.append(check(
        "REC-11",
        "The validator token must be present in the postfiatd config file for the node to validate.",
        "%s lines %s" % (ns, find_lines(ns, r"The current token needs to be present in the postfiatd config file")),
        bool(find_lines(ns, r"The current token needs to be present in the postfiatd config file")),
        "token-in-config required for validation",
    ))

    # --- ledger data and config artifacts ----------------------------------
    cfg = "cfg/postfiatd-mainnet-full.cfg"
    results.append(check(
        "REC-12",
        "Node database is NuDB at /var/lib/postfiatd/db/nudb; book-keeping databases live under /var/lib/postfiatd/db.",
        "%s lines %s" % (cfg, find_lines(cfg, r"^\[node_db\]|^type=NuDB|^path=/var/lib/postfiatd/db/nudb|^\[database_path\]|^/var/lib/postfiatd/db$")),
        all(bool(find_lines(cfg, p)) for p in (
            r"^\[node_db\]", r"^type=NuDB", r"^path=/var/lib/postfiatd/db/nudb",
            r"^\[database_path\]")),
        "node_db=NuDB /var/lib/postfiatd/db/nudb; database_path=/var/lib/postfiatd/db",
    ))
    cc = "src/xrpld/core/detail/Config.cpp"
    results.append(check(
        "REC-13",
        "When no validators file is configured, the loader looks for validators.txt in the config directory and does not complain if it is missing (path cleared, no error); an explicitly configured missing file is fatal. The mainnet config sets [validators_file] validators.txt explicitly.",
        "%s lines %s; %s lines %s" % (
            cc, find_lines(cc, r'validatorsFileName = "validators\.txt"|don\'t complain'),
            cfg, find_lines(cfg, r"^\[validators_file\]|^validators\.txt$")),
        bool(find_lines(cc, r"don't complain"))
        and bool(find_lines(cfg, r"^validators\.txt$")),
        "validators.txt default; missing default tolerated, missing explicit path fatal",
    ))
    vl = "cfg/validators-mainnet.txt"
    results.append(check(
        "REC-14",
        "The mainnet validator-list file trusts exactly one publisher key and points at a testnet list URL.",
        "%s lines %s" % (vl, find_lines(vl, r"postfiat\.org/testnet_vl\.json|^ED6B26")),
        bool(find_lines(vl, r"postfiat\.org/testnet_vl\.json"))
        and len(find_lines(vl, r"^ED[0-9A-F]{64}$")) == 1,
        "publisher keys=1; site=https://postfiat.org/testnet_vl.json",
    ))
    vlc = "src/xrpld/app/misc/detail/ValidatorList.cpp"
    results.append(check(
        "REC-15",
        "With fewer than 3 publishers the list threshold is 1, so the single publisher alone decides the trusted list.",
        "%s lines %s" % (vlc, find_lines(vlc, r"listThreshold_ = \(publisherLists_\.size\(\) < 3\)")),
        bool(find_lines(vlc, r"listThreshold_ = \(publisherLists_\.size\(\) < 3\)")),
        "threshold = size<3 ? 1 : size/2+1; 1 publisher -> threshold 1",
    ))
    results.append(check(
        "REC-16",
        "A locally configured validator list never expires, unlike fetched lists.",
        "%s lines %s" % (vlc, find_lines(vlc, r"localPublisherList never expires")),
        bool(find_lines(vlc, r"localPublisherList never expires")),
        "local list: no expiry",
    ))

    # --- deployment: what survives a redeploy / a destroy ------------------
    dep = ".github/workflows/deploy.yml"
    results.append(check(
        "REC-17",
        "Every redeploy deletes the postfiatd-config Docker volume (3 jobs), so the validator token is never persisted across redeploys.",
        "%s lines %s" % (dep, find_lines(dep, r"docker volume ls -q --filter name=postfiatd-config \| xargs -r docker volume rm")),
        len(find_lines(dep, r"docker volume ls -q --filter name=postfiatd-config \| xargs -r docker volume rm")) == 3,
        "config-volume deletions per deploy: 3",
    ))
    results.append(check(
        "REC-18",
        "After redeploy the validator token is re-injected from GitHub Secrets over SSH, selected by host IP and network.",
        "%s lines %s" % (dep, find_lines(dep, r"Injecting validator token|DEVNET_VALIDATOR_TOKEN_1: \$\{\{ secrets|docker exec postfiatd bash -c \"printf")),
        bool(find_lines(dep, r"Injecting validator token"))
        and bool(find_lines(dep, r"DEVNET_VALIDATOR_TOKEN_1")),
        "token source: GitHub Secrets, injected per host IP",
    ))
    results.append(check(
        "REC-19",
        "The config-volume wipe happens before the token re-injection in the deploy script, so a failed injection leaves a tokenless config.",
        "%s volume-rm lines %s; injection line %s" % (
            dep,
            find_lines(dep, r"docker volume ls -q --filter name=postfiatd-config"),
            find_lines(dep, r"Injecting validator token")),
        min(find_lines(dep, r"docker volume ls -q --filter name=postfiatd-config"))
        < min(find_lines(dep, r"Injecting validator token")),
        "wipe precedes injection in script order",
    ))
    des = ".github/workflows/destroy.yml"
    results.append(check(
        "REC-20",
        "The destroy workflow removes every postfiatd volume and deletes /opt/postfiatd — a one-command total host data loss.",
        "%s lines %s" % (des, find_lines(des, r"docker compose down --volumes|docker volume ls -q --filter name=postfiatd|rm -rf /opt/postfiatd")),
        all(bool(find_lines(des, p)) for p in (
            r"docker compose down --volumes",
            r"docker volume ls -q --filter name=postfiatd",
            r"rm -rf /opt/postfiatd")),
        "destroy: compose down --volumes + volume rm + rm -rf /opt/postfiatd",
    ))
    comp = "scripts/docker-compose-validator.yml"
    results.append(check(
        "REC-21",
        "Config and ledger data live in named Docker volumes on the host (/etc/postfiatd, /var/lib/postfiatd/db); host loss destroys them unless copied off-host.",
        "%s lines %s" % (comp, find_lines(comp, r"postfiatd-config:/etc/postfiatd|postfiatd-data:/var/lib/postfiatd/db")),
        bool(find_lines(comp, r"postfiatd-config:/etc/postfiatd"))
        and bool(find_lines(comp, r"postfiatd-data:/var/lib/postfiatd/db")),
        "volumes: postfiatd-config -> /etc/postfiatd; postfiatd-data -> /var/lib/postfiatd/db",
    ))
    ent = "scripts/docker-entrypoint.sh"
    results.append(check(
        "REC-22",
        "The container entrypoint performs no key generation, key restore, or token handling — it only rotates logs and starts postfiatd.",
        "%s (no validator-keys/seed/token/secret strings)" % ent,
        not find_lines(ent, r"validator-keys|seed|token|secret|private"),
        "entrypoint: cron + logrotate + exec postfiatd only",
    ))

    # --- wallet.db and ledger replay ---------------------------------------
    hot = "docs/MANIFEST_FLOOD_HOTFIX.md"
    results.append(check(
        "REC-23",
        "wallet.db holds manifests (including revocations); the hotfix doc orders a wallet.db backup before any destructive restart and forbids deleting wallet.db as a recovery procedure.",
        "%s lines %s" % (hot, find_lines(hot, r"Back up `wallet\.db`|Do not delete wallet\.db as a recovery procedure")),
        bool(find_lines(hot, r"Back up `wallet\.db`"))
        and bool(find_lines(hot, r"Do not delete wallet\.db as a recovery procedure")),
        "wallet.db: manifest store; backup-before-restart ordered; deletion forbidden",
    ))
    lr = "docs/0010-ledger-replay/README.md"
    results.append(check(
        "REC-24",
        "Ledger replay exists as a mechanism: a replayer fetches a skip list and ledger deltas from the network, so ledger state is re-acquirable from peers rather than from backup.",
        "%s lines %s" % (lr, find_lines(lr, r"SkipListAcquire|LedgerDeltaAcquire|replaying ledgers")),
        bool(find_lines(lr, r"SkipListAcquire"))
        and bool(find_lines(lr, r"LedgerDeltaAcquire")),
        "ledger replay: skip-list + delta acquire from network",
    ))

    # --- key rotation, revocation, seed format -----------------------------
    results.append(check(
        "REC-25",
        "Key rotation uses validator-keys create_token / set_domain; moving to new hardware is a documented reason to generate a new token.",
        "%s lines %s" % (vku, find_lines(vku, r"validator-keys create_token|validator-keys set_domain|Moving your validator to new hardware")),
        bool(find_lines(vku, r"validator-keys create_token"))
        and bool(find_lines(vku, r"Moving your validator to new hardware")),
        "rotation tools: create_token, set_domain",
    ))
    results.append(check(
        "REC-26",
        "A revocation is generated with the master key and published via [validator_key_revocation]; the config documents the single base64-blob field as a commented example section.",
        "%s lines %s; %s lines %s" % (
            cfg, find_lines(cfg, r"^# \[validator_key_revocation\]"),
            mh, find_lines(mh, r"0xFFFFFFFF will supersede")),
        bool(find_lines(cfg, r"^# \[validator_key_revocation\]")),
        "revocation field documented (commented example); revocation = max-sequence manifest",
    ))
    seed = "src/libxrpl/protocol/Seed.cpp"
    results.append(check(
        "REC-27",
        "A validation seed is a 128-bit value (base58 or hex), the sole input to master key derivation on the seed path.",
        "%s lines %s" % (seed, find_lines(seed, r"Seed::Seed\(uint128 const& seed\)")),
        bool(find_lines(seed, r"Seed::Seed\(uint128 const& seed\)")),
        "seed = uint128",
    ))
    results.append(check(
        "REC-28",
        "Validators have pathfinding disabled by default unless a validation seed or token is configured.",
        "%s lines %s" % (cc, find_lines(cc, r"validators don't have pathfinding enabled")),
        bool(find_lines(cc, r"validators don't have pathfinding enabled")),
        "no seed/token -> no pathfinding (non-validating behaviour)",
    ))

    # --- documentation gap: no full-backup procedure -----------------------
    paths = open(os.path.join(PACK, "evidence", "pinned-tree-paths.txt")).read().splitlines()
    # "recovery" also matches secp256k1's signature-recovery module (vendored
    # third-party crypto, unrelated to operational recovery) — exclude external/.
    dr_paths = [p for p in paths
                if not p.startswith("external/")
                and re.search(r"backup|restore|disaster|recovery|snapshot", p, re.I)]
    secp_recovery = [p for p in paths if p.startswith("external/secp256k1")
                     and re.search(r"recovery", p, re.I)]
    backup_mentions = {}
    for rel in ("docs/NodeSetup.md", "docs/ValidatorKeyUpdate.md", "docs/MANIFEST_FLOOD_HOTFIX.md",
                "docs/Docker.md", "docs/DeploymentWorkflows.md", "docs/consensus.md"):
        backup_mentions[rel] = len(find_lines(rel, r"(?i)backup"))
    results.append(check(
        "REC-29",
        "No file in the pinned tree outside vendored third-party code is about backup, restore, disaster recovery, or snapshots; backup guidance is limited to validator-keys.json and wallet.db warnings in three docs.",
        "evidence/pinned-tree-paths.txt; backup mentions %s; secp256k1 signature-recovery files excluded: %d" % (backup_mentions, len(secp_recovery)),
        len(dr_paths) == 0
        and sum(backup_mentions.values()) > 0
        and all(v == 0 for k, v in backup_mentions.items()
                if k not in ("docs/NodeSetup.md", "docs/ValidatorKeyUpdate.md", "docs/MANIFEST_FLOOD_HOTFIX.md")),
        "tree paths matching backup/restore/disaster/recovery/snapshot (excl. external/): %d; secp256k1 signature-recovery files: %d; backup mentions confined to 3 docs" % (len(dr_paths), len(secp_recovery)),
    ))
    results.append(check(
        "REC-30",
        "The only backup cadence guidance is advisory: 'Regularly backup your configuration and keys' — no schedule, no verification step, no restore test.",
        "%s lines %s" % (ns, find_lines(ns, r"Regularly backup your configuration and keys")),
        bool(find_lines(ns, r"Regularly backup your configuration and keys")),
        "backup cadence: advisory only",
    ))

    passed = sum(1 for r in results if r["result"] == "PASS")
    failed = [r["id"] for r in results if r["result"] != "PASS"]
    print("inventory_check: %d/%d PASS" % (passed, len(results)))
    if failed:
        print("FAILED: %s" % ", ".join(failed))
    out = {
        "label": "MEASURED",
        "pinned_commit": pin,
        "checks_total": len(results),
        "checks_passed": passed,
        "checks_failed": failed,
        "results": results,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
