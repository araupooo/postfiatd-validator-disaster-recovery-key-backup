#!/usr/bin/env python3
"""Recovery coverage: per-artifact verdicts for a total-host-loss rebuild.

Each artifact a validator needs is rated by how it comes back after the
host is gone: RESTORABLE (off-host backup), REGENERABLE (rebuilt from
another artifact or from documented defaults), PARTIAL (comes back with
lost capability), RESYNC (re-acquired from the network, duration
UNTESTABLE), or LOST (unrecoverable). Verdicts cite the MEASURED
inventory checks they rest on.

Deterministic: no timestamps, no randomness. Label: ANALYSIS (verdicts)
over MEASURED inventory facts. Exit code 0 always (coverage is a report,
not a pass/fail gate); the JSON carries the verdicts.
"""

import json
import os
import sys

PACK = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(PACK, "outputs", "recovery_coverage.json")


def main():
    artifacts = [
        {
            "artifact": "Master secret (validator-keys.json)",
            "location": "/root/.ripple/validator-keys.json (inside the container)",
            "verdict": "RESTORABLE-or-LOST",
            "detail": "Restorable only from an off-host backup (REC-01, REC-02). The file is deleted on container restart/recreate and no key material exists anywhere else. Without a backup the identity is unrecoverable (REC-03, drill DR-05).",
            "inventory": ["REC-01", "REC-02", "REC-03"],
            "drill": "DR-01, DR-05",
        },
        {
            "artifact": "Validator token (signed manifest)",
            "location": "[validator_token] in postfiatd.cfg; source of truth is GitHub Secrets in the deploy workflow",
            "verdict": "RESTORABLE",
            "detail": "Restorable from an off-host backup, or regenerable from the master key with a higher sequence (REC-07, drill DR-04). A restored token with a regressed sequence is silently stale (REC-08, drill DR-03).",
            "inventory": ["REC-05", "REC-07", "REC-08"],
            "drill": "DR-01, DR-03, DR-04",
        },
        {
            "artifact": "Manifest sequence state",
            "location": "Stored in validator-keys.json; not stored anywhere else",
            "verdict": "PARTIAL",
            "detail": "Comes back only with validator-keys.json (REC-07). A seed-only restore resets the sequence to 0 (REC-04), which peers dispose as stale (REC-08, drill DR-03). There is no out-of-band sequence record in the tree.",
            "inventory": ["REC-04", "REC-07", "REC-08"],
            "drill": "DR-03",
        },
        {
            "artifact": "postfiatd.cfg (config)",
            "location": "/etc/postfiatd/postfiatd.cfg (postfiatd-config Docker volume)",
            "verdict": "REGENERABLE",
            "detail": "Restorable from an off-host backup, or regenerable from the documented example config except for the token/seed sections (REC-12). The deploy workflow deletes the config volume on every redeploy and re-injects the token from GitHub Secrets (REC-17, REC-18).",
            "inventory": ["REC-12", "REC-17", "REC-18", "REC-19"],
            "drill": "DR-01, DR-07",
        },
        {
            "artifact": "validators.txt / UNL publisher list",
            "location": "validators.txt in the config directory; fetched from the publisher site",
            "verdict": "RESTORABLE",
            "detail": "Restorable from backup, or re-fetchable from the publisher site (REC-13). The mainnet file trusts exactly one publisher key and a testnet URL (REC-14); with one publisher the threshold is 1 (REC-15). A wrong list silently un-trusts the validator (drill DR-08).",
            "inventory": ["REC-13", "REC-14", "REC-15", "REC-16"],
            "drill": "DR-01, DR-08",
        },
        {
            "artifact": "Node database / ledger data (NuDB)",
            "location": "/var/lib/postfiatd/db/nudb (postfiatd-data Docker volume)",
            "verdict": "RESYNC",
            "detail": "No backup artifact in the tree covers ledger data (REC-29). The node must re-acquire ledger state from peers via ledger replay (REC-24); how long that takes is UNTESTABLE in the lab (drill DR-09). A snapshot whose hash matches no validated ledger is unusable.",
            "inventory": ["REC-12", "REC-24", "REC-29"],
            "drill": "DR-01, DR-09",
        },
        {
            "artifact": "wallet.db (cached manifests, incl. revocations)",
            "location": "Node database directory (wallet.db)",
            "verdict": "PARTIAL",
            "detail": "Holds manifests; the hotfix doc orders a backup before any destructive restart and forbids deleting wallet.db as a recovery procedure (REC-23). It is not part of the documented validator backup (REC-29), so it is usually lost with the host.",
            "inventory": ["REC-23", "REC-29"],
            "drill": "DR-01",
        },
    ]
    counts = {}
    for a in artifacts:
        counts[a["verdict"]] = counts.get(a["verdict"], 0) + 1
    print("recovery coverage: %d artifacts" % len(artifacts))
    for verdict in sorted(counts):
        print("    %s: %d" % (verdict, counts[verdict]))
    out = {
        "label": "ANALYSIS",
        "pinned_commit": "0085a1ff885d6a446369cf73a4430f75af22be55",
        "artifacts_total": len(artifacts),
        "verdict_counts": counts,
        "artifacts": artifacts,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
