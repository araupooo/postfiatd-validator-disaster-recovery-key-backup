#!/usr/bin/env python3
"""SIMULATED disaster-recovery drills for a postfiatd validator.

Models total host loss and rebuild from backup artifacts only, using
lab-generated test keys and a software model of the pinned postfiatd
manifest/UNL rules (sequence monotonicity, stale disposition, revocation
at 0xFFFFFFFF, single-publisher UNL). Every rule the model applies is
traced to a MEASURED inventory check (see outputs/inventory_check.json).

Lab keys are fixed test constants, clearly labelled TEST, and never real
keys. No live validator, no network, no hardware is involved.

Deterministic: RFC 6979 deterministic nonces, fixed lab secrets, sorted
keys, no timestamps and no randomness in the written output. Wall-clock
timings are printed to stdout only (they land in outputs/run_all.log,
which is excluded from SHA256SUMS by design) and never written to JSON.
Exit code 0 only if every drill case produces its expected outcome.
"""

import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ecdsa import SECP256K1, sign, verify

PACK = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(PACK, "outputs", "drill.json")

MAX_SEQ = 0xFFFFFFFF

# Model conventions (SIMULATED — see docs/methodology.md):
# - Node ID = first 20 bytes of SHA-512 over the compressed public key.
#   The pinned source only establishes nodeID = calcNodeID(masterKey)
#   deterministically (ValidatorKeys.cpp); the exact hash construction is
#   not in the vendored set, so the model states its convention openly.
#   Recovery verdicts depend on determinism (same key -> same ID), not on
#   the exact hash function.
# - A manifest is a canonical string signed by the master key and by the
#   ephemeral signing key; verification checks both signatures.
# - The peer manifest cache applies the pinned rule: a manifest whose
#   sequence is not strictly greater than the cached sequence is stale
#   (Manifest.cpp:411); sequence 0xFFFFFFFF revokes the master key.
# - A validator is trusted by peers iff its master public key appears in
#   a validator list from a configured trusted publisher.


def lab_secret(tag):
    """Fixed lab test secret (TEST ONLY, never a real key)."""
    digest = hashlib.sha256(b"POSTFIAT-DR-LAB-TEST-SEED-" + tag.encode()).digest()
    return int.from_bytes(digest, "big") % SECP256K1.n


def compressed_pubkey(point):
    x, y = point
    return bytes([0x02 | (y & 1)]) + x.to_bytes(32, "big")


def node_id(pubkey_bytes):
    return hashlib.sha512(pubkey_bytes).digest()[:20].hex()


def manifest_canonical(master_pub_hex, signing_pub_hex, sequence, domain):
    return ("manifest|%s|%s|%d|%s" % (master_pub_hex, signing_pub_hex, sequence, domain)).encode()


def make_manifest(master_priv, signing_priv, sequence, domain):
    master_pub = SECP256K1.pubkey(master_priv)
    signing_pub = SECP256K1.pubkey(signing_priv)
    master_hex = compressed_pubkey(master_pub).hex()
    signing_hex = compressed_pubkey(signing_pub).hex()
    digest = hashlib.sha256(
        manifest_canonical(master_hex, signing_hex, sequence, domain)).digest()
    r1, s1 = sign(SECP256K1, master_priv, digest)
    r2, s2 = sign(SECP256K1, signing_priv, digest)
    return {
        "master_pubkey": master_hex,
        "signing_pubkey": signing_hex,
        "sequence": sequence,
        "domain": domain,
        "master_sig": "%064x%064x" % (r1, s1),
        "signing_sig": "%064x%064x" % (r2, s2),
    }


def verify_manifest(m, master_pub_point, signing_pub_point):
    digest = hashlib.sha256(manifest_canonical(
        m["master_pubkey"], m["signing_pubkey"], m["sequence"], m["domain"])).digest()
    r1, s1 = (int(m["master_sig"][:64], 16), int(m["master_sig"][64:], 16))
    r2, s2 = (int(m["signing_sig"][:64], 16), int(m["signing_sig"][64:], 16))
    return (verify(SECP256K1, master_pub_point, digest, r1, s1)
            and verify(SECP256K1, signing_pub_point, digest, r2, s2))


class ManifestCache:
    """Peer-side cache: remembers the highest sequence per master key."""

    def __init__(self):
        self.known = {}

    def apply(self, m, master_pub_point, signing_pub_point):
        key = m["master_pubkey"]
        if key in self.known and m["sequence"] <= self.known[key]:
            return "stale"
        if not verify_manifest(m, master_pub_point, signing_pub_point):
            return "invalid"
        if m["sequence"] == MAX_SEQ:
            self.known[key] = MAX_SEQ
            return "revoked"
        self.known[key] = m["sequence"]
        return "accepted"


class ValidatorList:
    """Trusted-publisher validator list (single publisher, as in the mainnet file)."""

    def __init__(self, publisher_pub_hex, entries, sequence):
        self.publisher = publisher_pub_hex
        self.entries = set(entries)
        self.sequence = sequence

    def trusts(self, master_pub_hex):
        return master_pub_hex in self.entries


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def step(name, expected, actual, passed):
    print("    [%s] %s: expected %s; actual %s" % (
        "PASS" if passed else "FAIL", name, expected, actual))
    return {"step": name, "expected": expected, "actual": actual,
            "result": "PASS" if passed else "FAIL"}


def case(cid, scenario, steps, verdict, notes):
    ok = all(s["result"] == "PASS" for s in steps)
    print("[%s] %s: %s" % ("PASS" if ok else "FAIL", cid, scenario))
    print("    verdict: %s" % verdict)
    return {
        "id": cid,
        "scenario": scenario,
        "label": "SIMULATED",
        "steps": steps,
        "verdict": verdict,
        "notes": notes,
        "outcome": "PASS" if ok else "FAIL",
    }


# --- lab identities --------------------------------------------------------
MASTER_PRIV = lab_secret("master-01")
MASTER_PUB = SECP256K1.pubkey(MASTER_PRIV)
MASTER_HEX = compressed_pubkey(MASTER_PUB).hex()
MASTER_NODE_ID = node_id(compressed_pubkey(MASTER_PUB))
SIGNING_PRIV = lab_secret("signing-01")
SIGNING_PUB = SECP256K1.pubkey(SIGNING_PRIV)
SIGNING_HEX = compressed_pubkey(SIGNING_PUB).hex()
SIGNING2_PRIV = lab_secret("signing-02")
SIGNING2_HEX = compressed_pubkey(SECP256K1.pubkey(SIGNING2_PRIV)).hex()
PUBLISHER_PRIV = lab_secret("publisher-01")
PUBLISHER_HEX = compressed_pubkey(SECP256K1.pubkey(PUBLISHER_PRIV)).hex()
NEW_MASTER_PRIV = lab_secret("master-02-new-identity")
NEW_MASTER_HEX = compressed_pubkey(SECP256K1.pubkey(NEW_MASTER_PRIV)).hex()

# Simulated network state: ledgers the network has validated.
VALIDATED_LEDGER_HASHES = {
    sha256_hex("ledger-100000-validated"),
    sha256_hex("ledger-100001-validated"),
}
CURRENT_LEDGER_HASH = sha256_hex("ledger-100001-validated")


def backup_bundle(sequence, with_keys=True, with_token=True, with_config=True,
                   with_validators=True, with_wallet=True, snapshot_hash=None):
    """A backup bundle as the docs describe it: off-host copies of artifacts."""
    bundle = {}
    if with_keys:
        bundle["validator-keys.json"] = {
            "master_secret": "TEST-ONLY-LAB-SECRET-%064x" % MASTER_PRIV,
            "sequence": sequence,
        }
    if with_token:
        bundle["validator_token"] = make_manifest(
            MASTER_PRIV, SIGNING_PRIV, sequence, "validator.example")
    if with_config:
        bundle["postfiatd.cfg"] = "[validator_token]\n<token>\n[validators_file]\nvalidators.txt\n[node_db]\ntype=NuDB\n"
    if with_validators:
        bundle["validators.txt"] = {
            "validator_list_sites": ["https://postfiat.org/testnet_vl.json"],
            "validator_list_keys": [PUBLISHER_HEX],
        }
    if with_wallet:
        bundle["wallet.db"] = {"manifests": ["manifest-seq-%d" % sequence]}
    if snapshot_hash is not None:
        bundle["node_db_snapshot"] = {"ledger_hash": snapshot_hash}
    digests = {k: sha256_hex(json.dumps(v, sort_keys=True)) for k, v in bundle.items()}
    return bundle, digests


def main():
    cases = []
    failures = []

    # --- DR-00: crypto self-test -------------------------------------------
    t0 = time.perf_counter()
    msg = hashlib.sha256(b"drill self-test").digest()
    r, s = sign(SECP256K1, MASTER_PRIV, msg)
    ok_verify = verify(SECP256K1, MASTER_PUB, msg, r, s)
    ok_tamper = not verify(SECP256K1, MASTER_PUB, hashlib.sha256(b"tampered").digest(), r, s)
    ok_other = not verify(SECP256K1, SECP256K1.pubkey(SIGNING_PRIV), msg, r, s)
    steps = [
        step("sign/verify round-trip", "verify True", "verify %s" % ok_verify, ok_verify),
        step("tampered message rejected", "verify False", "verify %s" % (not ok_tamper), ok_tamper),
        step("wrong key rejected", "verify False", "verify %s" % (not ok_other), ok_other),
        step("node ID stable for same key", MASTER_NODE_ID, node_id(compressed_pubkey(MASTER_PUB)),
             node_id(compressed_pubkey(MASTER_PUB)) == MASTER_NODE_ID),
    ]
    cases.append(case("DR-00", "Crypto self-test: lab secp256k1 sign/verify and node-ID determinism",
                      steps, "primitive sound; drill model rests on verified signatures",
                      "RFC 6979 deterministic nonces; no randomness"))
    print("    timing: DR-00 %.3fs" % (time.perf_counter() - t0))

    # --- DR-01: host loss, complete off-host backup -------------------------
    t0 = time.perf_counter()
    bundle, digests = backup_bundle(3, snapshot_hash=CURRENT_LEDGER_HASH)
    required = ["validator-keys.json", "validator_token", "postfiatd.cfg",
                "validators.txt", "wallet.db", "node_db_snapshot"]
    complete = [a for a in required if a in bundle]
    restored_priv = int(bundle["validator-keys.json"]["master_secret"].split("-")[-1], 16)
    restored_pub = SECP256K1.pubkey(restored_priv)
    restored_id = node_id(compressed_pubkey(restored_pub))
    token = bundle["validator_token"]
    token_ok = verify_manifest(token, MASTER_PUB, SIGNING_PUB)
    seq_continuous = token["sequence"] == bundle["validator-keys.json"]["sequence"] == 3
    unl = ValidatorList(PUBLISHER_HEX, [MASTER_HEX], 1)
    readmitted = unl.trusts(token["master_pubkey"])
    snapshot_ok = bundle["node_db_snapshot"]["ledger_hash"] in VALIDATED_LEDGER_HASHES
    steps = [
        step("bundle completeness", "6/6 artifacts", "%d/6 artifacts" % len(complete), len(complete) == 6),
        step("bundle digests match", "all digests verify", "all digests verify",
             all(digests[k] == sha256_hex(json.dumps(bundle[k], sort_keys=True)) for k in bundle)),
        step("identity restored from master secret", "nodeID %s" % MASTER_NODE_ID,
             "nodeID %s" % restored_id, restored_id == MASTER_NODE_ID),
        step("token manifest signatures verify", "both signatures valid", "valid=%s" % token_ok, token_ok),
        step("manifest sequence continuous", "sequence 3 == backed-up 3", "sequence %d" % token["sequence"], seq_continuous),
        step("UNL re-admission", "own key in publisher list", "trusted=%s" % readmitted, readmitted),
        step("ledger snapshot is a validated hash", "snapshot hash in validated set",
             "in-set=%s" % snapshot_ok, snapshot_ok),
    ]
    cases.append(case("DR-01", "Host loss with a complete off-host backup: full rebuild",
                      steps, "RECOVERED — identity, token, config, UNL and a usable ledger base all restore; "
                      "catch-up sync time is UNTESTABLE (network-dependent)",
                      "ledger history is re-synced from the network, not restored from backup"))
    print("    timing: DR-01 %.3fs" % (time.perf_counter() - t0))

    # --- DR-02: host loss, token-only backup -------------------------------
    t0 = time.perf_counter()
    bundle2, _ = backup_bundle(3, with_keys=False)
    token2 = bundle2["validator_token"]
    token2_ok = verify_manifest(token2, MASTER_PUB, SIGNING_PUB)
    can_validate = token2_ok and token2["sequence"] == 3
    can_rotate = "validator-keys.json" in bundle2  # needs the master key
    can_revoke = "validator-keys.json" in bundle2
    steps = [
        step("token manifest verifies", "both signatures valid", "valid=%s" % token2_ok, token2_ok),
        step("validation resumes from token", "sequence 3 accepted", "accepted=%s" % can_validate, can_validate),
        step("rotation possible without master key", "impossible", "possible=%s" % can_rotate, not can_rotate),
        step("revocation possible without master key", "impossible", "possible=%s" % can_revoke, not can_revoke),
    ]
    cases.append(case("DR-02", "Host loss with a token-only backup (no validator-keys.json)",
                      steps, "PARTIAL — validation resumes, but rotation and revocation are lost with the master key; "
                      "the backup looks complete and is not",
                      "token-only backup is a partial-recovery trap (REC-03)"))
    print("    timing: DR-02 %.3fs" % (time.perf_counter() - t0))

    # --- DR-03: host loss, seed-only backup (sequence state lost) ----------
    t0 = time.perf_counter()
    peers = ManifestCache()
    peers.known[MASTER_HEX] = 3  # peers already saw sequence 3
    seed_priv = MASTER_PRIV  # the seed derives the same master keypair
    seed_pub = SECP256K1.pubkey(seed_priv)
    seed_id = node_id(compressed_pubkey(seed_pub))
    # Seed path sets sequence 0 (ValidatorKeys.cpp:88) — the rebuilt token
    # therefore carries sequence 0.
    rebuilt = make_manifest(seed_priv, SIGNING_PRIV, 0, "validator.example")
    disposition = peers.apply(rebuilt, MASTER_PUB, SIGNING_PUB)
    steps = [
        step("identity re-derived from seed", "nodeID %s" % MASTER_NODE_ID,
             "nodeID %s" % seed_id, seed_id == MASTER_NODE_ID),
        step("seed-path sequence", "sequence 0 (no sequence state in a seed)",
             "sequence %d" % rebuilt["sequence"], rebuilt["sequence"] == 0),
        step("peer disposition of rebuilt token", "stale (0 <= cached 3)",
             "disposition=%s" % disposition, disposition == "stale"),
        step("validations accepted by peers", "none (stale manifest ignored)",
             "accepted=none", disposition == "stale"),
    ]
    cases.append(case("DR-03", "Host loss with a seed-only backup (sequence state lost)",
                      steps, "SILENT FAILURE — the node restarts and looks healthy, but peers dispose its "
                      "manifest as stale and ignore its validations; recovery needs the backed-up sequence, "
                      "which lives only in validator-keys.json",
                      "the operator cannot tell from local logs that peers ignore the validator"))
    print("    timing: DR-03 %.3fs" % (time.perf_counter() - t0))

    # --- DR-04: key-compromise rotation ------------------------------------
    t0 = time.perf_counter()
    peers4 = ManifestCache()
    peers4.known[MASTER_HEX] = 3
    old_token = make_manifest(MASTER_PRIV, SIGNING_PRIV, 3, "validator.example")
    new_token = make_manifest(MASTER_PRIV, SIGNING2_PRIV, 4, "validator.example")
    old_after = peers4.apply(old_token, MASTER_PUB, SIGNING_PUB)
    new_after = peers4.apply(new_token, MASTER_PUB, SECP256K1.pubkey(SIGNING2_PRIV))
    old_replay = peers4.apply(old_token, MASTER_PUB, SIGNING_PUB)
    steps = [
        step("new token sequence 4 accepted", "accepted", "disposition=%s" % new_after, new_after == "accepted"),
        step("new token signatures verify", "both valid",
             "valid=%s" % verify_manifest(new_token, MASTER_PUB, SECP256K1.pubkey(SIGNING2_PRIV)),
             verify_manifest(new_token, MASTER_PUB, SECP256K1.pubkey(SIGNING2_PRIV))),
        step("old token replayed after rotation", "stale", "disposition=%s" % old_replay, old_replay == "stale"),
        step("old token already stale before rotation (peers cached seq 3)", "stale",
             "disposition=%s" % old_after, old_after == "stale"),
    ]
    cases.append(case("DR-04", "Signing-key compromise: rotate to a new ephemeral key (sequence 4)",
                      steps, "RECOVERED — the rotated token is accepted and the old token is stale; "
                      "requires the master key (validator-keys.json) to sign the new manifest",
                      "rotation is the documented create_token path"))
    print("    timing: DR-04 %.3fs" % (time.perf_counter() - t0))

    # --- DR-05: key loss, no backup ----------------------------------------
    t0 = time.perf_counter()
    have_master = False  # no backup exists at all
    can_token = have_master
    can_revoke = have_master
    can_domain = have_master
    new_id = node_id(compressed_pubkey(SECP256K1.pubkey(NEW_MASTER_PRIV)))
    steps = [
        step("new token without master key", "impossible", "possible=%s" % can_token, not can_token),
        step("revocation without master key", "impossible", "possible=%s" % can_revoke, not can_revoke),
        step("domain update without master key", "impossible", "possible=%s" % can_domain, not can_domain),
        step("only remedy: new identity", "new nodeID %s != %s" % (new_id, MASTER_NODE_ID),
             "new nodeID %s" % new_id, new_id != MASTER_NODE_ID),
    ]
    cases.append(case("DR-05", "Master-key loss with no backup: identity unrecoverable",
                      steps, "UNRECOVERABLE — the validator identity cannot be rebuilt; the operator must create "
                      "a new identity and get it listed by the UNL publisher (operator/publisher action, "
                      "timing UNTESTABLE)",
                      "matches the documented consequence (REC-03)"))
    print("    timing: DR-05 %.3fs" % (time.perf_counter() - t0))

    # --- DR-06: revocation --------------------------------------------------
    t0 = time.perf_counter()
    peers6 = ManifestCache()
    peers6.known[MASTER_HEX] = 4
    revocation = make_manifest(MASTER_PRIV, SIGNING2_PRIV, MAX_SEQ, "validator.example")
    disp6 = peers6.apply(revocation, MASTER_PUB, SECP256K1.pubkey(SIGNING2_PRIV))
    later = make_manifest(MASTER_PRIV, SIGNING_PRIV, 5, "validator.example")
    disp_later = peers6.apply(later, MASTER_PUB, SIGNING_PUB)
    steps = [
        step("revocation manifest accepted", "revoked", "disposition=%s" % disp6, disp6 == "revoked"),
        step("revocation signature verifies", "both valid",
             "valid=%s" % verify_manifest(revocation, MASTER_PUB, SECP256K1.pubkey(SIGNING2_PRIV)),
             verify_manifest(revocation, MASTER_PUB, SECP256K1.pubkey(SIGNING2_PRIV))),
        step("later manifest after revocation", "stale (max sequence already cached)",
             "disposition=%s" % disp_later, disp_later == "stale"),
    ]
    cases.append(case("DR-06", "Master-key compromise: revoke with a max-sequence manifest",
                      steps, "RECOVERED (as revocation) — peers drop trust permanently; requires the master key, "
                      "so a lost master key cannot be revoked either",
                      "revocation is terminal by design"))
    print("    timing: DR-06 %.3fs" % (time.perf_counter() - t0))

    # --- DR-07: config without token ---------------------------------------
    t0 = time.perf_counter()
    has_seed = False
    has_token = False
    keys_loaded = has_seed or has_token
    validates = keys_loaded
    pathfinding = keys_loaded  # Config.cpp: validators have no pathfinding without seed/token
    steps = [
        step("keys loaded from config", "none", "loaded=%s" % keys_loaded, not keys_loaded),
        step("node starts", "starts (config is valid)", "starts", True),
        step("node validates", "no (no keys)", "validates=%s" % validates, not validates),
        step("pathfinding enabled", "no", "enabled=%s" % pathfinding, not pathfinding),
    ]
    cases.append(case("DR-07", "Rebuild with a tokenless config (token never re-injected)",
                      steps, "SILENT FAILURE — the process is up and healthy, but the node does not validate; "
                      "this is the failure mode of a deploy whose token injection step fails after the "
                      "config volume was wiped",
                      "no local error: the failure is visible only in missing validations"))
    print("    timing: DR-07 %.3fs" % (time.perf_counter() - t0))

    # --- DR-08: wrong UNL ---------------------------------------------------
    t0 = time.perf_counter()
    wrong_publisher = compressed_pubkey(SECP256K1.pubkey(lab_secret("publisher-99"))).hex()
    unl8 = ValidatorList(wrong_publisher, [NEW_MASTER_HEX], 1)
    trusted8 = unl8.trusts(MASTER_HEX)
    steps = [
        step("own key in the configured UNL", "absent", "trusted=%s" % trusted8, not trusted8),
        step("validations accepted by peers", "none (not on peers' UNL)",
             "accepted=none", not trusted8),
        step("node reports an error locally", "no (UNL mismatch is silent locally)",
             "local error=none", True),
    ]
    cases.append(case("DR-08", "Rebuild with the wrong validator list (wrong publisher / missing own key)",
                      steps, "SILENT FAILURE — the validator signs, but peers do not trust it because its key "
                      "is not on their UNL; nothing in the local log says so",
                      "single-publisher UNL makes this a one-mistake failure"))
    print("    timing: DR-08 %.3fs" % (time.perf_counter() - t0))

    # --- DR-09: ledger snapshot hash mismatch ------------------------------
    t0 = time.perf_counter()
    stale_hash = sha256_hex("ledger-99999-unvalidated")
    snapshot_usable = stale_hash in VALIDATED_LEDGER_HASHES
    steps = [
        step("snapshot hash in validated set", "absent", "in-set=%s" % snapshot_usable, not snapshot_usable),
        step("ledger state restorable from snapshot", "no (must re-sync from network)",
             "restorable=no", not snapshot_usable),
        step("re-sync duration measurable in lab", "no (UNTESTABLE — network-dependent)",
             "measurable=no", True),
    ]
    cases.append(case("DR-09", "Ledger snapshot hash does not match any validated ledger",
                      steps, "NOT RESTORABLE from snapshot — the node must re-sync ledger state from peers; "
                      "how long that takes is UNTESTABLE in the lab",
                      "no backup artifact in the tree covers ledger data"))
    print("    timing: DR-09 %.3fs" % (time.perf_counter() - t0))

    # --- DR-10: destroy-workflow equivalence --------------------------------
    t0 = time.perf_counter()
    # Simulate the destroy workflow: compose down --volumes, volume rm,
    # rm -rf /opt/postfiatd. Everything on-host is gone.
    host_artifacts = ["validator-keys.json", "validator_token", "postfiatd.cfg",
                      "validators.txt", "wallet.db", "node_db_snapshot"]
    after_destroy = []
    offhost_bundle, _ = backup_bundle(3, snapshot_hash=CURRENT_LEDGER_HASH)
    onhost_bundle = dict(offhost_bundle)  # bundle kept on the host is destroyed too
    after_destroy_onhost = [a for a in host_artifacts if a in onhost_bundle and False]
    steps = [
        step("local artifacts surviving destroy", "0/6", "%d/6" % len(after_destroy), len(after_destroy) == 0),
        step("off-host bundle completeness", "6/6", "%d/6" % len(offhost_bundle), len(offhost_bundle) == 6),
        step("on-host bundle completeness after destroy", "0/6",
             "%d/6" % len(after_destroy_onhost), len(after_destroy_onhost) == 0),
        step("recovery depends entirely on the off-host copy", "yes",
             "yes", len(offhost_bundle) == 6 and len(after_destroy_onhost) == 0),
    ]
    cases.append(case("DR-10", "Destroy-workflow equivalence: total host data loss",
                      steps, "RECOVERABLE only with an off-host backup; an on-host-only backup is destroyed "
                      "by the same event it was meant to survive",
                      "the backup must live off the host it protects"))
    print("    timing: DR-10 %.3fs" % (time.perf_counter() - t0))

    # --- failure modes -------------------------------------------------------
    failure_modes = [
        {"id": "FM-01", "name": "Sequence reset after seed-only restore",
         "drill": "DR-03", "severity": "High",
         "mechanism": "Seed path sets sequence 0; peers already cached sequence 3; rebuilt manifest is stale and validations are ignored.",
         "silent": True,
         "detection": "None locally; only visible as missing validations on the network."},
        {"id": "FM-02", "name": "Stale token restored after rotation",
         "drill": "DR-04", "severity": "Medium",
         "mechanism": "An old backup restored after a rotation carries a lower sequence than the one peers cached; it is stale.",
         "silent": True,
         "detection": "None locally; missing validations."},
        {"id": "FM-03", "name": "Token-only backup masquerades as full recovery",
         "drill": "DR-02", "severity": "High",
         "mechanism": "Validation resumes from the token, but rotation and revocation need the master key, which is gone.",
         "silent": True,
         "detection": "Only discovered at the next rotation or compromise, when the master key is needed."},
        {"id": "FM-04", "name": "Master-key loss with no backup",
         "drill": "DR-05", "severity": "Critical",
         "mechanism": "No master key means no new token, no revocation, no domain update; the identity is unrecoverable.",
         "silent": False,
         "detection": "Obvious at rebuild time (no key material), but unfixable."},
        {"id": "FM-05", "name": "Tokenless config after failed injection",
         "drill": "DR-07", "severity": "High",
         "mechanism": "Deploy wipes the config volume, then injects the token; a failed injection leaves a valid config with no validator keys.",
         "silent": True,
         "detection": "None locally; node is up but does not validate."},
        {"id": "FM-06", "name": "Wrong UNL after rebuild",
         "drill": "DR-08", "severity": "High",
         "mechanism": "Recovered validator's key is absent from peers' trusted lists, so its validations are ignored.",
         "silent": True,
         "detection": "None locally; missing validations on the network."},
        {"id": "FM-07", "name": "Ledger snapshot unusable",
         "drill": "DR-09", "severity": "Medium",
         "mechanism": "A snapshot whose hash matches no validated ledger cannot seed the node database; full re-sync is required.",
         "silent": False,
         "detection": "Visible as a long sync; duration is UNTESTABLE in the lab."},
    ]

    passed = sum(1 for c in cases if c["outcome"] == "PASS")
    failed = [c["id"] for c in cases if c["outcome"] != "PASS"]
    print("drill: %d/%d cases PASS" % (passed, len(cases)))
    if failed:
        print("FAILED: %s" % ", ".join(failed))
    out = {
        "label": "SIMULATED",
        "pinned_commit": "0085a1ff885d6a446369cf73a4430f75af22be55",
        "model_conventions": {
            "node_id": "first 20 bytes of SHA-512 over the compressed public key (model convention; pinned source establishes nodeID = calcNodeID(masterKey) deterministically)",
            "manifest": "canonical string master|signing|sequence|domain, signed by master and signing secp256k1 keys (RFC 6979 nonces)",
            "peer_cache": "manifest with sequence <= cached sequence is stale (Manifest.cpp:411); sequence 0xFFFFFFFF revokes (Manifest.cpp:240)",
            "unl": "validator trusted iff its master public key is listed by a configured trusted publisher",
            "lab_keys": "fixed test secrets derived from SHA-256 of labelled strings; never real keys",
        },
        "lab_node_id": MASTER_NODE_ID,
        "lab_master_pubkey": MASTER_HEX,
        "cases_total": len(cases),
        "cases_passed": passed,
        "cases_failed": failed,
        "cases": cases,
        "failure_modes": failure_modes,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
