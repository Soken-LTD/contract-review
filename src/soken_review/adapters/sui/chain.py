"""Sui `chain_state` (plan v4 07 sections 4 and 6.1): supervisor-only GraphQL reads.

JSON-RPC is disabled on Sui Foundation mainnet full nodes (07 3), so every read is GraphQL at one
pinned checkpoint: package version, module bytes, linkage, type origins, original id, and the
`UpgradeCap` created by the original publish transaction with its holder and policy (U-01).

Upgrade state (07 6.1.2): `immutable` only when the cap's last transaction effects show the cap
id deleted; a wrapped cap (consumed without deletion) or anything not determined is `unknown`.
"""

from __future__ import annotations

import base64
from typing import Any

from soken_review.adapters.move import net
from soken_review.adapters.move.units import normalize_address

UPGRADE_CAP_TYPE = "0x0000000000000000000000000000000000000000000000000000000000000002::package::UpgradeCap"
POLICY = {0: "compatible", 128: "additive", 192: "dep_only"}   # package.move constants
_MAX_MODULE_PAGES = 20

_PACKAGE_Q = """
query($a: SuiAddress!, $c: UInt53!, $after: String) {
  object(address: $a, atCheckpoint: $c) { asMovePackage {
    address version
    linkage { originalId upgradedId version }
    typeOrigins { module struct definingId }
    modules(first: 50, after: $after) { nodes { name bytes } pageInfo { hasNextPage endCursor } }
    packageAt(version: 1) {
      address
      previousTransaction { digest }
    }
  } }
}
"""

_CHANGES_Q = """
query($d: String!, $after: String) {
  transaction(digest: $d) { effects { objectChanges(first: 50, after: $after) {
    nodes { address idCreated idDeleted outputState { version asMoveObject { contents { type { repr } } } } }
    pageInfo { hasNextPage endCursor }
  } } }
}
"""

_CAP_Q = """
query($a: SuiAddress!, $c: UInt53!) {
  object(address: $a, atCheckpoint: $c) {
    version
    owner {
      __typename
      ... on AddressOwner { address { address } }
      ... on ObjectOwner { address { address } }
      ... on ConsensusAddressOwner { address { address } }
    }
    asMoveObject { contents { json } }
  }
}
"""

_CAP_LAST_TX_Q = """
query($a: SuiAddress!, $c: UInt53!) {
  transactions(last: 1, filter: { affectedObject: $a, beforeCheckpoint: $c }) {
    nodes { digest }
  }
}
"""


def latest_checkpoint() -> int:
    data = net.graphql("{ checkpoint { sequenceNumber } }")
    try:
        return int(data["checkpoint"]["sequenceNumber"])
    except (KeyError, TypeError, ValueError) as exc:
        raise net.ChainReadError("no checkpoint") from exc


def object_changes(digest: str) -> list[dict[str, Any]]:
    """Every object change of one transaction (paginated)."""
    out: list[dict[str, Any]] = []
    after: str | None = None
    for _ in range(_MAX_MODULE_PAGES * 5):
        tx = net.graphql(_CHANGES_Q, {"d": digest, "after": after}).get("transaction")
        if tx is None:
            raise net.ChainReadError(f"transaction {digest} not found")
        page = (tx.get("effects") or {}).get("objectChanges") or {}
        out += page.get("nodes") or []
        if not (page.get("pageInfo") or {}).get("hasNextPage"):
            return out
        after = page["pageInfo"]["endCursor"]
    raise net.ChainReadError("too many object changes")


def read_package(address: str, checkpoint: int) -> dict[str, Any] | None:
    """Package at the checkpoint, all module bytes (base64 decoded later), or None when absent."""
    modules: list[dict[str, str]] = []
    after: str | None = None
    head: dict[str, Any] | None = None
    for _ in range(_MAX_MODULE_PAGES):
        data = net.graphql(_PACKAGE_Q, {"a": address, "c": checkpoint, "after": after})
        # `package(address)` resolves an original id to the latest version; the object read keeps
        # the exact storage id the user named (07 6.1.1: record original_id and storage_id).
        pkg = (data.get("object") or {}).get("asMovePackage")
        if pkg is None:
            return None
        head = head or pkg
        page = pkg["modules"]
        modules += [{"name": n["name"], "bytes": n["bytes"]} for n in page["nodes"]]
        if not page["pageInfo"]["hasNextPage"]:
            break
        after = page["pageInfo"]["endCursor"]
    else:
        raise net.ChainReadError("package module listing too long")
    assert head is not None
    original = head.get("packageAt") or {}
    tx = original.get("previousTransaction") or {}
    created_caps = []
    if tx.get("digest"):
        for change in object_changes(tx["digest"]):
            out = change.get("outputState") or {}
            repr_ = ((((out.get("asMoveObject") or {}).get("contents") or {}).get("type")) or {}).get("repr")
            if change.get("idCreated") and repr_ == UPGRADE_CAP_TYPE:
                created_caps.append(change["address"])
    for m in modules:
        try:
            base64.b64decode(m["bytes"], validate=True)
        except ValueError as exc:
            raise net.ChainReadError(f"module {m['name']} bytes not base64") from exc
    return {
        "address": normalize_address(head["address"]),
        "version": int(head["version"]),
        "original_id": normalize_address(original.get("address") or head["address"]),
        "publish_tx": tx.get("digest"),
        "linkage": [
            {"original_id": normalize_address(x["originalId"]), "storage_id": normalize_address(x["upgradedId"]),
             "version": int(x["version"])}
            for x in head.get("linkage") or []
        ],
        "type_origins": head.get("typeOrigins") or [],
        "modules": {m["name"]: m["bytes"] for m in modules},
        "upgrade_cap_ids": created_caps,
    }


def read_upgrade(cap_ids: list[str], checkpoint: int) -> dict[str, Any]:
    """Upgrade state from the UpgradeCap (07 6.1.2, U-01).

    Returns {state: upgradable | immutable | unknown, cap_id, policy, policy_name, holder_kind,
    holder, reason}. holder_kind: address | object | shared | immutable | unknown."""
    if len(cap_ids) != 1:
        return {"state": "unknown", "cap_id": None, "holder_kind": "unknown",
                "reason": "no_cap_in_publish_effects" if not cap_ids else "several_caps"}
    cap = cap_ids[0]
    obj = net.graphql(_CAP_Q, {"a": cap, "c": checkpoint}).get("object")
    if obj is not None:
        owner = obj.get("owner") or {}
        kind = owner.get("__typename")
        holder = ((owner.get("address") or {}).get("address")) if isinstance(owner, dict) else None
        holder_kind = {"AddressOwner": "address", "ConsensusAddressOwner": "address", "ObjectOwner": "object",
                       "Shared": "shared", "Immutable": "immutable"}.get(kind, "unknown")
        fields = ((obj.get("asMoveObject") or {}).get("contents") or {}).get("json") or {}
        try:
            policy = int(fields.get("policy"))
        except (TypeError, ValueError):
            policy = None
        return {"state": "upgradable", "cap_id": cap, "policy": policy, "policy_name": POLICY.get(policy, "unknown"),
                "holder_kind": holder_kind, "holder": normalize_address(holder) if holder else None,
                "reason": "cap_live"}
    # Not live at the checkpoint: the last transaction touching it tells deleted from wrapped.
    nodes = (net.graphql(_CAP_LAST_TX_Q, {"a": cap, "c": checkpoint + 1}).get("transactions") or {}).get("nodes") or []
    if not nodes:
        return {"state": "unknown", "cap_id": cap, "holder_kind": "unknown", "reason": "cap_history_not_found"}
    tx = nodes[-1]
    change = next((c for c in object_changes(tx["digest"])
                   if normalize_address(c.get("address", "")) == normalize_address(cap)), None)
    if change is not None and change.get("idDeleted") is True:
        return {"state": "immutable", "cap_id": cap, "holder_kind": "none", "reason": "cap_deleted",
                "deleted_in": tx.get("digest")}
    if change is not None and change.get("outputState") is None:
        return {"state": "unknown", "cap_id": cap, "holder_kind": "unknown", "reason": "cap_wrapped",
                "wrapped_in": tx.get("digest")}
    return {"state": "unknown", "cap_id": cap, "holder_kind": "unknown", "reason": "cap_state_not_determined"}


def read_chain_state(address: str, checkpoint: int | None = None) -> dict[str, Any] | None:
    """chain_state for a Sui package id (07 4, 6.1). None when no package lives at the id."""
    addr = normalize_address(address)
    if addr is None:
        raise net.ChainReadError("bad package id")
    checkpoint = checkpoint if checkpoint is not None else latest_checkpoint()
    pkg = read_package(addr, checkpoint)
    if pkg is None:
        return None
    upgrade = read_upgrade(pkg["upgrade_cap_ids"], checkpoint)
    # Linked dependency bytecode at the same checkpoint (the linkage table is transitive): the facts
    # layer links these, never the rebuilt dependency modules (07 10).
    dep_modules: dict[str, dict[str, str]] = {}
    for link in pkg["linkage"]:
        dep = read_package(link["storage_id"], checkpoint)
        if dep is not None:
            dep_modules[link["storage_id"]] = dep["modules"]
    return {"chain": "sui", "address": addr, "checkpoint": checkpoint, **pkg, "upgrade": upgrade,
            "dep_modules": dep_modules}
