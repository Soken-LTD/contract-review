"""Mainnet classification for all supported chains (CEO rule 2026-10-24).

``is_mainnet(job)`` returns True only when the job's deployment target is a production
mainnet.  Unknown means private (fail closed): any uncertainty about the network returns
False so the report stays private until the owner requests publication via review_publish.

``publication_outcome(job, profile)`` mirrors the full set of conditions that
``_auto_enqueue_publish`` checks so the requester's model can tell the user upfront
whether the report will appear publicly.

The test ``tests/test_networks.py::test_every_rpc_backed_chain_classified`` enforces that
every RPC-backed chain ID in chains.json appears in ``_EVM_MAINNET_CHAIN_IDS``.
"""

from __future__ import annotations

import json
import os
from typing import Any

# ---------------------------------------------------------------------------
# EVM-family mainnet allowlist
# ---------------------------------------------------------------------------

# Explicit allowlist of production mainnet chain IDs for evm / hyperevm / tron.
# chains.json carries no mainnet/testnet flag, so we maintain an explicit set here.
# Whenever chains.json gains a new mainnet entry:
#   1. Add the chain_id to this set.
#   2. Run test_every_rpc_backed_chain_classified to verify the sync.
_EVM_MAINNET_CHAIN_IDS: frozenset[int] = frozenset({
    1,           # Ethereum Mainnet
    10,          # OP Mainnet
    56,          # BNB Smart Chain Mainnet
    137,         # Polygon Mainnet
    999,         # HyperEVM Mainnet
    4663,        # Robinhood Chain Mainnet
    5042,        # Arc Mainnet
    8453,        # Base Mainnet
    42161,       # Arbitrum One Mainnet
    728126428,   # TRON Mainnet
})

# Solana cluster names that are NOT mainnet-beta.
_SOLANA_NON_MAINNET: frozenset[str] = frozenset({"devnet", "testnet", "localnet"})

# Mirror of report.render.AUTO_PUBLISH_SOURCE_KINDS; kept here to avoid a circular import
# (render.py imports from this module, so this module must not import from render.py).
# If the set in render.py changes, update this constant too.
_AUTO_PUBLISH_SOURCE_KINDS: frozenset[str] = frozenset({"deployed", "repo"})


# ---------------------------------------------------------------------------
# Global kill switch
# ---------------------------------------------------------------------------


def auto_publish_enabled() -> bool:
    """Return True when automatic publication is active (default on).

    Disable by setting ``SOKEN_AUTOPUBLISH`` to any of: ``off``, ``0``, ``false``
    (case-insensitive).  Used during blind-test runs and when a live mainnet contract
    under review has an unfixed High finding that must not be published automatically.
    Disabling does not affect the owner-triggered path (review_publish still works).
    """
    val = os.environ.get("SOKEN_AUTOPUBLISH", "on").strip().lower()
    return val not in {"off", "0", "false"}


# ---------------------------------------------------------------------------
# is_mainnet
# ---------------------------------------------------------------------------


def is_mainnet(job: dict[str, Any]) -> bool:
    """Return True iff the job's deployment is on a production mainnet; else False.

    Called by ``_auto_enqueue_publish`` before enqueuing automatic publication.
    Defaults to False (fail closed) so an unknown or unclassified network keeps
    the report private.

    Chain-specific rules
    --------------------
    - evm / hyperevm / tron : ``chain_id`` must be in ``_EVM_MAINNET_CHAIN_IDS``.
    - solana                : ``source_args["cluster"]`` must not be a non-mainnet
                              cluster; a missing cluster means mainnet-beta (the
                              system default RPC).
    - ton                   : testnet addresses are rejected at review_start
                              (detect.py _VALID_TAGS); all accepted jobs are mainnet.
    - aptos                 : system connects to api.mainnet.aptoslabs.com only;
                              all accepted jobs are mainnet.
    - sui                   : system connects to graphql.mainnet.sui.io only;
                              all accepted jobs are mainnet.
    - starknet              : system connects to mainnet RPCs only; all accepted
                              jobs are mainnet.
    - unknown chain         : False (fail closed).
    """
    chain = job.get("chain")
    if not chain:
        return False

    if chain in ("evm", "hyperevm", "tron"):
        chain_id = job.get("chain_id")
        if chain_id is None:
            return False
        return int(chain_id) in _EVM_MAINNET_CHAIN_IDS

    if chain == "solana":
        source_args: Any = job.get("source_args") or {}
        if isinstance(source_args, str):
            try:
                source_args = json.loads(source_args)
            except (ValueError, TypeError):
                source_args = {}
        cluster = (source_args or {}).get("cluster")
        # A missing cluster means mainnet-beta (the system default RPC).
        # An explicit non-mainnet cluster name → not mainnet.
        return cluster not in _SOLANA_NON_MAINNET

    # ton/aptos/sui/starknet: all connect to mainnet-only endpoints; testnet inputs
    # are rejected upstream, so every accepted job is on mainnet.
    # Unknown chain → fail closed.
    return chain in ("ton", "aptos", "sui", "starknet")


# ---------------------------------------------------------------------------
# publication_outcome
# ---------------------------------------------------------------------------


# ── Is the reviewed code the deployed code? (CEO rule, security review 2026-10-27) ─────────────
# Reference data for the publication rule. A deployment publishes automatically only when one of
# these holds; anything else (TON SOURCE_UNLINKED, dep.match not_checkable or mismatch on a repo,
# no build record yet) keeps the PDF private.
#
# dep.match values (contract/rubric/dep_match.yaml) that mean the reviewed source IS the deployed
# code: an own rebuild equal (exact, metadata_only), or a third party that verified this source for
# this deployment (Etherscan/TronScan/eth-bytecode-db, an OtterSec entry signed by the upgrade
# authority, a TON verifier source hash-attested with a toolchain gap).
PUBLISH_DEP_MATCHES = frozenset({"exact", "metadata_only", "third_party_verified_only"})
# Fetch providers whose source was verified against the deployed address by an explorer or a
# registry. They count for a `deployed` start (the source came from the address itself) unless the
# own rebuild proved a mismatch.
PUBLISH_VERIFIED_PROVIDERS = frozenset({"sourcify", "etherscan", "tronscan", "eth_bytecode_db", "ton_verifier"})
# Provenance reasons that never publish, whatever else was recorded.
NO_PUBLISH_REASONS = frozenset({"SOURCE_UNLINKED", "SOURCE_NOT_OWNER_LINKED"})


def _last_done(steps: list[dict[str, Any]] | None, name: str) -> dict[str, Any]:
    rows = [s for s in steps or [] if s.get("step") == name and s.get("status") == "done"]
    prov = rows[-1].get("provenance") if rows else None
    if isinstance(prov, str):
        try:
            prov = json.loads(prov)
        except (ValueError, TypeError):
            prov = None
    return prov if isinstance(prov, dict) else {}


def deployed_code_reviewed(job: dict[str, Any], steps: list[dict[str, Any]] | None) -> tuple[bool, str]:
    """(True, "") when the reviewed source is the code at the job's deployment, else (False, why).

    Read from the done build step (dep_match / reason, every family records them) and the done
    fetch step (provider). Tier A is a recorded match by definition."""
    build = _last_done(steps, "build")
    match = build.get("dep_match")
    reason = build.get("reason") or build.get("dep_reason")
    if isinstance(reason, str) and reason.upper() in NO_PUBLISH_REASONS:
        return False, "the reviewed source is not matched to the deployed code"
    if job.get("tier") == "A" or match in PUBLISH_DEP_MATCHES:
        return True, ""
    provider = _last_done(steps, "fetch").get("provider")
    if job.get("source_kind") == "deployed" and provider in PUBLISH_VERIFIED_PROVIDERS and match != "mismatch" \
            and job.get("tier") in ("A", "B"):
        return True, ""
    if not build:
        return False, "publishes automatically only once the reviewed source is matched to the deployed code"
    return False, "the reviewed source is not matched to the deployed code"


def publication_outcome(
    job: dict[str, Any],
    profile: str | None = None,
    steps: list[dict[str, Any]] | None = None,
) -> dict[str, str]:
    """Return ``{"outcome": "automatic"|"private", "reason": str}`` for the job.

    Mirrors the conditions in ``_auto_enqueue_publish`` so the requester's model
    can tell the user whether the report will appear publicly before it even renders.

    Parameters
    ----------
    job:
        A row dict from the jobs table (or a compatible dict with the same keys).
        Required keys: ``source_kind``, ``has_deployment``, ``chain``, ``chain_id``,
        ``source_args``, ``context_items``.
    profile:
        The report profile (``"owner"`` suppresses auto-publication).
    steps:
        The job's job_steps rows (build and fetch provenance decide whether the reviewed code is
        the deployed code, ``deployed_code_reviewed``).
    """
    # Global kill switch (blind-test matrix, live contracts with unfixed findings, etc.)
    if not auto_publish_enabled():
        return {"outcome": "private", "reason": "automatic publication paused"}

    source_kind = job.get("source_kind")
    if source_kind not in _AUTO_PUBLISH_SOURCE_KINDS:
        return {
            "outcome": "private",
            "reason": f"source kind {source_kind!r} is not a public deployment",
        }

    if not job.get("has_deployment"):
        return {"outcome": "private", "reason": "no on-chain deployment recorded"}

    if not is_mainnet(job):
        return {"outcome": "private", "reason": "not deployed on a mainnet"}

    # CEO rule: automatic publication only when the reviewed code is the code deployed on a mainnet
    # (PUBLISH_DEP_MATCHES / PUBLISH_VERIFIED_PROVIDERS below, decided from the build and fetch steps).
    matched, why = deployed_code_reviewed(job, steps)
    if not matched:
        return {"outcome": "private", "reason": why}

    # Inline context items: url==None means the requester pasted private content that
    # may be quoted verbatim in the report's context section.
    context_items: Any = job.get("context_items") or []
    if isinstance(context_items, str):
        try:
            context_items = json.loads(context_items)
        except (ValueError, TypeError):
            context_items = []
    if any(item.get("url") is None for item in (context_items or [])):
        return {
            "outcome": "private",
            "reason": "report includes privately supplied project documents",
        }

    # Owner-profile reports contain owner-only context; owner uses review_publish.
    if (profile or "") == "owner":
        return {
            "outcome": "private",
            "reason": "owner-profile report; use review_publish to make public",
        }

    return {"outcome": "automatic", "reason": "deployed on a mainnet with public source"}
