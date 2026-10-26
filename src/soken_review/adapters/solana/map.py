"""Solana map step: chain_extras.solana and deployment rows (06 sections 3.6, 3.7).

map(build_result, static_map, chain_state) -> (chain_extras, deployment_rows)

Extras (06 §3.6):
  - program_id (display_address)
  - framework (anchor / pinocchio / native)
  - overflow_checks (on / off / unknown)
  - upgrade_authority (from chain state)
  - program_hash (F5 hash)
  - provenance (tier A/B/C/D + reason)

Deployment rows (06 §3.7):
  - One row per candidate with: unit_label, program_id, tier, repo_url, commit, nsloc
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from soken_review.adapters.base import BuildResult


def map_result(
    result: BuildResult,
    static_map: dict[str, Any],
    chain_state: dict[str, Any],
) -> tuple[dict[str, Any], Any]:
    """Build chain_extras and deployment_rows for a Solana BuildResult.

    Returns (chain_extras, deployment_rows) where deployment_rows is a list of dicts.
    """
    candidate = result.candidate
    target = getattr(candidate, "_target", None)  # set by adapter if available

    # Basic extras from candidate settings
    framework = (candidate.settings or {}).get("framework", "native")

    # Read supervisor metadata from work_dir/host/ (written by build.py)
    overflow_checks = "unknown"
    program_hash: str | None = None
    so_name: str | None = None

    if result.work_dir:
        host_dir = Path(result.work_dir) / "host"
        try:
            overflow_checks = (host_dir / "overflow_checks.txt").read_text().strip()
        except OSError:
            pass
        try:
            program_hash = (host_dir / "program_hash.txt").read_text().strip()
        except OSError:
            pass
        try:
            so_name = (host_dir / "so_name.txt").read_text().strip()
        except OSError:
            pass

    def _chain(key: str) -> Any:
        val = (chain_state or {}).get(key)
        return val.value if hasattr(val, "value") else val

    # Upgrade authority and deployed program hash: supervisor chain reads (onchain.py), never a
    # registry value or a container file.
    upgrade_authority: str | None = _chain("upgrade_authority") or None
    deployed_hash: str | None = _chain("deployed_program_hash") or None

    # Program ID (display_address from target, or from static_map)
    program_id: str | None = None
    if target and hasattr(target, "display_address"):
        program_id = target.display_address
    else:
        program_id = static_map.get("program_id")

    # Version line of the build image (host/build_meta.json, supervisor-written) and its U-S1 row.
    from soken_review.adapters.solana import images as solana_images
    from soken_review.adapters.solana.build import sandbox_layout
    layout = sandbox_layout(Path(result.work_dir)) if result.work_dir else None
    version = (layout or {}).get("version")
    settings = candidate.settings or {}
    commit = getattr(target, "commit", None) or settings.get("commit")

    # Provenance (06 2.4): the decision point every trust flag must reach.
    provenance: dict[str, Any] = {}
    if static_map.get("verify_items") is not None or program_hash:
        from soken_review.adapters.solana.fetch import resolve_provenance
        provenance = resolve_provenance(
            program_id=program_id or "",
            program_hash=program_hash,
            verify_items=static_map.get("verify_items") or [],
            upgrade_authority=upgrade_authority,
            untrusted_inputs=result.candidate.untrusted_inputs,
            deployed_hash=deployed_hash,
            # a nearest-image build (no image of the program's own version) is never tier A
            version_line_passed=solana_images.line_passed(version)
            and (layout or {}).get("image_match", "exact") == "exact",
            build_declared=bool(settings.get("verify_args")),
            commit=commit,
        )
        provenance["version"] = version
        provenance["image"] = (layout or {}).get("image")

    chain_extras: dict[str, Any] = {
        "program_id": program_id,
        "framework": framework,
        "overflow_checks": overflow_checks,
        "upgrade_authority": upgrade_authority,
        "program_hash": program_hash,
        "so_name": so_name,
        "provenance": provenance,
        "nsloc": result.nsloc,
    }

    # Deployment rows (06 §3.7)
    unit_label = target.unit_label if target and hasattr(target, "unit_label") else None
    repo_url = candidate.source_url
    deployment_rows = [
        {
            "unit_label": unit_label,
            "program_id": program_id,
            "tier": provenance.get("tier", "D"),
            "reason": provenance.get("reason", "no_provenance"),
            "repo_url": repo_url,
            "commit": commit,
            "framework": framework,
            "overflow_checks": overflow_checks,
            "nsloc": result.nsloc,
            "program_hash": program_hash,
        }
    ]

    return chain_extras, deployment_rows


# dep.match (contract/rubric/dep_match.yaml) and the tier for a program the supervisor could not
# resolve through resolve_provenance: no deployment, or a build that produced no artifact.
_NO_DEPLOYMENT = {"tier": "B", "match": None, "reason": "NO_DEPLOYMENT_GIVEN"}
_BUILD_FAILED = {"tier": "B", "match": "not_checkable", "reason": "SOURCE_NOT_REBUILT", "why": "build_failed"}


def deployment_doc(
    provenance: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None,
    chain_state: dict[str, Any] | None,
    address: str | None,
    layout: dict[str, Any] | None,
    build_status: str,
) -> dict[str, Any]:
    """The `deployment.json` document the report assembly reads for a Solana program (06 2.4).

    `provenance` is the `resolve_provenance` result (map_result's `chain_extras.provenance`), or
    None when the build produced no hash. The shape is the EVM supervisor's (engine/provenance.py
    `resolve_provenance`: tier, dep, candidate, block) plus `code_hash` (the F5 hash of the
    deployed program the supervisor read, "sha256:" prefixed), `unit` "slot" and `chain`.

    Honest tiers (matrix run 2026-10-26, agent-loans): a repo job with a deployment that was built
    with the nearest published image, or from untrusted inputs, is tier B `not_checkable` with the
    reason named; tier A needs the exact image of the program's version on a passed U-S1 line and
    equal hashes; tier C needs a declared build (verify args) that differs. Before this the Solana
    pipeline set no tier at all, so finalize check F1 stayed open for every Solana job.
    """
    cs = chain_state or {}
    if not address:
        decision: dict[str, Any] = dict(_NO_DEPLOYMENT)
    elif build_status != "ok" or not provenance or not provenance.get("tier"):
        decision = dict(_BUILD_FAILED)
    else:
        decision = dict(provenance)
    tier = decision.get("tier") or "B"
    match = decision.get("match")
    reason = str(decision.get("reason") or "")
    deployed_hash = decision.get("deployed_hash") or cs.get("deployed_program_hash")
    notes: list[str] = []
    if decision.get("why"):
        notes.append(str(decision["why"]))
    image_match = (layout or {}).get("image_match")
    if image_match == "nearest":
        notes.append(f"built with the nearest published image {(layout or {}).get('image_version')} "
                     f"for solana {(layout or {}).get('version')}; the hash is not compared")
    dep: dict[str, Any] | None = None
    if address and match is not None:
        dep = {
            "match": match,
            "reason": reason.lower() or None,
            "contract": (layout or {}).get("library_name") or ((candidate or {}).get("settings") or {}).get("library_name"),
            "comparison": {
                "outcome": match,
                "local_hash": decision.get("hash"),
                "onchain_hash": deployed_hash,
                "hash_equal": bool(decision.get("hash_equal")),
                "version": (layout or {}).get("version"),
                "image_match": image_match,
                "image_version": (layout or {}).get("image_version"),
                "version_line_passed": bool(decision.get("version_line_passed")),
            },
            "notes": notes,
        }
    comp = (candidate or {}).get("compiler")
    comp = comp if isinstance(comp, dict) else {}
    return {
        "tier": tier,
        "label_reason": None,
        "checks": [],
        "dep": dep,
        "candidate": {
            "provider": candidate.get("provider"),
            "sha256": candidate.get("sha256"),
            "compiler": comp.get("version"),
            "version_pinned_by": comp.get("version_pinned_by"),
            "untrusted_inputs": bool(candidate.get("untrusted_inputs", False)),
        } if candidate else None,
        "block": cs.get("slot"),
        "unit": "slot",
        "chain": "solana",
        "address": address,
        "code_hash": f"sha256:{deployed_hash}" if deployed_hash else None,
    }
