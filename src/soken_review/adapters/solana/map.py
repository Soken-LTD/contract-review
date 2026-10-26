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
