"""Sui source intake (plan v4 07 section 6.1.3).

Source: user repo and commit; else the Move Registry `GitInfo` (repository, path, tag) recorded for
the package version, fetched at the tag and resolved to a commit; else tier D. Disassembly is
never used for findings. Inline files (language `move_sui`) use the fixed template (07 4).
"""

from __future__ import annotations

import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

from soken_review.adapters.base import Candidate, Compiler
from soken_review.adapters.move import gitfetch, net
from soken_review.adapters.move.units import candidate_sha256, normalize_address, safe_store_path

_NAME_RE = re.compile(r"^@[a-z0-9-]{1,64}/[a-z0-9-]{1,64}$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_MODULE_ADDR_RE = re.compile(r"\bmodule\s+([A-Za-z_][A-Za-z0-9_]*)\s*::")
_FRAMEWORK_NAMED = {"std", "sui", "sui_system", "deepbook", "bridge"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def mvr_git_info(address: str, version: int) -> dict[str, Any] | None:
    """MVR reverse resolution of the package id, then GitInfo of that version (07 6.1.3)."""
    res = net.post_json(f"{net.MVR_API}/v1/reverse-resolution/bulk", {"package_ids": [address]})
    name = (((res or {}).get("resolution") or {}).get(address) or {}).get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        return None
    try:
        rec = net.get_json(f"{net.MVR_API}/v1/names/{quote(name)}/{int(version)}")
    except net.NotFound:
        return None
    info = rec.get("git_info") if isinstance(rec, dict) else None
    if not isinstance(info, dict) or normalize_address(str(rec.get("package_address", ""))) != address:
        return None
    url, path, tag = info.get("repository_url"), info.get("path") or ".", info.get("tag")
    if not (isinstance(url, str) and gitfetch.REPO_URL_RE.match(url.strip().rstrip("/"))
            and isinstance(tag, str) and gitfetch.REF_RE.match(tag)
            and (path == "." or safe_store_path(path) is not None)):
        return None
    return {"name": name, "repository_url": url.strip().rstrip("/"), "path": safe_store_path(path) or ".", "tag": tag}


def recorded_toolchain(files: dict[str, str], package_dir: str) -> dict[str, Any]:
    """Toolchain version and published ids per DESIGN.md "Resolving the toolchain version":
    Published.toml publication metadata first, then legacy Move.lock [move].toolchain-version."""
    def read(name: str) -> dict[str, Any] | None:
        path = name if package_dir in (".", "") else f"{package_dir}/{name}"
        try:
            return tomllib.loads(files[path]) if path in files else None
        except tomllib.TOMLDecodeError:
            return None

    out: dict[str, Any] = {"version": None, "source": None, "original_id": None, "edition": None}
    published = read("Published.toml")
    if published:
        env = ((published.get("published") or {}).get("mainnet")) or {}
        version = env.get("toolchain-version") or (env.get("build-config") or {}).get("toolchain-version")
        if isinstance(version, str) and _VERSION_RE.match(version.removeprefix("v")):
            out |= {"version": version.removeprefix("v"), "source": "Published.toml"}
        out["original_id"] = normalize_address(str(env.get("original-id", ""))) if env.get("original-id") else None
    lock = read("Move.lock")
    if lock:
        tv = (lock.get("move") or {}).get("toolchain-version") or {}
        version = tv.get("compiler-version")
        if out["version"] is None and isinstance(version, str) and _VERSION_RE.match(version):
            out |= {"version": version, "source": "Move.lock", "edition": tv.get("edition")}
        env = (lock.get("env") or {}).get("mainnet") or {}
        if out["original_id"] is None and env.get("original-published-id"):
            out["original_id"] = normalize_address(str(env["original-published-id"]))
    return out


def _candidate(files: dict[str, str], provider: str, settings: dict[str, Any], source_url: str | None) -> Candidate:
    tc = settings.get("toolchain") or {}
    return Candidate(
        provider=provider,  # type: ignore[arg-type]
        files=files, sha256=candidate_sha256(files), language="move_sui",
        compiler=Compiler(version=tc["version"], version_pinned_by=tc["source"]) if tc.get("version") else None,
        settings=settings, std_json_input=None, entry_contract=None, source_url=source_url, fetched_at=_now(),
    )


def candidate_from_git(cs: dict[str, Any] | None, repo_url: str, ref: str, package_dir: str, work: Path,
                       provider: str, chain_state_file: str | None, mvr_name: str | None = None) -> Candidate:
    files, commit = gitfetch.fetch_repo(repo_url, ref, work)
    manifest = "Move.toml" if package_dir in (".", "") else f"{package_dir}/Move.toml"
    if manifest not in files:
        raise gitfetch.FetchError("no Move.toml at the package path")
    name = (tomllib.loads(files[manifest]).get("package") or {}).get("name")
    settings = {"chain": "sui", "kind": provider, "address": (cs or {}).get("address"),
                "original_id": (cs or {}).get("original_id"), "checkpoint": (cs or {}).get("checkpoint"),
                "package_dir": package_dir or ".", "package_name": name, "repo_url": repo_url, "ref": ref,
                "commit": commit, "mvr_name": mvr_name, "toolchain": recorded_toolchain(files, package_dir),
                "chain_state_file": chain_state_file,
                "units": [{"name": name, "dir": package_dir or ".",
                           "modules": sorted((cs or {}).get("modules", {})) or None}]}
    return _candidate(files, provider, settings, repo_url)


def candidate_from_inline(files: dict[str, str]) -> Candidate:
    """Inline `move_sui` files (07 4): named addresses 0x0, manifest from the fixed template."""
    clean: dict[str, str] = {}
    for path, text in files.items():
        norm = safe_store_path(path)
        if norm is None or not norm.endswith(".move"):
            continue
        clean[norm if norm.startswith("sources/") else f"sources/{PurePosixPath(norm).name}"] = text
    named = sorted({m for t in clean.values() for m in _MODULE_ADDR_RE.findall(t)} - _FRAMEWORK_NAMED)
    settings = {"chain": "sui", "kind": "inline", "address": None, "package_dir": ".", "package_name": "inline",
                "named_addresses": {n: "0x0" for n in named}, "toolchain": {"version": None},
                "units": [{"name": "inline", "dir": ".", "modules": None}]}
    return _candidate(clean, "user", settings, None)
