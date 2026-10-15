"""Aptos build step and deployment comparison (plan v4 07 sections 4 and 7.2).

Per unit package: `aptos move compile --package-dir <dir> --output-dir <out>` in the sandbox (no
network; framework from the image, registry deps staged from chain_state). Flags (07 7.2): bytecode
version from the on-chain module header, language and compiler versions from on-chain
`compilation_metadata` (U-22). The pinned CLI cannot emit every old format (its framework needs
newer bytecode); when the recorded flags do not build, the default flags build for analysis and the
comparison can then only be `exact` on equal bytes, else `not_checkable` (07 7.2, 9.1).

The source tree is the pinned candidate (spec blocks blanked, `aptos/specs.py`) plus template
manifests; mounted read-only. Rebuilt modules are copied to `host/` (never mounted); the
supervisor compares them with chain_state and writes `host/provenance.json`.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from soken_review.adapters.aptos.manifest import ManifestError, inline_manifest, registry_manifests, repo_manifest
from soken_review.adapters.aptos.specs import strip_specs
from soken_review.adapters.base import BuildResult, Candidate
from soken_review.adapters.move import sandbox, trust
from soken_review.adapters.move.bytecode import BytecodeError, aptos_compilation_metadata, header, parse_module
from soken_review.adapters.move.provenance import aptos_dep_match
from soken_review.adapters.move.units import count_nsloc, declared_modules, is_in_scope, write_tree

logger = logging.getLogger(__name__)
_SBX = Path(__file__).resolve().parents[4] / ".sbx"
_SKIP_GIT = "--skip-fetch-latest-" + "git-deps"


def in_scope_for(c: Candidate):
    """Scope = sources the compiler builds for the unit packages (units.is_in_scope)."""
    dirs = tuple(u.get("dir") or "." for u in (c.settings or {}).get("units", [])) or (".",)
    return lambda path: is_in_scope(path, dirs) and not path.startswith("deps/")


def _downgrade(result: dict[str, Any], reason: str, detail: Any) -> dict[str, Any]:
    """An exact (or any) comparison becomes not_checkable when the reviewed text is not what was
    compiled (spec strip refused) or a rebuilt module has no in-scope source (no tier A)."""
    if result.get("dep_match") == "exact" or result.get("dep_match") not in ("mismatch", None):
        result = result | {"dep_match": "not_checkable", "reason": reason}
    return result | {reason: detail}


def load_chain_state(c: Candidate) -> dict[str, Any] | None:
    f = (c.settings or {}).get("chain_state_file")
    return json.loads(Path(f).read_text()) if f else None


def _recorded_flags(onchain: dict[str, bytes]) -> dict[str, str] | None:
    """--bytecode-version from module headers; language/compiler from compilation_metadata."""
    versions, metas = set(), set()
    for code in onchain.values():
        try:
            versions.add(header(code)[1])
            meta = aptos_compilation_metadata(parse_module(code, "aptos"))
        except BytecodeError:
            return None
        if meta:
            metas.add((meta["compiler_version"], meta["language_version"]))
    if len(versions) != 1:
        return None
    flags = {"bytecode_version": str(versions.pop())}
    if len(metas) == 1:
        compiler, language = metas.pop()
        flags |= {"compiler_version": compiler, "language_version": language}
    return flags


def _argv(unit_dir: str, out: str, flags: dict[str, str] | None, lint: bool = False) -> list[str]:
    cmd = ["aptos", "move", "lint" if lint else "compile", "--package-dir", f"/work/src/{unit_dir}".rstrip("/."),
           "--output-dir", f"/work/out/{out}", _SKIP_GIT]
    for key in ("bytecode_version", "language_version", "compiler_version"):
        if flags and flags.get(key) and not (lint and key != "language_version"):
            cmd += [f"--{key.replace('_', '-')}", flags[key]]
    return cmd


def build(c: Candidate, work_dir: Path | None = None) -> BuildResult:
    _SBX.mkdir(exist_ok=True)
    work = work_dir or Path(tempfile.mkdtemp(dir=_SBX))
    try:
        dirs = sandbox.prepare_dirs(work)
    except PermissionError as exc:
        return BuildResult(candidate=c, status="failed", reason="sandbox_unavailable", stderr_head=str(exc))
    host = dirs["host"]
    reasons = trust.scan(c.files)
    if reasons:
        c.untrusted_inputs = True
        sandbox.write_host(host / "untrusted_inputs.txt", "\n".join(reasons))
    settings = c.settings or {}
    cs = load_chain_state(c)
    units = settings.get("units") or []
    onchain_all = {n: bytes.fromhex(h.removeprefix("0x")) for n, h in (cs or {}).get("module_bytecode", {}).items()}

    # Build tree: pinned files (prebuilt bytecode never copied), specs blanked, template manifests.
    tree: dict[str, str] = {}
    spec_report: dict[str, Any] = {"stripped": {}, "refused": []}
    for p, t in c.files.items():
        if p.endswith((".mv", ".mvsm")) or "bytecode_modules" in p:
            continue
        if p.endswith(".move"):
            t2, rep = strip_specs(t, p)
            if rep.stripped:
                spec_report["stripped"][p] = rep.stripped
            spec_report["refused"] += rep.refused
            tree[p] = t2
        else:
            tree[p] = t
    try:
        if settings.get("kind") == "registry":
            if cs is None:
                raise ManifestError("registry candidate without chain_state")
            if cs.get("deps_unreachable"):
                return _failed(c, host, "deps_unreachable", ", ".join(cs["deps_unreachable"]), onchain_all, units)
            tree |= registry_manifests(cs, {u["name"] for u in units}, account_addr=cs.get("address"))
        elif settings.get("kind") == "repo":
            u = units[0]
            mpath = "Move.toml" if u["dir"] in (".", "") else f"{u['dir']}/Move.toml"
            tree[mpath] = repo_manifest(c.files[mpath], u["dir"], set(c.files), settings.get("address"))
        else:
            tree["Move.toml"] = inline_manifest(settings.get("named_addresses") or {})
    except ManifestError as exc:
        reason = "deps_unreachable" if "deps_unreachable" in str(exc) or "dependency" in str(exc) else "build_failed"
        return _failed(c, host, reason, str(exc), onchain_all, units)
    if write_tree(tree, dirs["src"]):
        return _failed(c, host, "build_failed", "unsafe path in candidate", onchain_all, units)

    try:
        sandbox.image_for("aptos")
    except sandbox.SandboxUnavailable as exc:
        return BuildResult(candidate=c, status="failed", reason="sandbox_unavailable", stderr_head=str(exc))

    results: dict[str, Any] = {}
    all_ok = True
    stderr_head = None
    for u in units:
        onchain = {m: onchain_all[m] for m in (u.get("modules") or []) if m in onchain_all}
        recorded = _recorded_flags(onchain) if onchain else None
        attempts = [("recorded", recorded)] if recorded else []
        attempts.append(("default", None))
        built: dict[str, bytes] | None = None
        method: dict[str, Any] = {"recorded_flags": recorded, "attempts": []}
        for label, flags in attempts:
            out = f"{u['name']}-{label}"
            run = sandbox.run("aptos", "build", dirs, _argv(u["dir"], out, flags), timeout=sandbox.BUILD_WALL_S)
            method["attempts"].append({"flags": label, "returncode": run.returncode, "timed_out": run.timed_out})
            sandbox.write_host(host / f"build-{out}.log", run.stdout + "\n" + run.stderr)
            if run.returncode == 0:
                arts = sandbox.read_artifacts(dirs["out"] / out / "build")
                prefix = f"{u['name']}/bytecode_modules/"
                built = {k[len(prefix):-3]: v for k, v in arts.items()
                         if k.startswith(prefix) and "/" not in k[len(prefix):]}
                for name, data in built.items():
                    sandbox.write_host(host / "artifacts" / u["name"] / f"{name}.mv", data)
                method["used"] = label
                break
            stderr_head = "\n".join((run.stderr or run.stdout).strip().splitlines()[-20:])
        if built is None:
            all_ok = False
        results[u["name"]] = aptos_dep_match(
            onchain, built, untrusted=c.untrusted_inputs, build_reason="build_failed", method=method,
        ) if u.get("modules") is not None else {"chain": "aptos", "dep_match": None, "reason": "no_deployment",
                                                "method": method}
        if settings.get("package_not_found"):
            results[u["name"]] |= {"dep_match": "not_checkable", "reason": "package_not_found"}
        if spec_report["refused"]:
            results[u["name"]] = _downgrade(results[u["name"]], "spec_strip_refused", spec_report["refused"])
        if built is not None:
            declared = set()
            for p, t in c.files.items():
                if is_in_scope(p, (u.get("dir") or ".",)):
                    declared |= declared_modules(t)
            unmapped = sorted(set(built) - declared)
            if unmapped:
                results[u["name"]] = _downgrade(results[u["name"]], "source_module_unmapped", unmapped)
    sandbox.write_host(host / "provenance.json", json.dumps({"units": results, "untrusted": c.untrusted_inputs,
                                                             "untrusted_reasons": reasons,
                                                             "spec_strip": spec_report}, indent=2))
    in_scope = in_scope_for(c)
    nsloc = sum(count_nsloc(t) for p, t in c.files.items() if in_scope(p))
    if not all_ok:
        return BuildResult(candidate=c, status="failed", reason="build_failed", stderr_head=stderr_head,
                           nsloc=nsloc, work_dir=str(work))
    return BuildResult(candidate=c, status="ok", nsloc=nsloc, work_dir=str(work))


def _failed(c: Candidate, host: Path, reason: str, detail: str, onchain: dict[str, bytes],
            units: list[dict[str, Any]]) -> BuildResult:
    prov = {u["name"]: aptos_dep_match({m: onchain[m] for m in (u.get("modules") or []) if m in onchain}, None,
                                       untrusted=c.untrusted_inputs, build_reason=reason) for u in units}
    sandbox.write_host(host / "provenance.json", json.dumps({"units": prov, "untrusted": c.untrusted_inputs}, indent=2))
    return BuildResult(candidate=c, status="failed", reason=reason, stderr_head=detail[:2000], work_dir=str(host.parent))
