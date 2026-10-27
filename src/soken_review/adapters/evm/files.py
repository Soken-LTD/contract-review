"""Candidate for `source.kind = files` Solidity input (03 4.1 inline files; 05 6.1 compiler choice).

The compiler is, in order: `compiler_version` given with the files when it satisfies every
`pragma solidity` (version_pinned_by = "user"); an exact pin in a pasted foundry.toml,
hardhat.config.* or truffle-config.js that satisfies every pragma (version_pinned_by = "config");
else the newest solc release that satisfies every pragma (version_pinned_by = "pragma"), never
the floor of a `^x.y.z` range. `review_start.source.remappings` and a pasted `remappings.txt`
become solc `settings.remappings` (sanitized again by the build step); a `foundry.toml` gives
optimizer, viaIR and evmVersion. Only `.sol` files become solc sources; npm-style paths
(`@scope/pkg/...`, `node_modules/@scope/pkg/...`) are ordinary source keys.
"""

from __future__ import annotations

import re
import tomllib
from typing import Any

from soken_review.adapters.base import Candidate, Compiler
from soken_review.adapters.evm.compiler import get_cache
from soken_review.adapters.evm.fetch import make_candidate

PRAGMA = re.compile(r"^\s*pragma\s+solidity\s+([^;]+);", re.MULTILINE)
TERM = re.compile(r"(\^|~|>=|<=|>|<|=)?\s*v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?")

Version = tuple[int, int, int]


def _term_ok(op: str, want: tuple[int, int | None, int | None], v: Version) -> bool:
    major, minor, patch = want
    base = (major, minor or 0, patch or 0)
    if op == "^":
        if major > 0:
            return v >= base and v[0] == major
        if (minor or 0) > 0:
            return v >= base and v[:2] == (0, minor)
        return v[:3] == base
    if op == "~":
        return v >= base and v[:2] == (major, minor or 0) if minor is not None else v[0] == major
    if op in ("", "="):
        if minor is None:
            return v[0] == major
        if patch is None:
            return v[:2] == (major, minor)
        return v == base
    return {">=": v >= base, "<=": v <= base, ">": v > base, "<": v < base}[op]


def satisfies(expr: str, v: Version) -> bool:
    """npm-style range used by solc pragmas: space = AND, `||` = OR."""
    for alt in expr.split("||"):
        terms = list(TERM.finditer(alt.strip()))
        if not terms:
            continue
        ok = True
        for t in terms:
            minor = None if t[3] in (None, "x", "*") else int(t[3])
            patch = None if t[4] in (None, "x", "*") else int(t[4])
            ok = ok and _term_ok(t[1] or "", (int(t[2]), minor, patch), v)
        if ok:
            return True
    return False


def pick_solc(sources: dict[str, str], builds: list[dict[str, Any]]) -> str | None:
    """Newest release (no prerelease) satisfying every pragma; long version string or None."""
    exprs = [m.group(1) for text in sources.values() for m in PRAGMA.finditer(text)]
    releases = []
    for b in builds:
        if b.get("prerelease"):
            continue
        try:
            v = tuple(int(x) for x in str(b["version"]).split("."))
        except (KeyError, ValueError):
            continue
        if len(v) == 3:
            releases.append((v, b.get("longVersion") or b["version"]))
    for v, long_version in sorted(releases, reverse=True):
        if all(satisfies(e, v) for e in exprs):  # type: ignore[arg-type]
            return long_version
    return None


def foundry_settings(text: str) -> tuple[dict[str, Any], str | None]:
    """solc settings from a foundry.toml `[profile.default]` (optimizer, runs, via_ir, evm_version)
    and its `solc_version`, if any. Unknown or malformed keys are ignored."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}, None
    prof = (data.get("profile") or {}).get("default") or {}
    settings: dict[str, Any] = {}
    if isinstance(prof.get("optimizer"), bool):
        runs = prof.get("optimizer_runs", 200)
        settings["optimizer"] = {"enabled": prof["optimizer"], "runs": runs if isinstance(runs, int) else 200}
    via_ir = prof.get("via_ir", prof.get("via-ir"))
    if isinstance(via_ir, bool):
        settings["viaIR"] = via_ir
    evm = prof.get("evm_version")
    if isinstance(evm, str) and re.fullmatch(r"[a-z]{3,20}", evm):
        settings["evmVersion"] = evm
    solc = prof.get("solc_version", prof.get("solc"))
    return settings, solc if isinstance(solc, str) and re.fullmatch(r"\d+\.\d+\.\d+", solc) else None


IMPORT = re.compile(r"^\s*import\s+(?:[^;\"']*?\bfrom\s+)?[\"']([^\"']+)[\"']", re.MULTILINE)
CONTRACT = re.compile(r"^\s*(?:abstract\s+)?contract\s+([A-Za-z_]\w*)", re.MULTILINE)


def entry_contract(sources: dict[str, str]) -> str | None:
    """`path:Name` for the analyzers' entry (Slither runs on one file and its imports): the
    largest file no other file imports, with its first non-abstract contract (else the first)."""
    imported = {spec.rsplit("/", 1)[-1] for text in sources.values() for spec in IMPORT.findall(text)}
    roots = [p for p in sources if p.rsplit("/", 1)[-1] not in imported] or list(sources)
    for path in sorted(roots, key=lambda p: (-sources[p].count("\n"), p)):
        names = CONTRACT.findall(sources[path])
        concrete = re.findall(r"^\s*contract\s+([A-Za-z_]\w*)", sources[path], re.MULTILINE)
        if names:
            return f"{path}:{(concrete or names)[0]}"
    return None


def files_candidate(files: list[dict[str, Any]], builds: list[dict[str, Any]] | None = None, *,
                    remappings: list[str] | None = None, compiler_version: str | None = None) -> Candidate | None:
    sources = {f["path"]: f["content"] for f in files if str(f.get("path", "")).endswith(".sol")}
    if not sources:
        return None

    def named(name: str) -> str:
        return next((f["content"] for f in files if str(f.get("path", "")).rsplit("/", 1)[-1] == name), "")

    remaps = [ln.strip() for ln in named("remappings.txt").splitlines() if ln.strip() and not ln.startswith("#")]
    for r in remappings or []:  # review_start.source.remappings (were ignored before 2026-10-27)
        if isinstance(r, str) and r.strip() and r.strip() not in remaps:
            remaps.append(r.strip())
    settings, pinned = foundry_settings(named("foundry.toml"))
    if remaps:
        settings["remappings"] = remaps
    if builds is None:
        builds = get_cache()._load_list().get("builds", [])
    exprs = [m.group(1) for t in sources.values() for m in PRAGMA.finditer(t)]

    def release(short: str) -> str | None:
        return next((b.get("longVersion") or b.get("version") for b in builds
                     if b.get("version") == short and not b.get("prerelease")), None)

    def fits(short: str) -> bool:
        parts = short.split("+", 1)[0].split(".")
        return len(parts) == 3 and all(p.isdigit() for p in parts) and \
            all(satisfies(e, (int(parts[0]), int(parts[1]), int(parts[2]))) for e in exprs)

    version: str | None = None
    pinned_by = "pragma"
    user = (compiler_version or "").strip().lstrip("v")
    if user and fits(user) and release(user.split("+", 1)[0]):
        version, pinned_by = release(user.split("+", 1)[0]), "user"
    if version is None:
        from soken_review.adapters.evm import solc_select as _sel

        config = [(pinned, "foundry.toml")] if pinned else []
        config += _sel.config_versions({str(f.get("path", "")).rsplit("/", 1)[-1]: f["content"] for f in files
                                        if str(f.get("path", "")).rsplit("/", 1)[-1] != "foundry.toml"})
        picked = _sel.pick_config_version(config, exprs)
        if picked and fits(picked[0]) and release(picked[0]):
            version, pinned_by = release(picked[0]), "config"
    if version is None:
        version, pinned_by = pick_solc(sources, builds), "pragma"
    return make_candidate(
        provider="user",
        raw_files=sources,
        language="solidity",
        compiler=Compiler(version=version, version_pinned_by=pinned_by) if version else None,
        settings=settings,
        std_json_input=None,
        entry_contract=entry_contract(sources),
        _caller_context="files",
    )
