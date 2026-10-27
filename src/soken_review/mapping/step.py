"""The `map` step and artifact loading (03 3.1 steps `map`, `chain_state 1`; 04 2.1, 6.3, 12).

`run_map_step` builds `map.v1` from the pinned files (lexical layer always; semantic layer from
the build's solc output when the build succeeded), scans every pinned file for J1 to J5 (04 12:
detection at pin time, per file) and writes `map/`, `flags.json` and the static facts next to the
pin. `load_artifacts` reads them back for the tools and the pure validators.
"""

from __future__ import annotations

import json
import re
from functools import cache, lru_cache
from pathlib import Path
from typing import Any

import yaml

from ..engine.artifacts import Artifacts, word_set
from ..engine.injection import scan_file
from ..engine.numbers import NumberContext
from ..pinning.store import PinnedSource
from .build import build_map, load_map, load_tokens, write_map
from .facts import load_facts, static_facts, write_facts
from .lifecycle import apply_lifecycle
from .project_url import discover_project_urls, write_suggested_context

_ENUMS = Path(__file__).resolve().parents[3] / "contract" / "rubric" / "enums.yaml"


@cache
def family_categories(family: str, chain: str | None = None) -> tuple[str, ...]:
    """Category ids of a family (enums.yaml), chain-specific ids only for their chains."""
    data = yaml.safe_load(_ENUMS.read_text(encoding="utf-8"))
    out = []
    for c in data["categories"]:
        if c.get("family") != family:
            continue
        chains = c.get("chains")
        if chains and chain not in chains:
            continue
        out.append(c["id"])
    return tuple(out)


_LOCKFILE_PINS = frozenset({"lockfile", "lockfile_version"})
_NPM_NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")   # npm names, never a path


def dependency_trust(dependencies: dict[str, Any] | None, candidate: dict[str, Any] | None) -> dict[str, Any]:
    """Which unpinned files may credit a guard on a reviewed function (semantic_evm `_credit`).

    `trusted_prefixes`: `node_modules/<name>/` of every npm package whose tarball was verified
    against the lockfile sha512 in this run (adapters/evm/npm_deps.py summary: `integrity` set,
    pinned by the lockfile). A registry-range resolution is not integrity-pinned by the repo and
    stays untrusted. `untrusted_paths`: the files the scope rules removed from the candidate
    (test and mock contracts), never credited whatever their location."""
    prefixes: list[str] = []
    for pkg in ((dependencies or {}).get("packages") or []):
        if not isinstance(pkg, dict):
            continue
        name = str(pkg.get("name") or "")
        if _NPM_NAME_RE.fullmatch(name) and pkg.get("integrity") and str(pkg.get("pinned_by")) in _LOCKFILE_PINS:
            prefixes.append(f"node_modules/{name}/")
    untrusted = {str(row.get("path")) for row in ((candidate or {}).get("scope_excluded") or [])
                 if isinstance(row, dict) and row.get("path")}
    return {"trusted_prefixes": tuple(sorted(set(prefixes))), "untrusted_paths": frozenset(untrusted)}


def run_map_step(
    pin_root: Path,
    job_id: str,
    *,
    family: str = "evm",
    chain: str | None = None,
    solc_output_path: Path | None,
    build_ok: bool,
    std_input_path: Path | None = None,
    job: dict[str, Any] | None = None,
    chain_state: dict[str, Any] | None = None,
    candidate: dict[str, Any] | None = None,
    nsloc: int | None = None,
    analyzers: dict[str, str] | None = None,
    build_detail: str | None = None,
    build_status: str | None = None,
    dependencies: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build and store map, flags and static facts. Returns a summary for the step provenance.

    `std_input_path`: the Standard JSON input the compiler received (supervisor shape
    `{"std_json_input": {...}}` or the plain std-json of the host build copy). Its `content`
    strings are the bytes the AST offsets refer to (CRLF kept for an exact rebuild), so the
    semantic layer resolves lines against them, not against the LF pin.

    `dependencies`: the npm integrity record of the run (out_dir/dependencies.json), which with
    the candidate's `scope_excluded` decides which unpinned files may credit a guard."""
    pin = PinnedSource.load(pin_root, job_id)
    # in-scope entries only: pinned dependency files (role dependency, out of scope) are readable
    # but are not mapped, counted or reported as reviewed
    scope_paths = [p for p, e in pin.entries.items() if e.in_scope]
    files = {p: "\n".join(pin.read_all(p)) + ("\n" if pin.line_count(p) else "") for p in scope_paths}
    # Bug 7 fix (2026-10-25): for non-EVM families (TON, TRON, Solana) the build toolchain may
    # not report nsloc, or may return 0.  Fall back to counting lines from the pin so that
    # source.nsloc is never 0 for jobs with pinned files.
    if not nsloc and scope_paths:
        nsloc = sum(pin.line_count(p) for p in scope_paths) or None
    output = None
    compiled_texts: dict[str, str] | None = None
    if build_ok and solc_output_path is not None and solc_output_path.exists():
        output = json.loads(solc_output_path.read_text(encoding="utf-8"))
        compiled_texts = compiled_texts_from_std_input(std_input_path)
    trust = dependency_trust(dependencies, candidate)
    art = build_map(files, output, list(family_categories(family, chain)), build_ok=build_ok,
                    compiled_texts=compiled_texts, parsed_family="solana" if family == "solana" else None,
                    trusted_prefixes=trust["trusted_prefixes"], untrusted_paths=trust["untrusted_paths"])
    write_map(pin_root, job_id, art, build_detail=build_detail, build_status=build_status)

    # Lifecycle and invariant pass (feat/lifecycle-invariant-pass): lifecycle leads merged into
    # leads.json and the job's invariant walks in map/lifecycle.json. Additive: a fault here is
    # logged and never fails the map step.
    lifecycle: dict[str, Any] = {}
    try:
        lifecycle = apply_lifecycle(pin_root, job_id, family, files, art.doc, output, compiled_texts)
    except Exception:
        import logging as _logging
        _logging.getLogger(__name__).exception("lifecycle pass failed for job %s", job_id[-8:])

    # Server-side project URL discovery: scan source for NatSpec @custom:website,
    # @custom:security-contact, and GitHub repo URLs; write as suggested context items
    # so review_status can surface them to the model (feat/context-related-state).
    try:
        suggested = discover_project_urls(files)
        write_suggested_context(pin_root, job_id, suggested)
    except Exception:  # never fail the map step on a scan error
        import logging as _logging
        _logging.getLogger(__name__).debug("project URL discovery failed", exc_info=True)

    # The scan reads the lexer's own tokens (comment and string text intact) and the raw text; the
    # stored map tokens are redacted, so they must never feed detection.
    raw_tokens = {p: [t.to_json() for t in res.tokens] for p, res in art.lex.items()}
    ascii_idents = frozenset(t["text"] for toks in raw_tokens.values() for t in toks
                             if t["kind"] == "identifier" and t["text"].isascii())
    flags: list[dict[str, Any]] = []
    for path in sorted(files):
        flags.extend(scan_file(path, files[path], raw_tokens.get(path, []), ascii_idents))
    write_flags(pin_root, job_id, flags)

    job = job or {}
    facts = static_facts(
        chain_id=job.get("chain_id"),
        address=(chain_state or {}).get("address") or job.get("address"),
        chain_state=chain_state,
        candidate=candidate,
        nsloc=nsloc,
        pin_files=len(files),
        source_pin=pin.source_pin,
        analyzers=analyzers or {},
    )
    write_facts(pin_root, job_id, facts)
    return {
        "map_status": art.status,
        "files": len(files),
        "spans": len(art.doc["spans"]),
        "semantic": "semantic" in art.doc,
        **({"semantic_layer": art.doc["semantic"]["chain_extras"]["solana"]["layer"],
            "functions": len(art.doc["semantic"]["functions"]),
            "entries": sum(1 for f in art.doc["semantic"]["functions"] if f["is_entry"])}
           if family == "solana" and "semantic" in art.doc else {}),
        **({"build_status": build_status, "nsloc": nsloc} if build_status is not None else {}),
        "flags": {r: sum(1 for f in flags if f["rule"] == r) for r in ("J1", "J2", "J3", "J4", "J5")},
        "facts": len(facts),
        "lifecycle": lifecycle,
    }


def compiled_texts_from_std_input(path: Path | None) -> dict[str, str] | None:
    """Per-path `content` of a Standard JSON input file, or None when there is none to read.

    Accepts both on-disk shapes: the supervisor's `std_input_0.json`
    (`{"std_json_input": <std json>, "constructor_args_hex": ...}`) and the build adapter's
    host copy `input.json` (the std json itself). Only string `content` entries count; `urls`
    sources carry no text."""
    if path is None or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    std = data.get("std_json_input") if "std_json_input" in data else data
    sources = (std or {}).get("sources") if isinstance(std, dict) else None
    if not isinstance(sources, dict):
        return None
    out = {p: s["content"] for p, s in sources.items()
           if isinstance(s, dict) and isinstance(s.get("content"), str)}
    return out or None


def write_flags(root: Path, job_id: str, flags: list[dict[str, Any]]) -> None:
    d = root / job_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "flags.json").write_text(json.dumps(flags, indent=1), encoding="utf-8")


def load_flags(root: Path, job_id: str) -> list[dict[str, Any]] | None:
    p = root / job_id / "flags.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


@lru_cache(maxsize=32)
def _job_word_set(root: str, job_id: str, stamp: float) -> frozenset[str]:
    return word_set(load_artifacts(Path(root), job_id))


def job_number_context(root: Path, job_id: str) -> NumberContext:
    """NumberContext carrying the job's word set (04 5.1: identifier and type-name tokens of the
    pinned files plus map names) for the L7 rule, so an identifier with a digit (`ERC20Burnable`,
    `claim_v2`, a struct field `u5`) is not an unsourced number (matrix run 2026-10-26). Empty
    context when the map is not written yet; never raises."""
    try:
        stamp = (root / job_id / "map" / "tokens.json").stat().st_mtime
        return NumberContext(word_set=_job_word_set(str(root), job_id, stamp))
    except (OSError, ValueError, KeyError):
        return NumberContext()


def load_artifacts(root: Path, job_id: str, token_paths: list[str] | None = None) -> Artifacts:
    doc, status = load_map(root, job_id)
    return Artifacts(
        map=doc,
        map_status=status,
        tokens=load_tokens(root, job_id, token_paths),
        facts=load_facts(root, job_id),
        flags=load_flags(root, job_id) or [],
    )
