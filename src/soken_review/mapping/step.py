"""The `map` step and artifact loading (03 3.1 steps `map`, `chain_state 1`; 04 2.1, 6.3, 12).

`run_map_step` builds `map.v1` from the pinned files (lexical layer always; semantic layer from
the build's solc output when the build succeeded), scans every pinned file for J1 to J5 (04 12:
detection at pin time, per file) and writes `map/`, `flags.json` and the static facts next to the
pin. `load_artifacts` reads them back for the tools and the pure validators.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from ..engine.artifacts import Artifacts
from ..engine.injection import scan_file
from ..pinning.store import PinnedSource
from .build import build_map, load_map, load_tokens, write_map
from .facts import load_facts, static_facts, write_facts

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
) -> dict[str, Any]:
    """Build and store map, flags and static facts. Returns a summary for the step provenance.

    `std_input_path`: the Standard JSON input the compiler received (supervisor shape
    `{"std_json_input": {...}}` or the plain std-json of the host build copy). Its `content`
    strings are the bytes the AST offsets refer to (CRLF kept for an exact rebuild), so the
    semantic layer resolves lines against them, not against the LF pin."""
    pin = PinnedSource.load(pin_root, job_id)
    files = {p: "\n".join(pin.read_all(p)) + ("\n" if pin.line_count(p) else "") for p in pin.entries}
    output = None
    compiled_texts: dict[str, str] | None = None
    if build_ok and solc_output_path is not None and solc_output_path.exists():
        output = json.loads(solc_output_path.read_text(encoding="utf-8"))
        compiled_texts = compiled_texts_from_std_input(std_input_path)
    art = build_map(files, output, list(family_categories(family, chain)), build_ok=build_ok,
                    compiled_texts=compiled_texts)
    write_map(pin_root, job_id, art, build_detail=build_detail)

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
        "flags": {r: sum(1 for f in flags if f["rule"] == r) for r in ("J1", "J2", "J3", "J4", "J5")},
        "facts": len(facts),
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


def load_artifacts(root: Path, job_id: str, token_paths: list[str] | None = None) -> Artifacts:
    doc, status = load_map(root, job_id)
    return Artifacts(
        map=doc,
        map_status=status,
        tokens=load_tokens(root, job_id, token_paths),
        facts=load_facts(root, job_id),
        flags=load_flags(root, job_id) or [],
    )
