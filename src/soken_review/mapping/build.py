"""Build, validate and store `map.v1` for a pinned job (04 sections 2.1, 2.2, 1.3; 03 section 3.1 `map`).

`build_map(files, solc_output, categories)` is pure: pinned texts in, map document and per-file
tokens out. The lexical layer is always present; the semantic layer only when the build produced
an AST. `map_status`: `full` (semantic layer, every file parsed by a grammar or without error),
`partial` (semantic layer with fallback or error files, or no AST), `failed` (build failed:
lexical layer only, 03 3.1).

`write_map` / `load_map` keep the artifacts next to the pin: `<root>/<job_id>/map/map.json` and
`<root>/<job_id>/map/tokens/<sha256(path)[:16]>.jsonl` (index in `map/tokens.json`), so a path
from the source tree never becomes a file name.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema

from .lexers import LexResult, fold_constant, lex_file
from .semantic_evm import build_semantic

_SCHEMA = Path(__file__).resolve().parents[3] / "contract" / "rubric" / "schemas" / "map.v1.json"
logger = logging.getLogger(__name__)


# 04 2.1: names are validated against the identifier grammar, so free text from code never enters
# the map. Anything else (non-ASCII, over-long, ERROR-node text) is replaced by a stable id.
_NAME_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,63}$")
_TEXT_KINDS = frozenset({"comment", "literal_str"})


def safe_name(name: str) -> str:
    if _NAME_RE.match(name):
        return name
    return "id_" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]


def _stored_token(t: Any) -> dict[str, Any]:
    """Token as stored: comment and string text is never kept (J flags were taken at pin time)."""
    d = t.to_json()
    if d["kind"] in _TEXT_KINDS:
        d["text"] = ""
    elif d["kind"] == "identifier":
        d["text"] = safe_name(d["text"])
    return d


@dataclass
class MapArtifacts:
    doc: dict[str, Any]
    tokens: dict[str, list[dict[str, Any]]]
    status: str                                   # full | partial | failed
    lex: dict[str, LexResult] = field(default_factory=dict, repr=False)


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(json.loads(_SCHEMA.read_text(encoding="utf-8")))


def validate_map(doc: dict[str, Any]) -> None:
    """V0 on adapter output (04 1.1): raise jsonschema.ValidationError on a bad map; the job stops."""
    _validator().validate(doc)


def build_map(files: dict[str, str], solc_output: dict | None, categories: list[str],
              build_ok: bool = True, compiled_texts: dict[str, str] | None = None) -> MapArtifacts:
    """Lexical layer for every file; semantic layer from the solc AST when the build succeeded.

    `compiled_texts` are the exact source strings the compiler received (per path). The build step
    compiles the fetched Standard JSON byte for byte, so these may keep CRLF while `files` is the
    LF-normalised pin; AST byte offsets are resolved against them so every semantic function lands
    on its own lexical span."""
    lex: dict[str, LexResult] = {p: lex_file(p, t) for p, t in sorted(files.items())}
    file_rows = []
    spans: list[dict[str, Any]] = []
    references: dict[str, set[str]] = {}
    constants: list[dict[str, Any]] = []
    tokens: dict[str, list[dict[str, Any]]] = {}
    for path, res in lex.items():
        row: dict[str, Any] = {"path": path, "status": res.status, "lexer": res.lexer}
        if res.error_class:
            row["error_class"] = res.error_class
        file_rows.append(row)
        tokens[path] = [_stored_token(t) for t in res.tokens]
        for tok in res.tokens:
            if tok.kind == "identifier" and tok.line not in res.decls.get(tok.text, ()):
                references.setdefault(safe_name(tok.text), set()).add(f"{path}:{tok.line}")
        for name, line, init in res.constants:
            folded = fold_constant(init)
            if folded is None:
                continue
            value, unit = folded
            c: dict[str, Any] = {"name": safe_name(name), "decl_ref": f"{path}:{line}", "folded_value": str(value)}
            if unit:
                c["unit"] = unit
            constants.append(c)
        seen: dict[str, int] = {}
        for sp in res.spans:
            sp_name = safe_name(sp.name)
            base = f"{path}:{sp_name}"
            seen[base] = seen.get(base, 0) + 1
            sid = base if seen[base] == 1 else f"{base}@{sp.start}"
            entry: dict[str, Any] = {"id": sid, "name": sp_name, "kind": sp.kind, "file": path,
                                     "start": sp.start, "end": sp.end}
            if sp.unit:
                entry["unit"] = f"{path}:{safe_name(sp.unit)}"
            spans.append(entry)

    doc: dict[str, Any] = {
        "files": file_rows,
        "spans": spans,
        "references": {k: sorted(v, key=_ref_key) for k, v in sorted(references.items())},
        "constants": constants,
    }
    semantic = None
    if build_ok and solc_output:
        built = build_semantic(solc_output, files, categories, compiled_texts)
        if built is not None:
            semantic, span_ids = built
            known = set()
            for sp in spans:
                hit = span_ids.get((sp["file"], sp["start"]))
                if hit is not None:
                    sp["id"], sp["unit"] = hit
                    known.add(hit[0])
            # every semantic function must point at a span (V0 integrity)
            dropped = [f["span"] for f in semantic["functions"] if f["span"] not in known]
            if dropped:
                # A semantic function whose start line is not a lexical span start means the AST
                # offsets and the text disagree (line endings, stale output). Loud, never silent.
                logger.warning("map: %d semantic function(s) have no lexical span and are dropped: %s",
                               len(dropped), ", ".join(dropped[:8]))
            semantic["functions"] = [f for f in semantic["functions"] if f["span"] in known]
            _dedup_span_ids(spans)
            doc["semantic"] = semantic
    if not build_ok:
        status = "failed"
    elif semantic is None:
        status = "partial"
    elif all(r["status"] == "ok" and r["lexer"] == "grammar" for r in file_rows
             if Path(r["path"]).suffix in (".sol", ".rs")):
        status = "full"
    else:
        status = "partial"
    validate_map(doc)
    return MapArtifacts(doc=doc, tokens=tokens, status=status, lex=lex)


def _dedup_span_ids(spans: list[dict[str, Any]]) -> None:
    seen: dict[str, int] = {}
    for sp in spans:
        seen[sp["id"]] = seen.get(sp["id"], 0) + 1
        if seen[sp["id"]] > 1:
            sp["id"] = f"{sp['id']}@{sp['file']}:{sp['start']}"


def _ref_key(ref: str) -> tuple[str, int]:
    path, _, line = ref.rpartition(":")
    return path, int(line)


# ── storage next to the pin (03 3.6: no process memory) ─────────────────────


def _map_dir(root: Path, job_id: str) -> Path:
    return root / job_id / "map"


def token_file_name(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8")).hexdigest()[:16] + ".jsonl"


def write_map(root: Path, job_id: str, art: MapArtifacts, build_detail: str | None = None) -> None:
    d = _map_dir(root, job_id)
    (d / "tokens").mkdir(parents=True, exist_ok=True)
    index = {}
    for path, toks in art.tokens.items():
        name = token_file_name(path)
        index[path] = name
        (d / "tokens" / name).write_text("".join(json.dumps(t, separators=(",", ":")) + "\n" for t in toks),
                                         encoding="utf-8")
    (d / "tokens.json").write_text(json.dumps(index, sort_keys=True), encoding="utf-8")
    (d / "map.json").write_text(json.dumps(art.doc, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    (d / "status.json").write_text(json.dumps({"map_status": art.status, "build_detail": build_detail}),
                                   encoding="utf-8")


def load_map(root: Path, job_id: str) -> tuple[dict[str, Any] | None, str | None]:
    """(map document, map_status) or (None, None) when the job has no map yet."""
    d = _map_dir(root, job_id)
    if not (d / "map.json").exists():
        return None, None
    doc = json.loads((d / "map.json").read_text(encoding="utf-8"))
    status = load_map_status(root, job_id).get("map_status")
    return doc, status


def load_map_status(root: Path, job_id: str) -> dict[str, Any]:
    p = _map_dir(root, job_id) / "status.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def load_tokens(root: Path, job_id: str, paths: list[str] | None = None) -> dict[str, list[dict[str, Any]]]:
    d = _map_dir(root, job_id)
    idx_path = d / "tokens.json"
    if not idx_path.exists():
        return {}
    index: dict[str, str] = json.loads(idx_path.read_text(encoding="utf-8"))
    out: dict[str, list[dict[str, Any]]] = {}
    for path, name in index.items():
        if paths is not None and path not in paths:
            continue
        out[path] = [json.loads(line) for line in (d / "tokens" / name).read_text(encoding="utf-8").splitlines() if line]
    return out
