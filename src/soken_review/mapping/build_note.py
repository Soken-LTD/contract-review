"""One plain sentence for a failed build, printed on the cover, in the summary and in review_status.

Matrix run 2026-10-27 (1inch farming, job_536H8JDV9PQ5NY4EXCA6GQWG17): the build failed on solc 0.8.0,
the job finalized and rendered a tier B PDF whose only traces were "Contract map not available" and
"Checked without a contract map" under every finding. The client must read on page 1 which compiler
was tried, what class of error stopped it and what the review therefore lacks; the reviewer must
read the same sentence in review_status before submitting. Server text: compiler output quotes
source lines, so only the error class names are printed, never the detail.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# Compiler output quotes source lines; only its error class names are printed (no source text).
ERROR_CLASS_RE = re.compile(r"\b([A-Z][A-Za-z]{2,40}Error|not_checkable|failed|no_candidates|"
                            r"compiler_version_unknown|sandbox_unavailable|pin_load_error)\b")
REASON_RE = re.compile(r"[a-z][a-z0-9_]{1,40}")
_CAMEL_RE = re.compile(r"(?<=[a-z])(?=[A-Z])")
_COMPILER_NAME = {"evm": "solc", "hyperevm": "solc", "tron": "solc"}
_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+-]{0,39}$")


def error_class_words(build_detail: str | None) -> str:
    """The error classes of a build detail as plain words: `ParserError` becomes `parser error`;
    an unclassified failure is `build error`."""
    classes = sorted(set(ERROR_CLASS_RE.findall(str(build_detail or ""))))
    words = []
    for c in classes[:3]:
        w = _CAMEL_RE.sub(" ", c).replace("_", " ").lower()
        if w not in words:
            words.append(w)
    return ", ".join(words) or "build error"


def build_failure_sentence(compiler_version: str | None, build_detail: str | None, family: str = "evm") -> str:
    """The sentence for a job whose build failed: compiler chosen, error class, consequence."""
    name = _COMPILER_NAME.get(family, "the compiler")
    version = str(compiler_version or "").strip()
    chosen = f"{name} {version}" if version and _VERSION_RE.match(version) else name
    if chosen == "the compiler" and not version:
        chosen = "the selected compiler"
    return (f"The source did not compile with {chosen} ({error_class_words(build_detail)}). No contract map was "
            f"built and the analyzers did not run, so the findings rest on the session reading the source alone.")


def job_build_failure(root: Path, job_id: str, *, map_status: str | None, family: str = "evm") -> str | None:
    """The sentence for a job, from map/status.json and the compiler fact; None unless the build failed."""
    if map_status != "failed":
        return None
    from .build import load_map_status
    from .facts import load_facts

    try:
        status = load_map_status(root, job_id)
    except (OSError, ValueError):
        status = {}
    detail = status.get("build_detail") if isinstance(status, dict) else None
    try:
        facts = load_facts(root, job_id) or []
    except (OSError, ValueError):
        facts = []
    version = next((str(f.get("value") or "") for f in facts if f.get("key") == "compiler.version"), None)
    return build_failure_sentence(version, detail if isinstance(detail, str) else None, family)


def fact_value(facts: list[dict[str, Any]] | None, key: str) -> str | None:
    return next((str(f.get("value")) for f in facts or [] if f.get("key") == key and f.get("value") is not None), None)
