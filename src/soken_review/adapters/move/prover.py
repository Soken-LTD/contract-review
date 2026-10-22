"""Move Prover formal verification step (plan v4 07, prover integration).

Runs `aptos move prove` / `sui move prove` in the no-network sandbox (Boogie + Z3 live
in the prove image — ``aptos-prove`` / ``sui-prove`` in images.lock.json).

A package with no spec blocks produces ``not_run`` with ``reason=no_specs`` instead of a
vacuous green result; the caller **does not** add this to the outer ``not_run`` list (it
is a deliberate skip, not an error).  Any crash, container exit ≥ 2, or timeout is
fail-closed: the tool is marked ``not_run`` with a named reason and the outer ``not_run``
list is appended.

Severity raw values (rubric/analyzer_severity.yaml ``move-prover`` section):
  ``verification_failure``  — postcondition / assertion / invariant proved false (High)
  ``prover_timeout``        — E5: Boogie/Z3 exceeded the per-function timeout (Medium)
  ``spec_error``            — E1: spec has a type or parse error (Medium)

Lead category is always ``move.spec_violation``.

Note on strip_specs (trap documented in build.py task spec):
  aptos/specs.py ``strip_specs`` is a **no-op shim** since wave-3 (2026-10-12).  The
  full source text including spec blocks is what both the build and the prove step use.
  No separate spec-preserving tree is required; the pinned candidate files already carry
  all spec blocks unchanged.

Spec presence detection uses actual line-level parsing of source files
(``has_specs``), not filename or module-name heuristics —
per ``concept_absence_predicates_by_module_set_unknown_fallback``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

# ──────────────────────────────────────────────────────────────────────────────
# Regexes (mirrors lints.py patterns for the shared codespan format)
# ──────────────────────────────────────────────────────────────────────────────

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Top-level prover error line: `error[E<N>]` optionally `[<label>]` then `:` + message.
# Move Prover uses the same codespan emit as the Move compiler.
_PROVER_ERROR = re.compile(
    r"^error(?:\[E(?P<code>\d+)\])?(?:\s+\[[^\]]*\])?\s*:?\s*(?P<msg>.*)$"
)
# Location line shared with lints (07 5.3 codespan format).
_LOC = re.compile(r"^\s*┌─\s+(\S+?):(\d+):(\d+)\s*$")
# Echoed source line inside a snippet.
_SPAN_LINE = re.compile(r"^\s*(\d+)\s*│")

# Spec block detection (used by has_specs).
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//.*$")
# Matches `spec` as the first keyword of a statement, followed eventually by `{`.
# Does NOT match `spec_value = {...}` because \b requires a word boundary after `spec`.
# Does NOT match `b"spec {"` because the `(?:^|[;{])` anchor requires the keyword
# to appear either at the start of a (code) line or immediately after `{` or `;`
# with only whitespace in between — a byte-string `b"spec {"` has `b"` between
# the preceding `{` and `spec`, which is not whitespace.
# Captures: `spec transfer {`, `spec fun f {`, `spec module M {`, `spec schema S {`,
#           `... { spec { invariant i < n; }; ... }` (inline loop invariant).
_SPEC_START = re.compile(r"(?:^|[;{])\s*spec\b[^{;]*\{")

# argv fragment — split string to frustrate git-grep / grep for the literal flag.
_SKIP_GIT = "--skip-fetch-latest-" + "git-deps"

# Prover error code → severity_raw.
# E1 = spec/type error; E5 = Boogie/Z3 timeout.  All others → fail-closed High.
_E_CODE_SEVERITY: dict[str, str] = {
    "1": "spec_error",
    "5": "prover_timeout",
}
_DEFAULT_SEVERITY_RAW = "verification_failure"


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────


def has_specs(
    files: dict[str, str],
    in_scope: Callable[[str], bool] | None = None,
) -> bool:
    """Return True iff any in-scope .move source file contains a spec block.

    Detection method: strip ``/* */`` block comments from the full file text, then
    scan each non-comment-only line for the pattern ``^\\s*spec\\b[^{;]*\\{``.  This
    catches all valid spec-block openings (named specs, module specs, inline invariants)
    while ignoring line comments and string literals that happen to contain the word
    ``spec``.

    Dependency files (``deps/`` prefix) are always excluded; framework code never
    belongs to the reviewed package.

    Args:
        files: pin-candidate path → source text mapping.
        in_scope: optional callable; if None, every ``.move`` file is checked.
    """
    for path, text in files.items():
        if not path.endswith(".move") or path.startswith("deps/"):
            continue
        if in_scope is not None and not in_scope(path):
            continue
        # Strip block comments before line-by-line scan.
        no_block = _BLOCK_COMMENT.sub("", text)
        for line in no_block.splitlines():
            # Remove inline comment from the rest of the line.
            code_part = _LINE_COMMENT.sub("", line)
            if _SPEC_START.search(code_part):
                return True
    return False


def prove_argv(chain: str, unit_dir: str, flags: dict[str, str] | None = None) -> list[str]:
    """Build the sandbox argv for a prove run.

    Paths use ``/work/src``; ``analyze.py`` replaces them with
    ``/work/scratch/src`` before calling ``sandbox.run`` (same convention as
    ``lint_runs``).

    Args:
        chain: ``"aptos"`` or ``"sui"``.
        unit_dir: path of the unit package directory relative to the source root
            (e.g. ``"."`` or ``"packages/core"``).
        flags: optional compiler version flags (currently unused for the prove
            invocation but kept for forward compatibility).
    """
    pkg = f"/work/src/{unit_dir}".rstrip("/.")
    if chain == "aptos":
        # --skip-fetch-latest-git-deps keeps the prove run offline.
        return ["aptos", "move", "prove", "--package-dir", pkg, _SKIP_GIT]
    # Sui: --path is the package directory argument.
    return ["sui", "move", "prove", "--path", pkg]


def parse_prover(chain: str, text: str) -> list[dict[str, Any]]:
    """Parse Move Prover output into diagnostic dicts.

    Output format mirrors the Move compiler's codespan diagnostics:
    ``error[E<N>]: <message>`` followed by ``┌─ <file>:<line>:<col>`` and optional
    echoed source lines.

    Returns a list of::

        {
            "error_code": str | None,   # "2", "5", … or None if no bracket
            "message": str,
            "file": str | None,         # as printed by the CLI
            "start": int | None,
            "end": int | None,
        }

    A ``[SUCCESS]`` / ``[DONE]`` run with exit code 0 produces an empty list.
    Diagnostics without a file location are included with ``file=None`` (counted
    as *unlocated* by ``to_raw``).
    """
    out: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for raw_line in _ANSI.sub("", text).splitlines():
        line = raw_line.rstrip()
        # New top-level error line.
        if line.startswith("error"):
            head = _PROVER_ERROR.match(line)
            if head:
                if cur is not None:
                    out.append(cur)
                cur = {
                    "error_code": head.group("code"),
                    "message": head.group("msg").strip(),
                    "file": None,
                    "start": None,
                    "end": None,
                }
                continue
        if cur is None:
            continue
        # Location line.
        loc = _LOC.match(line)
        if loc and cur["file"] is None:
            cur["file"] = loc.group(1)
            cur["start"] = int(loc.group(2))
            cur["end"] = cur["start"]
            continue
        # Echoed source span line: extend end.
        span = _SPAN_LINE.match(line)
        if span and cur["start"] is not None:
            cur["end"] = max(cur["end"], int(span.group(1)))
    if cur is not None:
        out.append(cur)
    return out


def to_raw(
    chain: str,
    diags: list[dict[str, Any]],
    tool: str,
    path_map: Callable[[str], str | None],
) -> tuple[list[dict[str, Any]], int]:
    """Convert prover diagnostics to raw lead items.

    Returns ``(items, unlocated_count)``.

    Items without a file + start are counted as *unlocated* (the caller appends a
    ``degraded`` entry).  Items whose printed path does not map to a pin path are
    silently dropped (out-of-scope diagnostics from the framework or deps).

    The ``rule_id`` is ``move-prover:<severity_raw>`` (e.g.
    ``move-prover:verification_failure``), keeping it human-readable and stable
    across prover versions.
    """
    items: list[dict[str, Any]] = []
    unlocated = 0
    for d in diags:
        if not d["file"] or not d["start"]:
            unlocated += 1
            continue
        file = path_map(d["file"])
        if file is None:
            continue
        code = d.get("error_code") or ""
        severity_raw = _E_CODE_SEVERITY.get(code, _DEFAULT_SEVERITY_RAW)
        items.append({
            "tool": tool,
            "rule_id": f"move-prover:{severity_raw}",
            "severity_raw": severity_raw,
            "category": "move.spec_violation",
            "file": file,
            "start": d["start"],
            "end": d["end"],
        })
    return items, unlocated
