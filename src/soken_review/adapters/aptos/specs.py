"""Aptos spec-block handling (plan v4 07 7.2) — analysis uses full source text.

Spec blocks are NOT stripped from the source before analysis or compilation.

Rationale (security review 2026-10-12, wave-3): every regex-based spec stripper
introduced a parser differential — the compiled text differed from the text
the reviewer saw, allowing code to hide in a fake "spec" region.  After two
rounds of patching (`_FORBIDDEN` additions, head_end scoping) the review still
found new escapes.  The correct fix is to remove the parser, not patch it:

  * A false lead inside a spec block costs at most one reviewer dismissal.
  * A lead silently lost because a block was stripped is a gap in the review.
  * The only positive proof that a line is non-executable is the compiler's
    own source map (bytecode-to-source-location).  Use ``spec_region()`` when
    a source map is available; otherwise keep the lead.

``strip_specs`` is a no-op shim retained for call-site compatibility.
``spec_region`` answers positively ONLY for locations the compiler itself
flagged as spec in its debuginfo output (``aptos move compile --save-debuginfo``).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class StripReport:
    stripped: int = 0
    refused: list[str] = field(default_factory=list)


def strip_specs(text: str, path: str = "") -> tuple[str, StripReport]:
    """No-op shim: return the original text unchanged.

    Spec-block stripping was removed (2026-10-12) because every regex-based
    implementation introduced a parser differential.  The full source is
    compiled and analyzed; leads inside spec regions are kept or annotated by
    the compiler source map (``spec_region``), never silently discarded.
    """
    return text, StripReport()


def spec_region(source_map: dict, file: str, line: int) -> bool:
    """Return True iff the compiler source map marks *file*:*line* as a spec region.

    *source_map* is the parsed JSON produced by ``aptos move compile
    --save-debuginfo`` (the ``<module>.debuginfo`` sidecar).  If the source map
    is absent or does not cover the location, returns False (lead is kept).

    Only positive compiler evidence is accepted; absence of evidence is not
    evidence of absence.
    """
    if not source_map:
        return False
    # The debuginfo format maps bytecode offset -> {file, line, is_spec}.
    # We scan for any entry that names this file+line and has is_spec=True.
    for entry in source_map.get("locations", []):
        if (entry.get("file") == file or entry.get("file", "").endswith("/" + file)) and entry.get("line") == line and entry.get("is_spec"):
            return True
    return False
