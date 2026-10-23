"""Caracal static-analysis step for Starknet (depth: second engine beside scarb lint).

Caracal (crytic/caracal) analyses the SIERRA representation of a Starknet contract — the Cairo
analogue of Slither. It runs offline in the sandbox beside ``scarb lint`` and soken-cairo-rules;
``analyze.py`` resolves the pinned ``starknet-caracal`` image and executes ``caracal detect`` in
the build tree. Its text output is untrusted and is parsed here, in the supervisor.

Output format (caracal 0.2.x, ``DetectArgs::run`` → ``Result`` Display):

    <detector-name> Impact: <High|Medium|Low|Informational> Confidence: <High|Medium|Low>
    <message, possibly multiple lines indented with a tab>

Caracal works over SIERRA and, per its own README, "it's not possible to report where an error
is in the source code" — findings name the offending function by its full Cairo path
(``pkg::module::Contract::fn``) rather than a file and line. We therefore map each finding to a
source span through the parsed function table (``source.parse`` gives every function its file and
1-based line range). A finding whose referenced function cannot be resolved to exactly one
in-scope span is counted as *unlocated* (the caller records a degraded entry) and never becomes a
lead — fail-closed: a location is never fabricated.

Lead rows carry ``tool="caracal"``, ``rule_id="caracal:<detector>"`` and ``raw`` equal to the
detector's Impact string; ``rubric/analyzer_severity.yaml`` (``caracal:`` block) normalizes it,
failing closed to High for an unlisted value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from soken_review.adapters.starknet.source import CairoFile

# Tool identity (reference data, not output): the binary name and the pinned release version.
CARACAL_TOOL = "caracal"
CARACAL_VERSION = "0.2.3"
_SEMVER_RE = re.compile(r"^(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:[-+][0-9A-Za-z.]{1,40})?$")

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Header of one finding: `<name> Impact: <I> Confidence: <C>`. Detector names are lowercase with
# hyphens and digits (crytic/caracal detector registry).
_HEADER = re.compile(
    r"^(?P<name>[a-z][a-z0-9-]*) Impact: (?P<impact>High|Medium|Low|Informational)"
    r" Confidence: (?P<conf>High|Medium|Low)\s*$"
)
# A Cairo item path inside a message: at least two `::`-joined identifier segments.
_PATH = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+")
# `Function <name> defined in <declaration>` / `Event <name> defined in <declaration>`: the
# dead-code and unused-events detectors print the bare item name and its module path separately
# (the item is a bare word, not a `::`-path), so reconstruct the qualified `<decl>::<name>`.
_DEFINED_IN = re.compile(
    r"\b(?:Function|Event)\s+([A-Za-z_][A-Za-z0-9_]*)\s+defined in\s+([A-Za-z_][A-Za-z0-9_:]*)"
)

# Detector -> lead category (reference data; the crytic/caracal detector registry, v0.2.x).
# An unlisted detector falls back to cairo.best_practice (same floor as an unmapped scarb lint).
_DETECTOR_CATEGORY: dict[str, str] = {
    "controlled-library-call": "cairo.access_control",
    "unchecked-l1-handler-from": "cairo.access_control",
    "tx-origin": "cairo.access_control",
    "felt252-unsafe-arithmetic": "cairo.arithmetic",
    "reentrancy": "cairo.reentrancy",
    "read-only-reentrancy": "cairo.reentrancy",
    "reentrancy-benign": "cairo.reentrancy",
    "reentrancy-events": "cairo.reentrancy",
    "unused-return": "cairo.error_handling",
    "unused-events": "cairo.best_practice",
    "unenforced-view": "cairo.best_practice",
    "unused-arguments": "cairo.best_practice",
    "dead-code": "cairo.best_practice",
    "use-after-pop-front": "cairo.data_handling",
}
_DEFAULT_CATEGORY = "cairo.best_practice"


@dataclass(frozen=True)
class SierraSupport:
    """What the pinned caracal can read, from images.lock.json `tools` of `starknet-caracal`."""

    caracal: str          # "0.2.3"
    cairo_lang: str       # the cairo-lang-* crates its Cargo.lock pins, "2.5.0"
    sierra_max: str       # current_sierra_version_id() of that cairo-lang, "1.4.0"

    @property
    def sierra_major_minor(self) -> tuple[int, int]:
        return _major_minor(self.sierra_max)

    @property
    def cairo_major_minor(self) -> tuple[int, int]:
        return _major_minor(self.cairo_lang)

    def reason(self) -> str:
        major, minor = self.sierra_major_minor
        return f"unsupported_cairo_version (caracal {self.caracal} supports Sierra <= {major}.{minor})"


def _major_minor(version: str) -> tuple[int, int]:
    m = _SEMVER_RE.match(version or "")
    if m is None:
        raise ValueError(f"not a version: {version!r}")
    return int(m.group(1)), int(m.group(2))


def supported_sierra() -> SierraSupport | None:
    """The Sierra ceiling of the pinned caracal, or None when the lock does not record it.

    caracal v0.2.3 pins every `cairo-lang-*` crate at 2.5.0 (`Cargo.toml` lines 25 to 35:
    `git = ".../cairo.git", tag = "v2.5.0"`; `Cargo.lock` `cairo-lang-sierra 2.5.0`), and cairo
    v2.5.0 `crates/cairo-lang-starknet/src/compiler_version.rs` sets `current_sierra_version_id()`
    to 1.4.0. Its loader (`src/compilation/scarb.rs`: vendored `sierra_from_felt252s`, then
    `src/core/core_unit.rs:31` `ProgramRegistry::<CoreType, CoreLibfunc>::new(&p.sierra).unwrap()`)
    decodes the felts of a newer program but the 2.5.0 registry rejects its declarations: Cairo
    2.6.0 renamed the const type id from `"const"` to `"Const"` (`cairo-lang-sierra/src/extensions/
    modules/const_type.rs`, 2.5.0 line 27 vs 2.6.0 line 30) and added types and libfuncs the crate
    has no entry for. Verified on the stand 2026-10-23 with the real dev-profile artifacts of OZ
    presets at Cairo 2.13.1 (Sierra 1.7.0): every class panics at `core_unit.rs:31` with
    `TypeSpecialization { .. GenericTypeId("Const"), error: UnsupportedId("Const") }`, exit 101,
    within 2 s of loading. Scarb toolchains emit Sierra 1.4.0 (Cairo 2.4, 2.5), 1.5.0 (2.6),
    1.6.0 (2.7 to 2.9) and 1.7.0 (2.10 to 2.13). The numbers live in images.lock.json `tools`
    (`cairo-lang`, `sierra`) beside the caracal version, not here.
    """
    from soken_review.sandbox.profile import locked_tools

    tools = locked_tools("starknet-caracal")
    caracal, cairo_lang, sierra_max = tools.get("caracal"), tools.get("cairo-lang"), tools.get("sierra")
    if not caracal or not cairo_lang or not sierra_max:
        return None
    try:
        _major_minor(cairo_lang), _major_minor(sierra_max)
    except ValueError:
        return None
    return SierraSupport(caracal=caracal, cairo_lang=cairo_lang, sierra_max=sierra_max)


def sierra_supported(support: SierraSupport, *, sierra: str | None, cairo: str | None) -> bool | None:
    """True when the class caracal would load is within the ceiling, False when above, None when
    neither the Sierra version of a built class nor the project's Cairo version is known.

    The Sierra header of a built class is exact (the artifact the build step produced; caracal's
    own dev build uses the same compiler). Without one, the Cairo compiler version decides: a Cairo
    minor above the pinned cairo-lang minor emits a Sierra above the ceiling (the table in
    `supported_sierra`), a Cairo at or below it does not.
    """
    if sierra:
        try:
            major, minor = _major_minor(sierra)
        except ValueError:
            return None
        smajor, sminor = support.sierra_major_minor
        return major == smajor and minor <= sminor
    if cairo:
        try:
            major, minor = _major_minor(cairo)
        except ValueError:
            return None
        cmajor, cminor = support.cairo_major_minor
        return (major, minor) <= (cmajor, cminor)
    return None


def detect_argv(target: str = ".") -> list[str]:
    """argv for a caracal run on the Scarb project at ``target`` (the dir with Scarb.toml).

    ``analyze.py`` runs this with the container workdir set to the package directory, so the
    default ``.`` points caracal at the reviewed package. Caracal's Scarb mode runs ``scarb clean``
    and ``scarb build --workspace`` itself (offline through ``SCARB_OFFLINE``, against the
    scarb-cache the deps step fetched) and reads the classes from :func:`target_dir`.
    """
    return ["caracal", "detect", target]


def target_dir(workdir: str) -> str:
    """``SCARB_TARGET_DIR`` for a caracal run whose project dir is ``workdir`` in the container.

    caracal 0.2.x (``compilation/scarb.rs``) reads ``<project>/target/dev`` and never consults
    ``SCARB_TARGET_DIR``; pointing Scarb's target dir there makes its own build land where it
    looks, and keeps ``scarb clean`` away from the build step's ``/work/output``.
    """
    return workdir.rstrip("/") + "/target"


# One line per class caracal refused (no SIERRA debug names); it exits 0 regardless.
_SKIPPED = re.compile(r"^Skipping analysing file .*Debug info not found", re.MULTILINE)


def skipped_files(text: str) -> int:
    """Number of classes caracal skipped for missing debug info (``sierra-replace-ids`` off)."""
    return len(_SKIPPED.findall(_ANSI.sub("", text)))


def category_for(detector: str) -> str:
    """Lead category for a caracal detector, failing open to cairo.best_practice."""
    return _DETECTOR_CATEGORY.get(detector, _DEFAULT_CATEGORY)


def parse_caracal(text: str) -> list[dict[str, Any]]:
    """Parse caracal ``detect`` output into findings.

    Returns a list of::

        {"detector": str, "impact": str, "confidence": str, "message": str, "refs": [str, ...]}

    where ``refs`` are the Cairo item paths named in the message, in order of appearance. ANSI
    colour codes (caracal always colours stdout) are stripped first. A ``[SUCCESS]``/empty run
    yields an empty list.
    """
    findings: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    msg: list[str] = []

    def _flush() -> None:
        if cur is not None:
            message = "\n".join(msg).strip()
            cur["message"] = message
            # Reconstructed `<decl>::<name>` subjects first (dead-code / unused-events), then the
            # `::`-paths named directly (reentrancy, unused-arguments, controlled-library-call …).
            refs = [f"{decl}::{name}" for name, decl in _DEFINED_IN.findall(message)]
            refs += _PATH.findall(message)
            cur["refs"] = list(dict.fromkeys(refs))
            findings.append(cur)

    for raw_line in _ANSI.sub("", text).splitlines():
        line = raw_line.rstrip()
        head = _HEADER.match(line)
        if head:
            _flush()
            cur = {"detector": head.group("name"), "impact": head.group("impact"),
                   "confidence": head.group("conf")}
            msg = []
            continue
        if cur is not None:
            msg.append(line)
    _flush()
    return findings


def build_locator(parsed: list[CairoFile]):
    """Return a callable ``refs -> (file, start, end) | None`` over the parsed function table.

    Resolution is by the bare function name (last ``::`` segment of a ref). A ref resolves when
    exactly one in-scope function carries that name; when several do, the ref's preceding path
    segment must single out one by matching a file-path component (stem or directory), otherwise
    the ref is ambiguous and skipped. The first ref that resolves wins; if none resolve the
    finding is unlocated.
    """
    by_name: dict[str, list[tuple[str, int, int]]] = {}
    for cf in parsed:
        for fn in cf.functions:
            by_name.setdefault(fn.name, []).append((cf.path, fn.start, fn.end))

    def _components(path: str) -> set[str]:
        parts = re.split(r"[/.]", path)
        return {p for p in parts if p}

    def locate(refs: list[str]) -> tuple[str, int, int] | None:
        for ref in refs:
            segs = ref.split("::")
            bare = segs[-1]
            candidates = by_name.get(bare)
            if not candidates:
                continue
            if len(candidates) == 1:
                return candidates[0]
            # Ambiguous: use the preceding path segment to disambiguate by file component.
            hint = segs[-2] if len(segs) >= 2 else None
            if hint:
                narrowed = [c for c in candidates if hint in _components(c[0])]
                if len(narrowed) == 1:
                    return narrowed[0]
            # Still ambiguous for this ref: try the next ref rather than guessing.
        return None

    return locate


def to_rows(findings: list[dict[str, Any]], parsed: list[CairoFile],
            in_scope: set[str]) -> tuple[list[dict[str, Any]], int]:
    """Convert caracal findings to lead rows (the dict shape ``build_leads`` consumes).

    Returns ``(rows, unlocated)``. A finding whose referenced function resolves to exactly one
    in-scope source span becomes a row; one that does not is counted as unlocated. ``raw`` is the
    caracal Impact string (normalized by the ``caracal:`` block of analyzer_severity.yaml).
    """
    locate = build_locator(parsed)
    rows: list[dict[str, Any]] = []
    unlocated = 0
    for f in findings:
        span = locate(f["refs"])
        if span is None or span[0] not in in_scope:
            unlocated += 1
            continue
        file, start, end = span
        rows.append({
            "tool": CARACAL_TOOL,
            "rule_id": f"{CARACAL_TOOL}:{f['detector']}",
            "category": category_for(f["detector"]),
            "raw": f["impact"],
            "file": file,
            "start": start,
            "end": end,
            "unit": None,
        })
    return rows, unlocated
