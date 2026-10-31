"""TON trust scan (plan v4 06 3.3.4): sources that could carry precompiled code never reach tier A.

A FunC, Tolk or Tact `asm` body is Fift text: besides TVM mnemonics it can run any Fift word,
so it can build raw code or data inline (`<b ... b>`, `u,`, `ref,`, `B>boc`, `base64>B`,
`file>B`, big numeric literals). A source like that rebuilds to the deployed hash while its
readable text says nothing about the deployed behaviour, so a match from it proves nothing.

The check is an allowlist. Each asm body is tokenized; every token must be one of:
  - a TVM assembler mnemonic from `data/tvm_mnemonics.txt` (Asm.fif + tvm-spec cp0.json, pinned);
  - a stack or control register (`s0`..`s255`, `s(-1)`, `c0`..`c7`);
  - an integer immediate of at most 12 decimal digits or a 0x hex of at most 8 digits
    (op codes, nanoton amounts);
  - a continuation block delimiter (`<{`, `}>`, `}>c`, `}>s`);
  - a cell or slice literal (`B{..}`, `x{..}`, `b{..}`) of at most 32 bytes, at most 8 per candidate.
A whole body may instead equal one of `_KNOWN_BODIES`: fixed standard-library idioms that build
a constant of at most 2 bits (`address_none`, `empty_cell`), which cannot carry code.
A body may also be the library reference idiom `<b 2 8 u, 0x<64 hex> 256 u, b>spec PUSHREF`
(an exotic cell of type 2 that names a masterchain library by its hash; TVM whitepaper 3.1.7,
multisig v2 `auto/order_code.func`). It carries no code, only a hash: it is trusted when the
caller passes that hash in `resolved_libraries` (the supervisor read the library from the chain
and its body hashes to it, fetch.resolve_library_refs), else it is untrusted ("not resolved").
Any other token marks the candidate untrusted. The scan does not stop the build or the analysis;
it sets `Candidate.untrusted_inputs`, which `provenance.resolve_provenance` reads at the decision
point (tier A blocked).

Two views per file, both must pass: (1) the lexer view, comments removed with the compilers'
rules (FunC `;;` and nested `{- -}`, Tolk and Tact `//` and `/* */`, `\\` escapes in C-style
strings, markers inside string literals ignored), so a comment between `asm` and its body cannot
hide the body; an unterminated string or comment fails closed; (2) the raw text, unlexed, so a
lexer mistake can only remove false positives, never hide a body (commented-out asm with a
disallowed body is therefore untrusted too). In each view the number of `asm` keywords must equal
the number of bodies extracted, else the candidate is untrusted.

Every candidate file is scanned whatever its extension (FunC and C comment rules both applied to
non-source files); only files that parse as JSON are skipped, since no compiler reads them except
`tact.config.json`, whose project entries must be `.tact` files.

Code carried as data (both views): a data literal over the 32-byte budget (FunC `"<hex>"s`, Tolk
`stringHexToSlice(` / `stringToBase256(`, Tact `cell(` / `slice(` / `rawSlice(`) or an integer
outside strings over 20 decimal, 16 hex or 64 binary digits, unless it is 2**n or 2**n - 1 (a
mask carries no data); any asm body using BLESS / EXECUTE /
CALLX / JMPX or their ARGS forms; any mention of the wrapper names in `_EXEC_WRAPPER_NAMES`. The
single exception is the exact standard stdlib.fc declaration `cont bless(slice s) impure asm
"BLESS";`, which every FunC project ships; any other mention of `bless` is still untrusted.
SETCODE / set_code stay trusted: they change future code, not whether the deployed code equals
the rebuild.

Also untrusted (06 3.3.4 TON row): a Tact `asm` function over 16 instructions; an include or
import whose target is not a source file of the including language (FunC `.fc`/`.func`; Tolk
`.tolk` or `@stdlib/<name>`; Tact `.tact`/`.fc`/`.func` or no extension, which Tact resolves to
`.tact`), and any include from a non-source file; compiler params outside the worker allowlist
(`untrusted_args`).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from soken_review.adapters.ton.tact_config import check_config

MAX_LITERAL_BYTES = 32
MAX_LITERALS = 8
MAX_TACT_ASM_INSTRUCTIONS = 16
MAX_IMMEDIATE_DIGITS = 12
MAX_HEX_IMMEDIATE_DIGITS = 8

# Exact bodies from the standard stdlib.fc / Tolk / jetton-contract helpers; each yields a fixed
# cell or slice of at most 2 bits.
_KNOWN_BODIES = frozenset({
    "<b 0 2 u, b> <s PUSHSLICE",   # address_none (addr_none$00)
    "<b b> PUSHREF",               # empty cell
    "<b b> <s PUSHSLICE",          # empty slice
})

# Verifier bundle `compiler.params` top-level keys the worker accepts (acton compiler-worker, F13).
# compiler_version: FunC/Tolk legacy param.
# entrypoint: Tact registry param — path to the main .tact file (must end in .tact).
# options: Tact compiler options object; sub-keys are validated against the Tact 1.6 schema.
_ALLOWED_PARAMS = frozenset({"compiler_version", "entrypoint", "options"})

# Tact 1.6 options allowlist (mirrors tact_config._BOOL_OPTIONS / _NESTED_OPTIONS).
_ALLOWED_OPTION_KEYS = frozenset({
    "debug", "external", "ipfsAbiGetter", "interfacesGetter",
    "enableLazyDeploymentCompletedGetter",
    "experimental", "safety", "optimizations",
})
_NESTED_OPTION_KEYS: dict[str, frozenset[str]] = {
    "experimental": frozenset({"inline"}),
    "safety": frozenset({"nullChecks"}),
    "optimizations": frozenset({"alwaysSaveContractData", "internalExternalReceiversOutsideMethodsMap"}),
}

# Legacy mnemonics still declared by deployed stdlib.fc copies but absent from the pinned lists.
_LEGACY_MNEMONICS = frozenset({"BUYGAS"})

_MNEMONICS: frozenset[str] = _LEGACY_MNEMONICS | frozenset(
    line.strip()
    for line in (Path(__file__).parent / "data" / "tvm_mnemonics.txt").read_text().splitlines()
    if line.strip() and not line.startswith("#")
)

# Library reference cell builder (exotic type 2, 8-bit tag then the 256-bit representation hash).
_LIBRARY_REF_BODY = re.compile(r"^<b 2 8 u, (0x[0-9a-fA-F]{64}) 256 u, b>spec PUSHREF$")

_ASM_STRINGS = re.compile(r'\basm\b\s*(?:\([^)]*\)\s*)?((?:"[^"]*"\s*)+)')
_STRING = re.compile(r'"([^"]*)"')
_ASM_WORD = re.compile(r"\basm\b")
# a literal is a whole token: `x{..}` glued to anything else stays one unknown token
_LITERAL = re.compile(r"(?<!\S)(B|x|b)\{([^}]*)\}(?!\S)")
_LITERAL_BODY = {"x": re.compile(r"^[0-9a-fA-F]*_?$"), "B": re.compile(r"^[0-9a-fA-F]*$"), "b": re.compile(r"^[01]*$")}
_INCLUDE = re.compile(r'(?:#include|\bimport)\s+"([^"]+)"')
_TACT_ASM_HEAD = re.compile(r"\basm\b(?:\s*\([^)]*\))?\s+(?:\w+\s+)*fun\b[^{;]*\{")
_REGISTER = re.compile(r"^(?:s\d{1,3}|s\(-?\d{1,2}\)|c\d)$")
_IMMEDIATE = re.compile(rf"^(?:-?\d{{1,{MAX_IMMEDIATE_DIGITS}}}|0x[0-9a-fA-F]{{1,{MAX_HEX_IMMEDIATE_DIGITS}}})$")

# Source extensions the build of each language reads (06 4.2); includes must stay inside them.
_FUNC_EXTS = (".fc", ".func")
_TOLK_EXTS = (".tolk",)
_TACT_EXTS = (".tact", ".fc", ".func")   # Tact imports FunC files too
_SOURCE_EXTS = _FUNC_EXTS + _TOLK_EXTS + (".tact",)
# The one non-source file a build reads: Tact project config (paths rebased by build.py).
_CONFIG_FILES = frozenset({"tact.config.json"})
_BLOCK = frozenset({"<{", "}>", "}>c", "}>s"})

# Code-from-data execution (06 3.3.4, review 2026-10-10): a used wrapper over these makes the
# candidate untrusted. SETCODE / set_code are not here: they change future code, not whether the
# deployed code equals the rebuild; checklist leads cover them.
_EXEC = frozenset({"BLESS", "BLESSVARARGS", "BLESSARGS", "EXECUTE", "CALLX", "JMPX", "CALLXARGS",
                   "CALLXVARARGS", "JMPXARGS", "JMPXVARARGS", "RETVARARGS", "CALLXARGS_VAR"})
# Wrapper names (FunC stdlib, Tolk @stdlib, Tact core) whose mention anywhere is untrusted.
_EXEC_WRAPPER_NAMES = frozenset({"bless", "transformSliceToContinuation", "executeContinuation"})
# The one exception: the standard stdlib.fc declaration, which every FunC project ships and
# never calls. Exact text only; any other asm with an _EXEC mnemonic is untrusted.
_STD_BLESS = re.compile(r'\bcont\s+bless\s*\(\s*slice\s+s\s*\)\s*impure\s+asm\s+"BLESS"\s*;')
# Data literals that can carry code (FunC "..."s, Tolk stringHexToSlice / stringToBase256,
# Tact cell("base64") / slice("base64") / rawSlice("hex")).
_DATA_LITERALS = (
    (re.compile(r'"([0-9a-fA-F_\s]*)"s'), "hex"),
    (re.compile(r'stringHexToSlice\(\s*"([^"]*)"'), "hex"),
    (re.compile(r'stringToBase256\(\s*"([^"]*)"'), "text"),
    (re.compile(r'\b(?:cell|slice)\(\s*"([^"]*)"'), "base64"),
    (re.compile(r'\brawSlice\(\s*"([^"]*)"'), "hex"),
)
MAX_INT_DIGITS = 20
MAX_INT_HEX_DIGITS = 16
MAX_INT_BIN_DIGITS = 64
# every numeric form (digit separators `_` allowed by Tolk/Tact); digits counted without prefix and `_`
_NUMBER = re.compile(r"(?<![\w.])(0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|\d[\d_]*)(?![\w])")
_INT_CAP = {"x": MAX_INT_HEX_DIGITS, "b": MAX_INT_BIN_DIGITS, "o": MAX_INT_DIGITS}


def _literal_bytes(kind: str, body: str) -> int:
    body = re.sub(r"\s+", "", body)
    if kind == "b":
        return (len(body) + 7) // 8
    return (len(body.rstrip("_")) + 1) // 2


def _tact_asm_bodies(text: str) -> list[str]:
    bodies: list[str] = []
    for m in _TACT_ASM_HEAD.finditer(text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        bodies.append(text[m.end() : i - 1])
    return bodies


def lex(text: str, style: str) -> tuple[str, bool]:
    """Remove comments outside string literals; returns (text, terminated).

    style "func": `;;` and nested `{- -}`; style "c": `//` and `/* */`, with `\\` escapes inside
    strings. Comment text becomes one space. `terminated` is False when a string or block comment
    is still open at the end of the file (the caller fails closed).
    """
    out: list[str] = []
    i, n, depth, in_str = 0, len(text), 0, False
    while i < n:
        ch, two = text[i], text[i : i + 2]
        if depth:
            if style == "func" and two == "{-":
                depth += 1
                i += 2
            elif (style == "func" and two == "-}") or (style == "c" and two == "*/"):
                depth -= 1
                i += 2
                if not depth:
                    out.append(" ")
            else:
                i += 1
            continue
        if in_str:
            if style == "c" and ch == "\\" and i + 1 < n:
                out.append(text[i : i + 2])
                i += 2
                continue
            out.append(ch)
            in_str = ch != '"'
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
        elif (style == "func" and two == ";;") or (style == "c" and two == "//"):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif (style == "func" and two == "{-") or (style == "c" and two == "/*"):
            depth = 1
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out), not (depth or in_str)


def strip_comments(text: str, style: str) -> str:
    return lex(text, style)[0]


def _include_ok(target: str, lower_path: str) -> bool:
    t = target.lower()
    if lower_path.endswith(_FUNC_EXTS):
        return t.endswith(_FUNC_EXTS)
    if lower_path.endswith(_TOLK_EXTS):
        return t.endswith(_TOLK_EXTS) or (t.startswith("@stdlib/") and "." not in t.rsplit("/", 1)[-1])
    if lower_path.endswith(".tact"):
        last = t.rsplit("/", 1)[-1]
        # no extension: the Tact compiler reads `<name>.tact`
        return t.endswith(_TACT_EXTS) or "." not in last
    return False


def _is_json(text: str) -> bool:
    """JSON, or JSON with `//` and `/* */` comments (JSONC, e.g. cspell.json): data no compiler reads."""
    for candidate in (text, lex(text, "c")[0]):
        try:
            json.loads(candidate)
        except ValueError:
            continue
        return True
    return False


def _non_source_reads(files: dict[str, str]) -> list[str]:
    """Files the build reads by name besides includes: tact.config.json.

    Project entries must be `.tact` files, and the config must stay inside the Tact 1.6.13
    schema allowlist (`tact_config.check_config`): documented options and mode pass through to
    the compiler and are recorded; an unknown key or a wrong type is untrusted.
    """
    reasons: list[str] = []
    for path, text in files.items():
        if path.lower().rsplit("/", 1)[-1] not in _CONFIG_FILES:
            continue
        try:
            cfg = json.loads(text)
        except ValueError:
            reasons.append(f"{path}: unreadable config")
            continue
        projects, cfg_reasons = check_config(cfg, path)
        reasons.extend(cfg_reasons)
        for proj in projects:
            entry = str(proj.get("path") or "")
            if not entry.lower().endswith(".tact"):
                reasons.append(f"{path}: project entry {entry[:80]!r} is not a .tact file")
    return reasons


def library_ref_hash(body: str) -> str | None:
    """The 64-hex library hash when an asm body is exactly the library reference idiom."""
    m = _LIBRARY_REF_BODY.match(" ".join(body.split()))
    return m.group(1)[2:].lower().rjust(64, "0") if m else None


def library_refs(files: dict[str, str]) -> list[str]:
    """Library hashes named by library reference asm bodies in source files (lexer view)."""
    found: list[str] = []
    for path, raw in sorted(files.items()):
        lower = path.lower()
        if not lower.endswith(_SOURCE_EXTS):
            continue
        text = strip_comments(raw, "func" if lower.endswith(_FUNC_EXTS) else "c")
        for m in _ASM_STRINGS.finditer(text):
            h = library_ref_hash(" ".join(_STRING.findall(m.group(1))))
            if h and h not in found:
                found.append(h)
    return found


def _check_body(path: str, body: str, reasons: list[str],
                resolved: frozenset[str] = frozenset()) -> tuple[int, int]:
    """Allowlist one asm body. Returns (literal count, mnemonic count)."""
    if " ".join(body.split()) in _KNOWN_BODIES:
        return 0, 1
    lib = library_ref_hash(body)
    if lib is not None:
        if lib not in resolved:
            reasons.append(f"{path}: library reference {lib[:16]}... is not resolved on chain")
        return 0, 1
    literals = 0
    for lit in _LITERAL.finditer(body):
        literals += 1
        if not _LITERAL_BODY[lit.group(1)].match(re.sub(r"\s+", "", lit.group(2))):
            reasons.append(f"{path}: asm literal {lit.group(0)[:40]!r} is not plain hex or binary")
        size = _literal_bytes(lit.group(1), lit.group(2))
        if size > MAX_LITERAL_BYTES:
            reasons.append(f"{path}: asm literal of {size} bytes")
    mnemonics = 0
    for token in _LITERAL.sub(" ", body).split():
        if token in _MNEMONICS:
            mnemonics += 1
        elif not (_REGISTER.match(token) or _IMMEDIATE.match(token) or token in _BLOCK):
            reasons.append(f"{path}: asm token {token[:40]!r} is not a TVM mnemonic or small operand")
    return literals, mnemonics


def _data_literals(path: str, text: str, reasons: list[str]) -> None:
    """Code can ride in data: a literal over the 32-byte budget, or a huge integer, is untrusted."""
    for rx, enc in _DATA_LITERALS:
        for m in rx.finditer(text):
            body = re.sub(r"\s+", "", m.group(1))
            size = (len(body.rstrip("_")) + 1) // 2 if enc == "hex" else (
                len(body.encode()) if enc == "text" else len(body.rstrip("=")) * 3 // 4)
            if size > MAX_LITERAL_BYTES:
                reasons.append(f"{path}: data literal of {size} bytes ({m.group(0)[:24]}...)")
    for m in _NUMBER.finditer(_STRING.sub(chr(34) * 2, text)):
        tok = m.group(1).lower()
        kind = tok[1] if len(tok) > 1 and tok[0] == "0" and tok[1] in "xbo" else "d"
        digits = len((tok[2:] if kind != "d" else tok).replace("_", ""))
        if digits > _INT_CAP.get(kind, MAX_INT_DIGITS) and not _is_mask(tok, kind):
            reasons.append(f"{path}: integer constant {m.group(0)[:24]} over the digit cap")


def _is_mask(tok: str, kind: str) -> bool:
    """A big constant that carries no data: 2**n - 1 (a bit mask such as MAX_ORDER_SEQNO in
    multisig v2, all hex `f`) or 2**n, for n at most 257 (the TVM integer width)."""
    body = (tok[2:] if kind != "d" else tok).replace("_", "")
    try:
        value = int(body, {"x": 16, "b": 2, "o": 8}.get(kind, 10))
    except ValueError:
        return False
    if value <= 0 or value.bit_length() > 257:
        return False
    return value & (value + 1) == 0 or value & (value - 1) == 0


def _scan_text(path: str, text: str, reasons: list[str], resolved: frozenset[str] = frozenset()) -> int:
    """Independent checks on one view of a file; returns the literal count of this view."""
    _data_literals(path, text, reasons)
    literals = 0
    bodies = 0
    std_spans = [m.span() for m in _STD_BLESS.finditer(text)]
    for m in _ASM_STRINGS.finditer(text):
        body = " ".join(_STRING.findall(m.group(1)))
        n, _ = _check_body(path, body, reasons, resolved)
        literals += n
        bodies += 1
        if _EXEC & set(body.split()) and not any(lo <= m.start() < hi for lo, hi in std_spans):
            reasons.append(f"{path}: asm executes code taken from data ({body[:40]!r})")
    for body in _tact_asm_bodies(text):
        n, count = _check_body(path, body, reasons)
        literals += n
        bodies += 1
        if count > MAX_TACT_ASM_INSTRUCTIONS:
            reasons.append(f"{path}: Tact asm with {count} instructions")
        if _EXEC & set(body.split()):
            reasons.append(f"{path}: asm executes code taken from data ({body.strip()[:40]!r})")
    words = len(_ASM_WORD.findall(text))
    if words != bodies:
        # fail closed: an `asm` keyword whose body the scanner did not extract
        reasons.append(f"{path}: {words} asm keywords, {bodies} asm bodies recognised")
    # A code-from-data wrapper named anywhere except the exact stdlib declaration is a call.
    rest = _STD_BLESS.sub(" ", text)
    for name in sorted(_EXEC_WRAPPER_NAMES):
        if re.search(rf"(?<![\w]){re.escape(name)}(?![\w])", rest):
            reasons.append(f"{path}: code-from-data wrapper {name!r} is referenced")
    return literals


def _views(path: str, raw: str, reasons: list[str]) -> list[str]:
    """The lexer views (FunC and/or C comment rules) plus the raw text."""
    lower = path.lower()
    if lower.endswith(_FUNC_EXTS):
        styles = ["func"]
    elif lower.endswith((".tolk", ".tact")):
        styles = ["c"]
    else:
        styles = ["func", "c"]
    views = []
    for style in styles:
        text, terminated = lex(raw, style)
        if not terminated:
            reasons.append(f"{path}: unterminated string or comment")
        views.append(text)
    return [*views, raw]


def scan_files(files: dict[str, str], resolved_libraries: Iterable[str] = ()) -> list[str]:
    """Return the reasons a candidate is untrusted (empty list = trusted).

    The reasons are the union of independent checks over (file x view): each lexer view and
    the raw text. No check compares counts across views, so scanning a file in more views can
    only add reasons (the literal total takes, per file, the largest count of any view). Every
    file is scanned, whatever its extension; only non-source files that parse as JSON are
    skipped (no compiler reads them, and a reference to one is an include violation).
    `resolved_libraries`: library hashes the supervisor read from the chain (hash verified); a
    library reference body naming one of them is trusted.
    """
    resolved = frozenset(h.lower() for h in resolved_libraries)
    reasons: list[str] = []
    literals = 0
    for path, raw in sorted(files.items()):
        lower = path.lower()
        is_source = lower.endswith(_SOURCE_EXTS)
        if not is_source and _is_json(raw):
            continue
        per_file = 0
        for text in _views(path, raw, reasons):
            per_file = max(per_file, _scan_text(path, text, reasons, resolved))
            for inc in _INCLUDE.findall(text):
                if not is_source or not _include_ok(inc, lower):
                    reasons.append(f"{path}: includes {inc[:80]!r}, not a source file of the language")
        literals += per_file
    reasons.extend(_non_source_reads(files))
    if literals > MAX_LITERALS:
        reasons.append(f"{literals} asm cell or slice literals")
    return list(dict.fromkeys(reasons))


def scan_params(params: Any) -> list[str]:
    """Compiler params outside the allowlist make the candidate `untrusted_args`.

    Top-level keys are checked against _ALLOWED_PARAMS.  The `entrypoint` value must be a
    string ending in `.tact`.  The `options` value must be an object whose keys and their
    types match the Tact 1.6 schema (boolean scalars, or nested objects with known sub-keys).
    Unknown option keys are untrusted even if nested keys are otherwise valid.
    """
    if not params:
        return []
    if not isinstance(params, dict):
        return ["compiler params are not an object"]
    reasons = [f"compiler param {k!r} outside the allowlist" for k in params if k not in _ALLOWED_PARAMS]
    if "entrypoint" in params:
        ep = params["entrypoint"]
        if not isinstance(ep, str):
            reasons.append("compiler param 'entrypoint' is not a string")
        elif not ep.lower().endswith(".tact"):
            reasons.append(f"compiler param 'entrypoint' {ep[:80]!r} is not a .tact file")
    if "options" in params:
        opts = params["options"]
        if not isinstance(opts, dict):
            reasons.append("compiler param 'options' is not an object")
        else:
            for ok, ov in opts.items():
                if ok not in _ALLOWED_OPTION_KEYS:
                    reasons.append(f"compiler param options.{ok!r} outside the allowlist")
                elif ok in _NESTED_OPTION_KEYS:
                    if not isinstance(ov, dict):
                        reasons.append(f"compiler param options.{ok} is not an object")
                    else:
                        for sk, sv in ov.items():
                            if sk not in _NESTED_OPTION_KEYS[ok]:
                                reasons.append(f"compiler param options.{ok}.{sk!r} outside the allowlist")
                            elif not isinstance(sv, bool):
                                reasons.append(f"compiler param options.{ok}.{sk} is not a boolean")
                elif not isinstance(ov, bool):
                    reasons.append(f"compiler param options.{ok} is not a boolean")
    return reasons
