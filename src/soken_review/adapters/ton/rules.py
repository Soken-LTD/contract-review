"""soken-ton-rules: text-pattern rule pack for FunC, Tact, Tolk (plan v4 06 4.5).

Each rule function takes the source files dict and returns a list of raw lead dicts.
The raw dicts are consumed by analyze.py to produce lead.v1.

Rules are defined in plan 06 4.5 (TON-BNC-*, TON-GAS-*, TON-MODE-*, TON-AUTH-*,
TON-RPL-*, TON-UPG-*, TON-INT-*, TON-RND-*, TON-RACE-*, TON-JET-*).

This is a pattern-based implementation. High-confidence detections only;
uncertain patterns emit Info severity rather than omitting.
"""

from __future__ import annotations

import re
from typing import Any

_RULE_VERSION = "0.1.0"
_TOOL_NAME = f"soken-ton-rules@{_RULE_VERSION}"


def _lines_with_numbers(source: str) -> list[tuple[int, str]]:
    """Return [(1-based line number, line text)] for a source string."""
    return [(i + 1, line) for i, line in enumerate(source.splitlines())]


def _search_lines(pattern: re.Pattern[str], lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Return matching (lineno, text) pairs."""
    return [(n, t) for n, t in lines if pattern.search(t)]


def _raw_lead(
    rule_id: str,
    file_path: str,
    line_start: int,
    line_end: int,
    severity: str = "warning",
) -> dict[str, Any]:
    return {
        "tool": _TOOL_NAME,
        "rule_id": rule_id,
        "severity_raw": severity,
        "file": file_path,
        "start": line_start,
        "end": line_end,
        "message": rule_message(rule_id),
    }


_RULE_MESSAGES: dict[str, str] | None = None
_PLAN_REF_RE = re.compile(r"\s*\((?:plan|06|F\d)[^()]*\)\.?$")


def rule_message(rule_id: str) -> str:
    """Detector text of a rule: the first line of its `check_*` docstring (`TON-X-NN: <what it
    flags>`), without the plan reference. Printed by review_leads so a rule lead says what to
    check at the location (blind run 2026-10-26: TON leads showed no detector text at all)."""
    global _RULE_MESSAGES
    if _RULE_MESSAGES is None:
        table: dict[str, str] = {}
        for name, fn in globals().items():
            doc = getattr(fn, "__doc__", None) if name.startswith("check_") and callable(fn) else None
            if not doc:
                continue
            rid, sep, rest = doc.strip().splitlines()[0].partition(":")
            if sep and rid.strip():
                table[rid.strip()] = _PLAN_REF_RE.sub("", rest.strip()).rstrip(".")[:600]
        _RULE_MESSAGES = table
    return _RULE_MESSAGES.get(rule_id, "")


# ── TON-RPL: replay protection (plan 06 4.5) ─────────────────────────────

_SEQNO_STORE_RE = re.compile(r"store_uint\s*\(\s*seqno|set_seqno|seqno\s*=\s*|\.seqno\s*=", re.IGNORECASE)
_VALID_UNTIL_RE = re.compile(r"valid_until|validUntil|expireAt", re.IGNORECASE)
_ACCEPT_RE = re.compile(r"\baccept_message\b|\bACCEPT\b")
_SEQNO_CHECK_RE = re.compile(r"(==\s*seqno|seqno\s*==|check_seqno|slice_bits.*seqno)", re.IGNORECASE)
_EXTERNAL_HANDLER_RE = re.compile(r"recv_external|onExternalMessage", re.IGNORECASE)
_SIGNATURE_CHECK_RE = re.compile(r"check_signature|check_data_signature|ed25519_check_signature", re.IGNORECASE)


def check_ton_rpl_01(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-RPL-01: accept_message before signature and seqno checks (plan 06 4.5, F23)."""
    leads = []
    for path, source in files.items():
        lines = _lines_with_numbers(source)
        in_ext_handler = False
        sig_seen = False
        seqno_seen = False

        for lineno, text in lines:
            if _EXTERNAL_HANDLER_RE.search(text):
                in_ext_handler = True
                sig_seen = False
                seqno_seen = False
                continue
            if not in_ext_handler:
                continue
            if _SIGNATURE_CHECK_RE.search(text):
                sig_seen = True
            if _SEQNO_CHECK_RE.search(text):
                seqno_seen = True
            if _ACCEPT_RE.search(text) and not (sig_seen and seqno_seen):
                leads.append(_raw_lead("TON-RPL-01", path, lineno, lineno, "error"))
                in_ext_handler = False  # report once per handler

    return leads


def check_ton_rpl_02(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-RPL-02: no persisted seqno increment or no valid_until (plan 06 4.5)."""
    leads = []
    for path, source in files.items():
        if not _EXTERNAL_HANDLER_RE.search(source):
            continue
        lines = _lines_with_numbers(source)
        has_seqno_store = bool(_SEQNO_STORE_RE.search(source))
        has_valid_until = bool(_VALID_UNTIL_RE.search(source))
        if not has_seqno_store:
            ext_matches = _search_lines(_EXTERNAL_HANDLER_RE, lines)
            for lineno, _ in ext_matches:
                leads.append(_raw_lead("TON-RPL-02", path, lineno, lineno, "warning"))
        if not has_valid_until and _EXTERNAL_HANDLER_RE.search(source):
            ext_matches = _search_lines(_EXTERNAL_HANDLER_RE, lines)
            for lineno, _ in ext_matches:
                leads.append(_raw_lead("TON-RPL-02", path, lineno, lineno, "note"))
    return leads


# ── TON-AUTH: authentication (plan 06 4.5) ──────────────────────────────

_SENDER_AUTH_RE = re.compile(r"(sender\(\)|msg\.sender|get_sender|slice_hash.*owner|owner.*equal|equal_slices.*sender)", re.IGNORECASE)
_PRIVILEGED_OP_RE = re.compile(r"(set_code|SETCODE|raw_reserve|send_raw_message.*128|deploy_contract|transfer.*admin|op::withdraw|op::upgrade)", re.IGNORECASE)


def check_ton_auth_01(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-AUTH-01: privileged op without sender equality check (plan 06 4.5)."""
    leads = []
    for path, source in files.items():
        lines = _lines_with_numbers(source)
        # Heuristic: find blocks around privileged ops and check for nearby sender checks
        for lineno, text in lines:
            if _PRIVILEGED_OP_RE.search(text):
                # Check window of ±5 lines for sender check
                window_start = max(0, lineno - 6)
                window_end = min(len(lines) - 1, lineno + 4)
                window_text = " ".join(t for _, t in lines[window_start:window_end])
                if not _SENDER_AUTH_RE.search(window_text):
                    leads.append(_raw_lead("TON-AUTH-01", path, lineno, lineno, "warning"))
    return leads


# ── TON-MODE: send mode issues (plan 06 4.5, F20) ────────────────────────

_MODE_128_RE = re.compile(r"send_raw_message.*,\s*128\b|SendMode\.DestroyAccount|mode\s*==?\s*128", re.IGNORECASE)
_OWNER_CHECK_NEAR_RE = re.compile(r"(equal_slices|throw_unless.*owner|require.*sender|sender.*==|==.*sender)", re.IGNORECASE)
_MODE_64_RE = re.compile(r"send_raw_message.*,\s*64\b|SendMode\.CarryAllRemainingValue|mode\s*==?\s*64", re.IGNORECASE)
_RESERVE_RE = re.compile(r"raw_reserve\s*\(|rawReserve\s*\(|reserve_balance", re.IGNORECASE)
_SEND_AFTER_64_128_RE = re.compile(r"send_raw_message|sendMessage|nativeSendMessage", re.IGNORECASE)


def check_ton_mode_01(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-MODE-01: mode 128 reachable without owner sender check (plan 06 4.5)."""
    leads = []
    for path, source in files.items():
        lines = _lines_with_numbers(source)
        for lineno, text in lines:
            if _MODE_128_RE.search(text):
                window_start = max(0, lineno - 10)
                window_text = " ".join(t for _, t in lines[window_start:lineno])
                if not _OWNER_CHECK_NEAR_RE.search(window_text):
                    leads.append(_raw_lead("TON-MODE-01", path, lineno, lineno, "warning"))
    return leads


def check_ton_gas_03(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-GAS-03: mode 64 or 128 without storage reserve (plan 06 4.5)."""
    leads = []
    for path, source in files.items():
        lines = _lines_with_numbers(source)
        has_reserve = bool(_RESERVE_RE.search(source))
        if has_reserve:
            continue
        for lineno, text in lines:
            if _MODE_64_RE.search(text) or _MODE_128_RE.search(text):
                leads.append(_raw_lead("TON-GAS-03", path, lineno, lineno, "note"))
    return leads


def check_ton_mode_03(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-MODE-03: another send follows a mode 64 or 128 send (plan 06 4.5)."""
    leads = []
    for path, source in files.items():
        lines = _lines_with_numbers(source)
        mode_64_128_seen = False
        for lineno, text in lines:
            if _MODE_64_RE.search(text) or _MODE_128_RE.search(text):
                mode_64_128_seen = True
            elif mode_64_128_seen and _SEND_AFTER_64_128_RE.search(text):
                leads.append(_raw_lead("TON-MODE-03", path, lineno, lineno, "error"))
                mode_64_128_seen = False
    return leads


# ── TON-BNC: bounce handling (plan 06 4.5, F26) ──────────────────────────

_BOUNCEABLE_SEND_RE = re.compile(r"(send_raw_message|sendMessage|nativeSendMessage).*bounceable|flags.*0x18|\.bounce\s*=\s*true", re.IGNORECASE)
_BOUNCE_HANDLER_RE = re.compile(r"onBounce\s*\(|bounced\s*\{|recv_bounced|0xffffffff", re.IGNORECASE)


def check_ton_bnc_01(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-BNC-01: bounceable send after changing value fields, no bounced handler (plan 06 4.5)."""
    leads = []
    has_bounce_handler = any(_BOUNCE_HANDLER_RE.search(src) for src in files.values())
    if has_bounce_handler:
        return leads
    for path, source in files.items():
        lines = _lines_with_numbers(source)
        for lineno, text in lines:
            if _BOUNCEABLE_SEND_RE.search(text):
                leads.append(_raw_lead("TON-BNC-01", path, lineno, lineno, "warning"))
    return leads


# ── TON-GAS: gas management (plan 06 4.5, F23) ───────────────────────────

_MSG_VALUE_RE = re.compile(r"msg_value\(\)|get_incoming_value|message_value|context\(\)\.value", re.IGNORECASE)
_STATE_CHANGE_RE = re.compile(r"(set_data|save_data|emit|send_raw_message|commit\(\))", re.IGNORECASE)
_LOOP_RE = re.compile(r"\brepeat\b|\bwhile\b|\bdo\b|\bfor\b|\bforEach\b", re.IGNORECASE)
_USER_COLLECTION_RE = re.compile(r"\[.*\]|\.size\(\)|\.length\b|dict_|mapOf|hashMap", re.IGNORECASE)


def check_ton_gas_01(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-GAS-01: forwards or changes state without msg_value check (plan 06 4.5)."""
    leads = []
    for path, source in files.items():
        lines = _lines_with_numbers(source)
        has_value_check = bool(_MSG_VALUE_RE.search(source))
        if has_value_check:
            continue
        for lineno, text in lines:
            if _STATE_CHANGE_RE.search(text):
                leads.append(_raw_lead("TON-GAS-01", path, lineno, lineno, "note"))
    return leads


def check_ton_gas_02(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-GAS-02: unbounded loop over user-sized collection (plan 06 4.5)."""
    leads = []
    for path, source in files.items():
        lines = _lines_with_numbers(source)
        for lineno, text in lines:
            if _LOOP_RE.search(text) and _USER_COLLECTION_RE.search(text):
                leads.append(_raw_lead("TON-GAS-02", path, lineno, lineno, "warning"))
    return leads


# ── TON-UPG: upgradability (plan 06 4.5, F20) ────────────────────────────

_SETCODE_RE = re.compile(r"\bset_code\b|\bSETCODE\b|\bsetCode\b", re.IGNORECASE)


def check_ton_upg_01(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-UPG-01: SETCODE reachable (report with guard if present) (plan 06 4.5)."""
    leads = []
    for path, source in files.items():
        lines = _lines_with_numbers(source)
        for lineno, text in lines:
            if _SETCODE_RE.search(text):
                window = max(0, lineno - 8)
                ctx = " ".join(t for _, t in lines[window:lineno])
                severity = "note" if _OWNER_CHECK_NEAR_RE.search(ctx) else "warning"
                leads.append(_raw_lead("TON-UPG-01", path, lineno, lineno, severity))
    return leads


# ── TON-RND: randomness (plan 06 4.5) ────────────────────────────────────

_RANDOM_RE = re.compile(r"\brandom\(\)|\bran\b|\bnativeRandom\b|\brandom_seed\b", re.IGNORECASE)
_RANDOMIZE_LT_RE = re.compile(r"randomize_lt\(\)|nativeRandomizeLt\(\)", re.IGNORECASE)


def check_ton_rnd_01(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-RND-01: random() decides value, or no randomize_lt (plan 06 4.5)."""
    leads = []
    for path, source in files.items():
        if not _RANDOM_RE.search(source):
            continue
        lines = _lines_with_numbers(source)
        has_randomize = bool(_RANDOMIZE_LT_RE.search(source))
        for lineno, text in lines:
            if _RANDOM_RE.search(text):
                severity = "note" if has_randomize else "warning"
                leads.append(_raw_lead("TON-RND-01", path, lineno, lineno, severity))
    return leads


# ── TON-INT: signed integer (plan 06 4.5) ─────────────────────────────────

_LOAD_INT_RE = re.compile(r"load_int\s*\(|\.loadInt\s*\(|\.loadCoins\s*\(", re.IGNORECASE)
_AMOUNT_FIELD_RE = re.compile(r"(amount|value|fee|balance|price|qty)", re.IGNORECASE)


def check_ton_int_01(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-INT-01: amount parsed as signed integer (plan 06 4.5)."""
    leads = []
    for path, source in files.items():
        lines = _lines_with_numbers(source)
        for lineno, text in lines:
            if _LOAD_INT_RE.search(text) and _AMOUNT_FIELD_RE.search(text):
                leads.append(_raw_lead("TON-INT-01", path, lineno, lineno, "warning"))
    return leads


# ── TON-AUTH-02: address parsing (plan 06 4.5) ───────────────────────────

_ADDR_COMPARE_RE = re.compile(r"(equal_slices|slice_equal|==.*addr|addr.*==)", re.IGNORECASE)
_WORKCHAIN_CHECK_RE = re.compile(r"(workchain\b|wc\b|slice_bits.*267|parse_addr|forceBasechain)", re.IGNORECASE)


def check_ton_auth_02(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-AUTH-02: address compared without workchain check (plan 06 4.5)."""
    leads = []
    for path, source in files.items():
        lines = _lines_with_numbers(source)
        for lineno, text in lines:
            if _ADDR_COMPARE_RE.search(text):
                window_start = max(0, lineno - 5)
                ctx = " ".join(t for _, t in lines[window_start:lineno + 1])
                if not _WORKCHAIN_CHECK_RE.search(ctx):
                    leads.append(_raw_lead("TON-AUTH-02", path, lineno, lineno, "note"))
    return leads


# ── TON-JET: jetton standard (plan 06 4.5, TEP-74) ───────────────────────

_INTERNAL_TRANSFER_RE = re.compile(r"internal_transfer|InternalTransfer|op::internal_transfer\b", re.IGNORECASE)
_MASTER_CHECK_RE = re.compile(r"(jetton_master|master_address|equal_slices.*jetton|from_master|is_master)", re.IGNORECASE)


def check_ton_jet_01(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-JET-01: wallet accepts internal_transfer not from master or computed wallet (plan 06 4.5)."""
    leads = []
    for path, source in files.items():
        if not _INTERNAL_TRANSFER_RE.search(source):
            continue
        lines = _lines_with_numbers(source)
        for lineno, text in lines:
            if _INTERNAL_TRANSFER_RE.search(text):
                window_start = max(0, lineno - 5)
                window_end = min(len(lines) - 1, lineno + 10)
                ctx = " ".join(t for _, t in lines[window_start:window_end])
                if not _MASTER_CHECK_RE.search(ctx):
                    leads.append(_raw_lead("TON-JET-01", path, lineno, lineno, "warning"))
    return leads


# ── TON-MODE-04: account destroy (plan 06 4.5) ───────────────────────────

_DESTROY_FLAG_RE = re.compile(r"\+\s*32\b|SendMode\.DestroyAccount|\bDESTROY\b|mode.*32\b", re.IGNORECASE)


def check_ton_mode_04(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-MODE-04: +32 destroy reachable (plan 06 4.5)."""
    leads = []
    for path, source in files.items():
        lines = _lines_with_numbers(source)
        for lineno, text in lines:
            if _DESTROY_FLAG_RE.search(text):
                leads.append(_raw_lead("TON-MODE-04", path, lineno, lineno, "note"))
    return leads


# ── Depth rules: classic TON smart-contract risk patterns ──────────────────
#
# The five checks below raise analysis depth for the recurring fund-safety and
# correctness mistakes seen in FunC/Tact/Tolk contracts. Each is high-confidence
# and language-aware: patterns that only make sense for manual-c4 languages
# (recv_internal / set_data) are gated away from Tact, whose state is persisted
# by the compiler and whose receivers dispatch by message type.

# FunC/Tolk manage the c4 persistent cell by hand; Tact auto-persists contract state.
_MANUAL_STORAGE_EXTS = (".fc", ".func", ".tolk")

# recv_internal / onInternalMessage are FunC/Tolk entrypoints; Tact uses receive(...).
_FUNC_RECV_INTERNAL_RE = re.compile(r"\brecv_internal\b|\bonInternalMessage\b", re.IGNORECASE)
_RECV_INTERNAL_ANY_RE = re.compile(r"\brecv_internal\b|\bonInternalMessage\b|\breceive\s*\(", re.IGNORECASE)
_SEND_MSG_RE = re.compile(r"send_raw_message|sendMessage|nativeSendMessage|\bself\.forward\b|\bsend\s*\(\s*SendParameters", re.IGNORECASE)

# Any evidence the contract handles a bounced message: a Tact `bounced(...)` receiver,
# the FunC `flags & 1` guard, the 0xffffffff bounced op, or a recv_bounced hook. The bounce
# word is matched only as a handler (followed by `(` or `{`), never as prose in a comment.
_BOUNCE_HANDLING_ANY_RE = re.compile(
    r"\bonBounce\s*\(|\bbounced\s*[\(\{]|recv_bounced|0xffffffff|flags\s*&\s*1\b",
    re.IGNORECASE,
)


def _is_manual_storage_file(path: str) -> bool:
    return path.lower().endswith(_MANUAL_STORAGE_EXTS)


def check_ton_bnc_02(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-BNC-02: a handler sends messages but the contract has no bounced-message handling.

    Value sent in a bounceable message can be returned by the network if the destination
    rejects it; a contract that never inspects the bounced flag silently drops that value
    (and leaves state it updated before the send inconsistent). Reported once per file when
    no bounce handling is present anywhere in the candidate (a handler may live in an include).
    """
    leads = []
    if any(_BOUNCE_HANDLING_ANY_RE.search(src) for src in files.values()):
        return leads
    for path, source in files.items():
        if not _RECV_INTERNAL_ANY_RE.search(source):
            continue
        for lineno, text in _lines_with_numbers(source):
            if _SEND_MSG_RE.search(text):
                leads.append(_raw_lead("TON-BNC-02", path, lineno, lineno, "warning"))
                break  # one per file
    return leads


_OP_PARSE_RE = re.compile(r"load_uint\s*\(\s*32\s*\)|\bop\b\s*==|==\s*\bop\b|\bop::", re.IGNORECASE)
_SENDER_READ_RE = re.compile(r"sender_address|load_msg_addr|src_addr|cs~load_msg_addr|\.loadAddress", re.IGNORECASE)
_MUTATE_RE = re.compile(r"send_raw_message|nativeSendMessage|set_data\s*\(|save_data\s*\(|set_code\s*\(", re.IGNORECASE)


def check_ton_auth_03(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-AUTH-03: recv_internal mutates state or sends with no op dispatch and no sender check.

    A FunC/Tolk internal handler that neither reads the op code nor reads/compares the message
    sender, yet performs a privileged action (send, set_data, set_code), acts on any message from
    anyone. Tact is excluded: its receive(...) handlers already dispatch by message type.
    """
    leads = []
    for path, source in files.items():
        if not _FUNC_RECV_INTERNAL_RE.search(source):
            continue
        if _OP_PARSE_RE.search(source) or _SENDER_AUTH_RE.search(source) or _SENDER_READ_RE.search(source):
            continue
        for lineno, text in _lines_with_numbers(source):
            if _MUTATE_RE.search(text):
                leads.append(_raw_lead("TON-AUTH-03", path, lineno, lineno, "warning"))
                break  # one per file
    return leads


_LOAD_DATA_RE = re.compile(r"\bload_data\s*\(|\bget_data\s*\(", re.IGNORECASE)
_STORE_DATA_RE = re.compile(r"\bset_data\s*\(|\bsave_data\s*\(|\bcommit\s*\(", re.IGNORECASE)


def check_ton_sto_01(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-STO-01 (FunC/Tolk): an internal handler reads c4 via load_data() but never persists it.

    Persistent state lives in the c4 cell; a FunC/Tolk handler that reads it (load_data/get_data)
    and updates values but never writes it back with set_data() loses every change when the
    transaction ends. Tact is excluded (the compiler persists contract fields automatically).
    """
    leads = []
    for path, source in files.items():
        if not _is_manual_storage_file(path):
            continue
        if not _FUNC_RECV_INTERNAL_RE.search(source):
            continue
        if _STORE_DATA_RE.search(source):
            continue
        for lineno, text in _lines_with_numbers(source):
            if _LOAD_DATA_RE.search(text):
                leads.append(_raw_lead("TON-STO-01", path, lineno, lineno, "warning"))
                break  # one per file
    return leads


_BALANCE_SUB_RE = re.compile(
    r"(balance|amount|value|funds|supply|total|jetton_amount|bal)\s*-(?!-|=|>)"
    r"|-=\s*"
    r"|-\s*(msg_value|amount|value|balance|jetton_amount)\b",
    re.IGNORECASE,
)
_ARITH_GUARD_RE = re.compile(
    r"throw_unless|throw_if|\brequire\b|\brequire_|\bassert\b|>=|<=|[<>]\s|\bifnot\b|\bmin\b|\bmax\b",
    re.IGNORECASE,
)


def check_ton_int_02(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-INT-02: amount/balance subtraction with no nearby bound or underflow guard.

    TVM integers are 257-bit signed, so subtracting more than is held does not wrap: it produces
    a negative balance that later serialization or comparisons mishandle, draining or bricking the
    contract. Fires when a subtraction touches a value field and no comparison/throw guard sits in
    the surrounding window.
    """
    leads = []
    for path, source in files.items():
        lines = _lines_with_numbers(source)
        for lineno, text in lines:
            if not _BALANCE_SUB_RE.search(text):
                continue
            window_start = max(0, lineno - 7)
            window_end = min(len(lines), lineno + 1)
            ctx = " ".join(t for _, t in lines[window_start:window_end])
            if not _ARITH_GUARD_RE.search(ctx):
                leads.append(_raw_lead("TON-INT-02", path, lineno, lineno, "warning"))
    return leads


def check_ton_rpl_03(files: dict[str, str]) -> list[dict[str, Any]]:
    """TON-RPL-03: recv_external verifies a signature but never checks seqno (replay).

    Signing a payload stops forgery, not replay: without comparing an incrementing seqno (or an
    equivalent nonce) a captured signed external message can be re-sent any number of times. Fires
    when an external handler checks a signature yet no seqno comparison appears in the file.
    """
    leads = []
    for path, source in files.items():
        if not _EXTERNAL_HANDLER_RE.search(source):
            continue
        if not _SIGNATURE_CHECK_RE.search(source):
            continue
        if _SEQNO_CHECK_RE.search(source):
            continue
        for lineno, text in _lines_with_numbers(source):
            if _SIGNATURE_CHECK_RE.search(text):
                leads.append(_raw_lead("TON-RPL-03", path, lineno, lineno, "warning"))
                break  # one per file
    return leads


# ── Public API ────────────────────────────────────────────────────────────

# All rule checkers in one list for easy iteration
ALL_RULES = [
    check_ton_rpl_01,
    check_ton_rpl_02,
    check_ton_rpl_03,
    check_ton_auth_01,
    check_ton_auth_03,
    check_ton_mode_01,
    check_ton_gas_03,
    check_ton_mode_03,
    check_ton_bnc_01,
    check_ton_bnc_02,
    check_ton_gas_01,
    check_ton_gas_02,
    check_ton_upg_01,
    check_ton_rnd_01,
    check_ton_int_01,
    check_ton_int_02,
    check_ton_auth_02,
    check_ton_jet_01,
    check_ton_mode_04,
    check_ton_sto_01,
]


def run_all_rules(files: dict[str, str]) -> list[dict[str, Any]]:
    """Run all soken-ton-rules on the given files. Returns list of raw leads."""
    results: list[dict[str, Any]] = []
    for checker in ALL_RULES:
        try:
            results.extend(checker(files))
        except Exception as exc:  # noqa: BLE001
            # Rule failure is non-fatal; the checker is counted as not_run for its rule_id
            import logging
            logging.getLogger(__name__).debug("rule %s failed: %s", checker.__name__, exc)
    return results
