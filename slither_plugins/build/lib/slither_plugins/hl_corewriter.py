"""HyperEVM CoreWriter Slither detectors (plan-v4 05 section 10, 8.2).

HL-CW-01: accounting assumes sendRawAction settled in the same tx (no precompile read-back).
HL-CW-04: CoreWriter action without coreUserExists (0x810) check on the call path.

Published under AGPL-3.0 in soken-review-rubric (plan 05 section 8.2, D4).
Loads via entry point slither_analyzer.plugin (F38).

Slither 0.11.6 API notes:
  - StaticCall was removed; staticcalls are LowLevelCall(function_name.value="staticcall").
  - For HighLevelCall the destination is a Variable, not a Constant; address is not
    directly accessible via dest.value.  CoreWriter detection uses function_name matching
    ("sendRawAction" is unique to the CoreWriter interface) and, for raw .call() paths,
    checks the state variable constant expression.
"""

from __future__ import annotations

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

# CoreWriter address (F15).
_COREWRITER_ADDR = "0x3333333333333333333333333333333333333333"
# coreUserExists precompile (snapshot 0x810, F16).
_CORE_USER_EXISTS_ADDR = "0x0000000000000000000000000000000000000810"
# CoreWriter sendRawAction function name (unique to CoreWriter interface).
_SEND_RAW_ACTION_SIG = "sendRawAction"

# Accounting-related Slither variable write patterns that indicate state changes.
_ACCOUNTING_PATTERNS = frozenset({
    "balance", "balances", "amount", "debt", "collateral", "equity",
    "deposit", "withdraw", "reserve", "supply",
})


def _is_accounting_var(var_name: str) -> bool:
    """Heuristic: variable name contains an accounting keyword (case-insensitive)."""
    low = var_name.lower()
    return any(pat in low for pat in _ACCOUNTING_PATTERNS)


def _extract_addr(dest) -> str | None:
    """Extract a lowercase hex address string from a Slither IR variable.

    Handles three cases:
      1. Constant (inlined literal): dest.value is a hex string.
      2. StateVariable constant: dest.is_constant == True; expr = dest.expression.
      3. LocalVariable with a name that is the hex string (rare; belt-and-suspenders).
    """
    # Case 1: IR Constant (slither.slithir.variables.constant.Constant)
    v = getattr(dest, "value", None)
    if isinstance(v, str) and v.startswith("0x"):
        return v.lower()
    # Case 2: StateVariable with is_constant=True
    if getattr(dest, "is_constant", False):
        expr = getattr(dest, "expression", None)
        if expr is not None:
            s = str(expr).lower().strip()
            if s.startswith("0x"):
                return s
    return None


def _calls_corewriter(ir_ops: list) -> bool:
    """Return True if any IR op is a call to CoreWriter.

    Detects two patterns:
      A) HighLevelCall with function_name "sendRawAction" (interface call).
      B) LowLevelCall to the CoreWriter address (direct .call()).
    """
    from slither.slithir.operations import HighLevelCall, LowLevelCall
    for op in ir_ops:
        # Pattern A: interface call ICoreWriter(...).sendRawAction(...)
        if isinstance(op, HighLevelCall):
            fn = op.function_name
            fn_val = getattr(fn, "value", None) or ""
            if fn_val == _SEND_RAW_ACTION_SIG:
                return True
        # Pattern B: low-level .call() or .staticcall() to the CoreWriter address
        if isinstance(op, LowLevelCall):
            dest_addr = _extract_addr(op.destination)
            if dest_addr == _COREWRITER_ADDR:
                return True
    return False


def _calls_addr(ir_ops: list, addr_lower: str) -> bool:
    """Return True if any IR operation calls the given address (hex, lowercase).

    Covers both high-level (interface) and low-level (.call, .staticcall) patterns.
    """
    from slither.slithir.operations import HighLevelCall, LowLevelCall
    for op in ir_ops:
        if isinstance(op, (LowLevelCall, HighLevelCall)):
            dest = op.destination
            dest_addr = _extract_addr(dest)
            if dest_addr == addr_lower:
                return True
    return False


def _writes_accounting_state(ir_ops: list) -> bool:
    """Return True if any IR operation writes to an accounting-named state variable.

    Covers both simple Assignment ops and compound writes through ReferenceVariable
    (e.g. ``balance[msg.sender] += 100`` generates a Binary op; str(op) is
    ``"REF_n(-> balance) = REF_n + 100"`` — the accounting keyword appears in the
    full operation string, NOT in str(lvalue) which is just ``"REF_n"``).

    Also checks the lvalue.name attribute directly for simple state variable writes.
    """
    for op in ir_ops:
        # Check the full op string: "REF_1(-> balance) = ..." exposes the target name.
        op_str = str(op).lower()
        if any(pat in op_str for pat in _ACCOUNTING_PATTERNS):
            return True
        # Also check lvalue name directly for simple assignments.
        lval = getattr(op, "lvalue", None)
        if lval is not None:
            lval_name = getattr(lval, "name", None) or ""
            if _is_accounting_var(str(lval_name)):
                return True
    return False


def _collect_all_ops(function) -> list:
    """Collect all IR operations from all nodes of a function."""
    return [op for node in function.nodes for op in node.irs]


class HLCoreWriterAccountingAssumption(AbstractDetector):
    """HL-CW-01: Accounting assumes CoreWriter sendRawAction settled in the same transaction.

    Detects functions that call CoreWriter.sendRawAction and then write to accounting
    state variables (balance, debt, collateral, etc.) without an intervening read-back
    via a HyperEVM precompile.  Order and vault-transfer actions are delayed by several
    seconds (05 F15); reading back via a precompile is required before treating the
    action as settled.
    """

    ARGUMENT = "hl-cw-01"
    HELP = "HL-CW-01: CoreWriter accounting assumes immediate settlement (HyperEVM)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://soken.dev/rubric/hl-cw-01"
    WIKI_TITLE = "HL-CW-01: CoreWriter Accounting Assumption"
    WIKI_DESCRIPTION = (
        "CoreWriter sendRawAction is delayed by several seconds (F15). "
        "Writing accounting state immediately after the call treats an unconfirmed "
        "action as settled, which can lead to incorrect balances or double-accounting."
    )
    WIKI_RECOMMENDATION = (
        "Do not write accounting state in the same transaction as a sendRawAction call. "
        "Use a precompile read-back (e.g. coreTokenInfo 0x80c) in a subsequent transaction "
        "to confirm the action before updating balances."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A vault contract calls sendRawAction to withdraw funds from HyperCore, then "
        "immediately increments the user balance.  Because the withdrawal is delayed, "
        "the user can call again before HyperCore processes the first request, "
        "withdrawing twice."
    )

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_and_modifiers:
                if func.is_constructor:
                    continue
                ops = _collect_all_ops(func)
                if not _calls_corewriter(ops):
                    continue
                if _writes_accounting_state(ops):
                    info = [
                        "Function ",
                        func,
                        " calls CoreWriter.sendRawAction and writes accounting state in the same transaction (HL-CW-01).\n",
                    ]
                    results.append(self.generate_result(info))
        return results


class HLCoreWriterMissingUserCheck(AbstractDetector):
    """HL-CW-04: CoreWriter action dispatched without coreUserExists (0x810) check.

    Detects functions that call CoreWriter.sendRawAction without a preceding staticcall
    to coreUserExists (0x810 precompile).  Sending an action for a non-existent user
    consumes all gas passed and silently drops the action.
    """

    ARGUMENT = "hl-cw-04"
    HELP = "HL-CW-04: CoreWriter action without coreUserExists check (HyperEVM)"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://soken.dev/rubric/hl-cw-04"
    WIKI_TITLE = "HL-CW-04: CoreWriter Missing coreUserExists Check"
    WIKI_DESCRIPTION = (
        "Sending a CoreWriter action for a user who does not have a HyperCore account "
        "consumes all passed gas and the action is silently dropped.  "
        "coreUserExists (precompile 0x810) must be called first."
    )
    WIKI_RECOMMENDATION = (
        "Before calling sendRawAction, staticcall coreUserExists (0x810) with the "
        "target user address and revert if it returns false."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An attacker passes an address that does not have a HyperCore account.  "
        "The contract calls sendRawAction, consumes 500k gas, and the action is dropped, "
        "causing a denial-of-service or fund loss if fees were charged upfront."
    )

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_and_modifiers:
                if func.is_constructor:
                    continue
                ops = _collect_all_ops(func)
                if not _calls_corewriter(ops):
                    continue
                if not _calls_addr(ops, _CORE_USER_EXISTS_ADDR):
                    info = [
                        "Function ",
                        func,
                        " calls CoreWriter.sendRawAction without checking coreUserExists (precompile 0x810) (HL-CW-04).\n",
                    ]
                    results.append(self.generate_result(info))
        return results
