"""HyperEVM precompile Slither detectors (plan-v4 05 section 10, 8.2).

HL-PC-01: price precompile value used without bound or freshness check.
HL-PC-02: precompile call without gas cap or with caller-chosen index.

Published under AGPL-3.0 in soken-review-rubric (plan 05 section 8.2, D4).
Loads via entry point slither_analyzer.plugin (F38).

Slither 0.11.6 API notes:
  - StaticCall was removed; staticcalls are LowLevelCall(function_name.value="staticcall").
  - LowLevelCall.destination can be a StateVariable constant whose address is in
    dest.expression; extract via _extract_addr().
  - Condition is the correct class for CFG condition nodes (unchanged in 0.11.6).
"""

from __future__ import annotations

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

# Price precompile addresses (snapshot upstream/hyperevm_precompiles.json, 05 F16).
_PRICE_PRECOMPILES = frozenset({
    "0x0000000000000000000000000000000000000800",
    "0x0000000000000000000000000000000000000801",
    "0x0000000000000000000000000000000000000802",
    "0x0000000000000000000000000000000000000803",
    "0x0000000000000000000000000000000000000806",
    "0x0000000000000000000000000000000000000807",
    "0x0000000000000000000000000000000000000808",
    "0x000000000000000000000000000000000000080e",
})

# All HyperEVM precompile addresses (0x800..0x813).
_ALL_PRECOMPILES = frozenset({
    "0x0000000000000000000000000000000000000800",
    "0x0000000000000000000000000000000000000801",
    "0x0000000000000000000000000000000000000802",
    "0x0000000000000000000000000000000000000803",
    "0x0000000000000000000000000000000000000804",
    "0x0000000000000000000000000000000000000805",
    "0x0000000000000000000000000000000000000806",
    "0x0000000000000000000000000000000000000807",
    "0x0000000000000000000000000000000000000808",
    "0x0000000000000000000000000000000000000809",
    "0x000000000000000000000000000000000000080a",
    "0x000000000000000000000000000000000000080b",
    "0x000000000000000000000000000000000000080c",
    "0x000000000000000000000000000000000000080d",
    "0x000000000000000000000000000000000000080e",
    "0x000000000000000000000000000000000000080f",
    "0x0000000000000000000000000000000000000810",
    "0x0000000000000000000000000000000000000811",
    "0x0000000000000000000000000000000000000812",
    "0x0000000000000000000000000000000000000813",
})


def _extract_addr(dest) -> str | None:
    """Extract a lowercase hex address string from a Slither IR variable.

    Handles:
      1. IR Constant (slither.slithir.variables.constant.Constant): dest.value is hex str.
      2. StateVariable constant: dest.is_constant == True; read dest.expression.
    """
    # Case 1: IR Constant
    v = getattr(dest, "value", None)
    if isinstance(v, str) and v.startswith("0x"):
        return v.lower()
    # Case 2: StateVariable constant (expression holds the literal)
    if getattr(dest, "is_constant", False):
        expr = getattr(dest, "expression", None)
        if expr is not None:
            s = str(expr).lower().strip()
            if s.startswith("0x"):
                return s
    return None


def _node_calls_precompile_set(node, precompile_set: frozenset) -> bool:
    """Return True if the node makes a low-level call to an address in precompile_set.

    In Slither 0.11.6 staticcalls are LowLevelCall with function_name.value="staticcall".
    """
    from slither.slithir.operations import LowLevelCall
    for op in node.irs:
        if isinstance(op, LowLevelCall):
            fn_val = getattr(op.function_name, "value", "") or ""
            if fn_val not in ("call", "staticcall", "delegatecall"):
                continue
            dest_addr = _extract_addr(op.destination)
            if dest_addr and dest_addr in precompile_set:
                return True
    return False


def _subsequent_nodes_have_bound_check(func, call_node) -> bool:
    """Return True if any successor node contains evidence of a bounds/freshness check.

    In Slither 0.11.6, ``require(price >= MIN)`` compiles to:
      Binary(GREATER_EQUAL) then SolidityCall(require).
    There is NO ``Condition`` op — that only appears for ``if`` statements.

    We look for:
      • ``Condition`` op  (from an ``if``/ternary expression)
      • ``Binary`` op with a comparison operator (>=, <=, >, <, ==, !=)
        — this directly captures ``price >= MIN_PRICE`` even before the require.

    Returns False → detector reports the issue (err on the side of reporting).
    """
    from slither.slithir.operations import Binary, Condition
    _CMP_TYPES: frozenset
    try:
        from slither.slithir.operations.binary import BinaryType  # 0.11.6 path
        _CMP_TYPES = frozenset({
            BinaryType.GREATER, BinaryType.GREATER_EQUAL,
            BinaryType.LESS, BinaryType.LESS_EQUAL,
            BinaryType.EQUAL, BinaryType.NOT_EQUAL,
        })
    except ImportError:
        # Fallback: match by string name
        _CMP_TYPES = None  # type: ignore[assignment]

    visited: set = set()
    queue = list(call_node.sons)
    while queue:
        n = queue.pop()
        if n in visited:
            continue
        visited.add(n)
        for op in n.irs:
            if isinstance(op, Condition):
                return True
            if isinstance(op, Binary):
                if _CMP_TYPES is not None:
                    if op.type in _CMP_TYPES:
                        return True
                else:
                    # Fallback: check string representation
                    type_name = str(getattr(op.type, "name", op.type)).lower()
                    if any(c in type_name for c in ("greater", "less", "equal")):
                        return True
        queue.extend(s for s in n.sons if s not in visited)
    return False


def _gas_is_constant(call_op) -> bool:
    """Return True if the gas argument to a call is a Slither IR Constant."""
    from slither.slithir.variables import Constant
    if hasattr(call_op, "call_gas") and call_op.call_gas is not None:
        gas = call_op.call_gas
        return isinstance(gas, Constant)
    # No gas argument specified — the call will pass all available gas.
    return False


def _index_is_caller_controlled(call_op, func) -> bool:
    """Heuristic: the first argument to a precompile may be a user-supplied index.

    We check whether any of the call's arguments can be traced to a function parameter
    that is not restricted by a modifier.  This is an approximation.

    Slither 0.11.6: LocalVariable lives in slither.core.variables.local_variable,
    not in slither.slithir.variables.
    """
    from slither.core.variables.local_variable import LocalVariable  # 0.11.6 path
    if hasattr(call_op, "arguments"):
        for arg in call_op.arguments:
            if isinstance(arg, LocalVariable):
                # If the local variable originates from a function parameter, flag it.
                param_names = {p.name for p in func.parameters}
                if arg.name in param_names:
                    return True
    return False


class HLPrecompilePriceUnbounded(AbstractDetector):
    """HL-PC-01: Price precompile value used without a bound or freshness check.

    Detects staticcalls to HyperEVM price precompiles (0x806, 0x807, 0x808, 0x80e, and
    others in the price set) whose return value is used arithmetically without an
    intervening comparison / require / assert.
    """

    ARGUMENT = "hl-pc-01"
    HELP = "HL-PC-01: HyperEVM price precompile value without bound check"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://soken.dev/rubric/hl-pc-01"
    WIKI_TITLE = "HL-PC-01: Price Precompile Without Bound or Freshness Check"
    WIKI_DESCRIPTION = (
        "HyperEVM price precompiles (0x806, 0x807, 0x808, 0x80e) return oracle prices that "
        "can deviate significantly in volatile markets.  Using them without a min/max bound "
        "or staleness check can lead to incorrect liquidations or over-collateralisation."
    )
    WIKI_RECOMMENDATION = (
        "After reading a price precompile, validate the result with a min/max sanity range "
        "and consider adding a staleness threshold by tracking the last read block."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A perp lending contract reads the mark price from 0x806 without bounds.  "
        "In a flash-crash the price drops to near zero; the contract liquidates all "
        "positions incorrectly."
    )

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_and_modifiers:
                for node in func.nodes:
                    if not _node_calls_precompile_set(node, _PRICE_PRECOMPILES):
                        continue
                    if not _subsequent_nodes_have_bound_check(func, node):
                        info = [
                            "Function ",
                            func,
                            " calls a price precompile without a subsequent bound or freshness check (HL-PC-01).\n",
                        ]
                        results.append(self.generate_result(info))
        return results


class HLPrecompileGasOrIndex(AbstractDetector):
    """HL-PC-02: Precompile call without gas cap or with caller-supplied asset index.

    Invalid input to a HyperEVM precompile consumes all gas passed (F14).
    Caller-controlled index enables DoS by targeting an invalid market index.
    """

    ARGUMENT = "hl-pc-02"
    HELP = "HL-PC-02: HyperEVM precompile call without gas cap or with caller-chosen index"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://soken.dev/rubric/hl-pc-02"
    WIKI_TITLE = "HL-PC-02: Precompile Gas Cap or Caller-Index Missing"
    WIKI_DESCRIPTION = (
        "HyperEVM precompiles consume all passed gas on invalid input (F14).  "
        "A call with all available gas will brick the transaction; "
        "a caller-supplied index allows DoS by choosing an invalid market."
    )
    WIKI_RECOMMENDATION = (
        "Pass a fixed gas constant (e.g. 50000) to every HyperEVM precompile call.  "
        "Validate market indices against an allowlist before passing them to the precompile."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A user passes a very large market index.  The precompile sees invalid input, "
        "consumes all 3M gas forwarded, and the transaction reverts."
    )

    def _detect(self):
        results = []
        from slither.slithir.operations import LowLevelCall
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_and_modifiers:
                for node in func.nodes:
                    for op in node.irs:
                        if not isinstance(op, LowLevelCall):
                            continue
                        fn_val = getattr(op.function_name, "value", "") or ""
                        if fn_val not in ("call", "staticcall"):
                            continue
                        dest_addr = _extract_addr(op.destination)
                        if not dest_addr or dest_addr not in _ALL_PRECOMPILES:
                            continue
                        no_gas_cap = not _gas_is_constant(op)
                        caller_index = _index_is_caller_controlled(op, func)
                        if no_gas_cap or caller_index:
                            reason = []
                            if no_gas_cap:
                                reason.append("no constant gas cap")
                            if caller_index:
                                reason.append("caller-supplied index")
                            info = [
                                "Function ",
                                func,
                                f" calls a HyperEVM precompile with {', '.join(reason)} (HL-PC-02).\n",
                            ]
                            results.append(self.generate_result(info))
        return results
