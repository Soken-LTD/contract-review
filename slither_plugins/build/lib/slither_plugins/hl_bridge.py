"""HyperEVM bridge/decimals Slither detectors (plan-v4 05 section 10, 8.2).

HL-BR-01: system-address token transfers treated as exact ERC20 sends; non-round amounts.

Published under AGPL-3.0 in soken-review-rubric (plan 05 section 8.2, D4).
Loads via entry point slither_analyzer.plugin (F38).

Slither 0.11.6 API notes:
  - StaticCall was removed; not used in this detector.
  - HighLevelCall.function_name is a Constant; its .value gives the function name string.
  - For system-token address matching, use _extract_addr() on the destination variable.
"""

from __future__ import annotations

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

# HYPE native token address (F17).
_HYPE_ADDR = "0x2222222222222222222222222222222222222222"
# WHYPE wrapper address.
_WHYPE_ADDR = "0x5555555555555555555555555555555555555555"

# System token address prefix: 0x00...00<n> where n is 1 or 2 bytes.
# The simplest heuristic: any address literal whose first 18 bytes are zero.
_SYSTEM_TOKEN_PREFIXES = (
    "0x000000000000000000000000000000000000",  # 18 leading zero-bytes
)

_ROUNDING_PATTERNS = frozenset({
    "truncat", "floor", "round", "mod", "%", "decimals", "precision",
})


def _is_system_token_addr(addr_str: str) -> bool:
    """Return True if the address looks like a HyperCore system token (0x00..00xx)."""
    low = addr_str.lower()
    if low in (_HYPE_ADDR, _WHYPE_ADDR):
        return True
    return any(low.startswith(prefix.lower()) for prefix in _SYSTEM_TOKEN_PREFIXES)


def _extract_addr(dest) -> str | None:
    """Extract a lowercase hex address string from a Slither IR variable.

    Handles IR Constant (dest.value) and StateVariable constant (dest.expression).
    """
    v = getattr(dest, "value", None)
    if isinstance(v, str) and v.startswith("0x"):
        return v.lower()
    if getattr(dest, "is_constant", False):
        expr = getattr(dest, "expression", None)
        if expr is not None:
            s = str(expr).lower().strip()
            if s.startswith("0x"):
                return s
    return None


def _calls_transfer(ir_op) -> bool:
    """Return True if the IR op is a high-level call matching ERC-20 transfer patterns."""
    from slither.slithir.operations import HighLevelCall
    if isinstance(ir_op, HighLevelCall):
        # function_name is a Constant in Slither 0.11.6; use .value attribute.
        fn = ir_op.function_name
        fn_val = str(getattr(fn, "value", fn) or "").lower()
        return fn_val in {"transfer", "transferfrom", "safetransfer", "safetransferfrom"}
    return False


def _transfer_target_is_system_token(ir_op, func=None) -> bool:
    """Return True if the receiver of the transfer call is a system token constant.

    Handles two cases:
      1. Destination is a Constant or StateVariable constant — direct address extraction.
      2. Destination is a TemporaryVariable from a TypeConversion (e.g. IERC20(HYPE).transfer(...)).
         Walk all IR ops in ``func`` to find the TypeConversion that produced the temp,
         then extract the address from its source variable.

    ``func`` is required for case 2; if not provided, case 2 silently returns False.
    """
    from slither.slithir.operations import TypeConversion
    dest = getattr(ir_op, "destination", None)
    if dest is None:
        return False
    # Case 1: direct constant address
    addr = _extract_addr(dest)
    if addr is not None:
        return _is_system_token_addr(addr)
    # Case 2: dest is a TemporaryVariable produced by a TypeConversion
    if func is not None:
        for node in func.nodes:
            for op in node.irs:
                # lvalue identity comparison — both reference the same TMP object
                if isinstance(op, TypeConversion) and (
                    op.lvalue is dest or str(op.lvalue) == str(dest)
                ):
                    src_addr = _extract_addr(op.variable)
                    if src_addr is not None:
                        return _is_system_token_addr(src_addr)
    return False


def _amount_has_rounding(func, call_node) -> bool:
    """Heuristic: look for a modulo or decimal-truncation operation on the transfer amount."""
    for node in func.nodes:
        for op in node.irs:
            src = str(op).lower()
            if any(pat in src for pat in _ROUNDING_PATTERNS):
                return True
    return False


class HLBridgeDecimalsUnchecked(AbstractDetector):
    """HL-BR-01: system-token transfers without rounding: non-round amounts silently burned.

    HyperCore may send a token amount to HyperEVM that includes a non-round remainder
    (relative to the EVM decimal precision); that remainder is burned.  A contract that
    trusts the calldata amount without truncating over-counts user deposits.
    """

    ARGUMENT = "hl-br-01"
    HELP = "HL-BR-01: HyperEVM system-token transfer without decimal rounding check"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://soken.dev/rubric/hl-br-01"
    WIKI_TITLE = "HL-BR-01: Bridge Decimals Unchecked"
    WIKI_DESCRIPTION = (
        "When HyperCore sends tokens to HyperEVM the amount may include a non-round "
        "remainder (F17, F42).  The remainder is burned by the protocol.  Contracts "
        "that record the raw transferred amount over-count balances."
    )
    WIKI_RECOMMENDATION = (
        "When accounting for HyperCore system-token deposits, truncate the received "
        "amount to the EVM decimal precision before recording it.  Read token decimals "
        "from the coreTokenInfo precompile (0x80c) and compute: "
        "accountedAmount = amount - (amount % 10**(coreDecimals - evmDecimals))."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A HYPE staking contract records the full transferred amount including a "
        "1-wei non-round remainder.  Over thousands of deposits the cumulative "
        "over-count allows a user to claim more HYPE than the contract actually holds."
    )

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_and_modifiers:
                for node in func.nodes:
                    for op in node.irs:
                        if not _calls_transfer(op):
                            continue
                        if not _transfer_target_is_system_token(op, func):
                            continue
                        if not _amount_has_rounding(func, node):
                            info = [
                                "Function ",
                                func,
                                " transfers system-token (HYPE/system-address) amounts without decimal rounding (HL-BR-01).\n",
                            ]
                            results.append(self.generate_result(info))
        return results
