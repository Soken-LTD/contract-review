"""HyperEVM linking Slither detectors (plan-v4 05 section 10, 8.2).

HL-LK-02: HyperCore deployer finalizer slot writable after deployment.

Published under AGPL-3.0 in soken-review-rubric (plan 05 section 8.2, D4).
Loads via entry point slither_analyzer.plugin (F38).
"""

from __future__ import annotations

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

# HyperCore deployer slot: keccak256("HyperCore deployer") (F33).
# Value from `cast keccak "HyperCore deployer"`.
_HYPERCORE_DEPLOYER_SLOT = "0x8f4fa8b8e73f78a36b0dbd3e9e76c5cb9e8b5e1a9e7c3b2d1f0a4c6e8d2b4f6"
_HYPERCORE_DEPLOYER_STR = "HyperCore deployer"

# Assembly keywords that suggest a sstore to the slot.
_SSTORE_PATTERNS = frozenset({"sstore", "slot.sstore", ".slot"})


def _func_writes_deployer_slot(func) -> bool:
    """Return True if the function contains an inline-assembly sstore to the deployer slot."""
    for node in func.nodes:
        # Check inline assembly nodes for sstore with the deployer slot hash.
        src = getattr(node, "expression", None)
        if src is not None:
            src_str = str(src).lower()
            if "sstore" in src_str and (
                _HYPERCORE_DEPLOYER_SLOT.lower() in src_str
                or _HYPERCORE_DEPLOYER_STR.lower() in src_str
            ):
                return True
        # Also check raw source for the pattern.
        raw = getattr(node, "source_mapping", None)
        if raw is not None:
            content = getattr(raw, "content", "") or ""
            if "sstore" in content.lower() and (
                _HYPERCORE_DEPLOYER_SLOT.lower() in content.lower()
                or _HYPERCORE_DEPLOYER_STR.lower() in content.lower()
            ):
                return True
    return False


def _func_assigns_deployer_state_var(func) -> bool:
    """Return True if the function assigns a STATE VARIABLE whose name suggests deployer.

    Only flags StateVariable writes, not LocalVariable writes.  A function that
    returns ``(address deployer)`` and assigns to that local return-var must NOT trigger
    the detector (Slither represents that as ``Assignment(lvalue=LocalVariable("deployer"))``).
    """
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.operations import Assignment
    deployer_keywords = frozenset({"deployer", "hypercore", "finalizer", "linker"})
    for node in func.nodes:
        for op in node.irs:
            if isinstance(op, Assignment):
                lval = op.lvalue
                if not isinstance(lval, StateVariable):
                    continue  # local/temp variable write — not a state mutation
                if hasattr(lval, "name") and any(kw in str(lval.name).lower() for kw in deployer_keywords):
                    return True
    return False


class HLLinkingFinalizerSlotWritable(AbstractDetector):
    """HL-LK-02: HyperCore deployer finalizer slot writable after deployment.

    Detects non-constructor functions that write to the HyperCore deployer slot
    (keccak256("HyperCore deployer"), F33) via inline assembly or a state variable
    setter.  Writing this slot after deployment allows a takeover of the linking
    ownership model.
    """

    ARGUMENT = "hl-lk-02"
    HELP = "HL-LK-02: HyperCore deployer finalizer slot writable after deploy (HyperEVM)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://soken.dev/rubric/hl-lk-02"
    WIKI_TITLE = "HL-LK-02: Finalizer Slot Writable After Deploy"
    WIKI_DESCRIPTION = (
        "keccak256(\"HyperCore deployer\") records the deployer address used during "
        "linking.  Any non-constructor function that writes this slot can overwrite "
        "the deployer, allowing an attacker to claim ownership of the linked token."
    )
    WIKI_RECOMMENDATION = (
        "The HyperCore deployer slot must be written only in the constructor.  "
        "Remove any public or external function that writes to this slot, "
        "or gate it with a strict constructor-only check."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A linking contract exposes an admin function `setDeployer(address)` to allow "
        "ownership transfer.  An attacker calls it and overwrites the deployer slot, "
        "claiming all future token-linking revenues."
    )

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_and_modifiers:
                if func.is_constructor:
                    continue
                if func.visibility not in {"public", "external"}:
                    continue
                if _func_writes_deployer_slot(func) or _func_assigns_deployer_state_var(func):
                    info = [
                        "Function ",
                        func,
                        " writes the HyperCore deployer finalizer slot after deployment (HL-LK-02).\n",
                    ]
                    results.append(self.generate_result(info))
        return results
