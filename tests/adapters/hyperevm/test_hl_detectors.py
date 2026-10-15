"""Unit tests for HyperEVM Slither plugin detectors (plan-v4 05 section 10, 8.2).

Each HL-* detector is tested with a positive fixture (bug present) and a negative
fixture (no bug) via mock Slither IR objects.  Full Slither compilation is not
required; the tests exercise the detector logic directly.

Fixtures in tests/fixtures/hyperevm/ are the expected-input Solidity files.
The positive and negative distinction is documented in each fixture file.

Tests are structured as:
  test_<rule>_attributes: verify ARGUMENT, IMPACT, CONFIDENCE, etc.
  test_<rule>_positive: mock IR where the bug is present; detector fires.
  test_<rule>_negative: mock IR where the bug is absent; detector does not fire.

Slither 0.11.6 API notes used throughout:
  - StaticCall does NOT exist; staticcalls are LowLevelCall(function_name.value="staticcall").
  - HighLevelCall.function_name is a Constant whose .value is the function name string.
  - LowLevelCall.destination is a Variable; address extracted via dest.value (Constant) or
    dest.expression (StateVariable with is_constant=True).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

_FIXTURES = Path(__file__).parents[2] / "fixtures" / "hyperevm"

# ---------------------------------------------------------------------------
# Skip guard: Slither not installed in the base dev environment.
# The tests require slither-analyzer; skip gracefully if absent.
# ---------------------------------------------------------------------------
pytest.importorskip("slither", reason="slither-analyzer not installed; skipping HL detector tests")

from slither.detectors.abstract_detector import DetectorClassification

# ---------------------------------------------------------------------------
# Helpers: minimal mock Slither IR objects matching Slither 0.11.6 API
# ---------------------------------------------------------------------------


def _mock_contract(name: str) -> MagicMock:
    c = MagicMock()
    c.name = name
    return c


def _mock_function(name: str, is_constructor: bool = False, visibility: str = "public") -> MagicMock:
    f = MagicMock()
    f.name = name
    f.is_constructor = is_constructor
    f.visibility = visibility
    f.parameters = []
    f.nodes = []
    return f


def _mock_lowlevel_call(dest_value: str | None = None, fn_name: str = "call") -> MagicMock:
    """Simulate a LowLevelCall IR op.

    Args:
        dest_value: hex address string placed on dest.value (simulates IR Constant).
        fn_name: call type; "call", "staticcall", "delegatecall".
    """
    from slither.slithir.operations import LowLevelCall
    op = MagicMock(spec=LowLevelCall)
    dest = MagicMock()
    dest.value = dest_value  # simulates Constant variable
    dest.is_constant = False  # not a StateVariable constant in mock
    op.destination = dest
    fn_const = MagicMock()
    fn_const.value = fn_name
    op.function_name = fn_const
    op.call_gas = None
    op.arguments = []
    return op


def _mock_highlevel_call(dest_value: str | None = None, fn_name: str = "sendRawAction") -> MagicMock:
    """Simulate a HighLevelCall IR op.

    Args:
        dest_value: hex address placed on dest.value.
        fn_name: Solidity function name (e.g. "sendRawAction", "transfer").
    """
    from slither.slithir.operations import HighLevelCall
    op = MagicMock(spec=HighLevelCall)
    dest = MagicMock()
    dest.value = dest_value
    dest.is_constant = False
    op.destination = dest
    fn_const = MagicMock()
    fn_const.value = fn_name
    op.function_name = fn_const
    op.call_gas = None
    op.arguments = []
    return op


def _mock_assignment(lvalue_name: str, is_state_var: bool = False) -> MagicMock:
    """Simulate an Assignment IR op with the given lvalue name.

    Args:
        lvalue_name: the lvalue variable name.
        is_state_var: if True, the lvalue will be spec'd as StateVariable so that
            isinstance checks in detectors pass.  Use True for HL-LK-02 positive tests.
    """
    from slither.slithir.operations import Assignment
    op = MagicMock(spec=Assignment)
    if is_state_var:
        from slither.core.variables.state_variable import StateVariable
        lval = MagicMock(spec=StateVariable)
    else:
        lval = MagicMock()
    lval.name = lvalue_name
    op.lvalue = lval
    return op


def _mock_condition() -> MagicMock:
    """Simulate a Condition IR op."""
    from slither.slithir.operations import Condition
    return MagicMock(spec=Condition)


def _mock_node(ir_ops: list) -> MagicMock:
    node = MagicMock()
    node.irs = ir_ops
    node.sons = []
    return node


def _mock_compilation_unit(contracts: list) -> MagicMock:
    cu = MagicMock()
    cu.contracts_derived = contracts
    return cu


def _make_detector(cls, compilation_unit: MagicMock) -> MagicMock:
    """Instantiate a detector bypassing Slither constructor."""
    det = object.__new__(cls)
    det.compilation_unit = compilation_unit
    det.slither = MagicMock()
    det.logger = MagicMock()
    det.generate_result = lambda info: {"info": info}
    return det


# ---------------------------------------------------------------------------
# Fixtures exist
# ---------------------------------------------------------------------------

def test_fixtures_exist():
    for name in [
        "hl_cw_01_pos.sol", "hl_cw_01_neg.sol",
        "hl_cw_04_pos.sol", "hl_cw_04_neg.sol",
        "hl_pc_01_pos.sol", "hl_pc_01_neg.sol",
        "hl_br_01_pos.sol", "hl_br_01_neg.sol",
        "hl_lk_02_pos.sol", "hl_lk_02_neg.sol",
    ]:
        assert (_FIXTURES / name).exists(), f"fixture {name} missing"


# ---------------------------------------------------------------------------
# HL-CW-01
# ---------------------------------------------------------------------------

def test_hl_cw_01_attributes():
    from slither_plugins.hl_corewriter import HLCoreWriterAccountingAssumption
    assert HLCoreWriterAccountingAssumption.ARGUMENT == "hl-cw-01"
    assert HLCoreWriterAccountingAssumption.IMPACT == DetectorClassification.HIGH
    assert HLCoreWriterAccountingAssumption.CONFIDENCE == DetectorClassification.MEDIUM


def test_hl_cw_01_positive_via_highlevel():
    """Positive: HighLevelCall(sendRawAction) + accounting write -> fires.

    Note: _writes_accounting_state checks str(op) not isinstance(lval, StateVariable),
    so the mock just needs str(op) to contain "balance".
    """
    from slither_plugins.hl_corewriter import HLCoreWriterAccountingAssumption

    cw_call = _mock_highlevel_call(fn_name="sendRawAction")
    accounting_write = _mock_assignment("balance")

    func = _mock_function("deposit")
    node = _mock_node([cw_call, accounting_write])
    func.nodes = [node]

    contract = _mock_contract("VaultPos")
    contract.functions_and_modifiers = [func]

    det = _make_detector(HLCoreWriterAccountingAssumption, _mock_compilation_unit([contract]))
    results = det._detect()
    assert len(results) >= 1, "HL-CW-01 should fire: sendRawAction + accounting write"


def test_hl_cw_01_positive_via_lowlevel():
    """Positive: LowLevelCall to CoreWriter address + accounting write -> fires."""
    from slither_plugins.hl_corewriter import HLCoreWriterAccountingAssumption

    cw_call = _mock_lowlevel_call(dest_value="0x3333333333333333333333333333333333333333")
    accounting_write = _mock_assignment("balances")

    func = _mock_function("deposit2")
    node = _mock_node([cw_call, accounting_write])
    func.nodes = [node]

    contract = _mock_contract("VaultPos2")
    contract.functions_and_modifiers = [func]

    det = _make_detector(HLCoreWriterAccountingAssumption, _mock_compilation_unit([contract]))
    results = det._detect()
    assert len(results) >= 1, "HL-CW-01 should fire: raw CoreWriter call + accounting write"


def test_hl_cw_01_negative():
    """Negative: sendRawAction call with no accounting write -> does not fire."""
    from slither_plugins.hl_corewriter import HLCoreWriterAccountingAssumption

    cw_call = _mock_highlevel_call(fn_name="sendRawAction")

    func = _mock_function("sendAction")
    node = _mock_node([cw_call])
    func.nodes = [node]

    contract = _mock_contract("VaultNeg")
    contract.functions_and_modifiers = [func]

    det = _make_detector(HLCoreWriterAccountingAssumption, _mock_compilation_unit([contract]))
    results = det._detect()
    assert len(results) == 0, "HL-CW-01 should not fire: sendRawAction with no accounting write"


# ---------------------------------------------------------------------------
# HL-CW-04
# ---------------------------------------------------------------------------

def test_hl_cw_04_attributes():
    from slither_plugins.hl_corewriter import HLCoreWriterMissingUserCheck
    assert HLCoreWriterMissingUserCheck.ARGUMENT == "hl-cw-04"
    assert HLCoreWriterMissingUserCheck.IMPACT == DetectorClassification.MEDIUM


def test_hl_cw_04_positive():
    """Positive: sendRawAction without coreUserExists call -> fires."""
    from slither_plugins.hl_corewriter import HLCoreWriterMissingUserCheck

    cw_call = _mock_highlevel_call(fn_name="sendRawAction")
    func = _mock_function("placeOrder")
    node = _mock_node([cw_call])
    func.nodes = [node]

    contract = _mock_contract("OrderPos")
    contract.functions_and_modifiers = [func]

    det = _make_detector(HLCoreWriterMissingUserCheck, _mock_compilation_unit([contract]))
    results = det._detect()
    assert len(results) >= 1, "HL-CW-04 should fire: no coreUserExists check"


def test_hl_cw_04_negative():
    """Negative: sendRawAction with a prior staticcall to 0x810 -> does not fire."""
    from slither_plugins.hl_corewriter import HLCoreWriterMissingUserCheck

    # LowLevelCall to coreUserExists (0x810) as staticcall
    user_exists = _mock_lowlevel_call(
        dest_value="0x0000000000000000000000000000000000000810",
        fn_name="staticcall",
    )
    cw_call = _mock_highlevel_call(fn_name="sendRawAction")

    func = _mock_function("placeOrderSafe")
    node = _mock_node([user_exists, cw_call])
    func.nodes = [node]

    contract = _mock_contract("OrderNeg")
    contract.functions_and_modifiers = [func]

    det = _make_detector(HLCoreWriterMissingUserCheck, _mock_compilation_unit([contract]))
    results = det._detect()
    assert len(results) == 0, "HL-CW-04 should not fire: coreUserExists called"


# ---------------------------------------------------------------------------
# HL-PC-01
# ---------------------------------------------------------------------------

def test_hl_pc_01_attributes():
    from slither_plugins.hl_precompile import HLPrecompilePriceUnbounded
    assert HLPrecompilePriceUnbounded.ARGUMENT == "hl-pc-01"
    assert HLPrecompilePriceUnbounded.IMPACT == DetectorClassification.HIGH


def test_hl_pc_01_positive():
    """Positive: price precompile staticcall, no Condition successor -> fires."""
    from slither_plugins.hl_precompile import HLPrecompilePriceUnbounded

    price_call = _mock_lowlevel_call(
        dest_value="0x0000000000000000000000000000000000000800",
        fn_name="staticcall",
    )
    call_node = _mock_node([price_call])
    call_node.sons = []  # no condition successors

    func = _mock_function("liquidate")
    func.nodes = [call_node]

    contract = _mock_contract("LiquidatorPos")
    contract.functions_and_modifiers = [func]

    det = _make_detector(HLPrecompilePriceUnbounded, _mock_compilation_unit([contract]))
    results = det._detect()
    assert len(results) >= 1, "HL-PC-01 should fire: price precompile without bound check"


def test_hl_pc_01_negative():
    """Negative: price precompile with a subsequent Condition -> does not fire."""
    from slither_plugins.hl_precompile import HLPrecompilePriceUnbounded

    price_call = _mock_lowlevel_call(
        dest_value="0x0000000000000000000000000000000000000800",
        fn_name="staticcall",
    )
    check_node = _mock_node([_mock_condition()])
    check_node.sons = []

    call_node = _mock_node([price_call])
    call_node.sons = [check_node]

    func = _mock_function("liquidateSafe")
    func.nodes = [call_node, check_node]

    contract = _mock_contract("LiquidatorNeg")
    contract.functions_and_modifiers = [func]

    det = _make_detector(HLPrecompilePriceUnbounded, _mock_compilation_unit([contract]))
    results = det._detect()
    assert len(results) == 0, "HL-PC-01 should not fire: bound check condition present"


# ---------------------------------------------------------------------------
# HL-PC-02
# ---------------------------------------------------------------------------

def test_hl_pc_02_attributes():
    from slither_plugins.hl_precompile import HLPrecompileGasOrIndex
    assert HLPrecompileGasOrIndex.ARGUMENT == "hl-pc-02"
    assert HLPrecompileGasOrIndex.IMPACT == DetectorClassification.MEDIUM


def test_hl_pc_02_positive_no_gas_cap():
    """Positive: precompile staticcall with no call_gas -> fires."""
    from slither_plugins.hl_precompile import HLPrecompileGasOrIndex

    op = _mock_lowlevel_call(
        dest_value="0x0000000000000000000000000000000000000806",
        fn_name="staticcall",
    )
    # call_gas is None (not a Constant) -> no gas cap
    op.call_gas = None

    func = _mock_function("getPosition")
    node = _mock_node([op])
    func.nodes = [node]

    contract = _mock_contract("PositionReader")
    contract.functions_and_modifiers = [func]

    det = _make_detector(HLPrecompileGasOrIndex, _mock_compilation_unit([contract]))
    results = det._detect()
    assert len(results) >= 1, "HL-PC-02 should fire: no constant gas cap"


def test_hl_pc_02_negative_constant_gas():
    """Negative: precompile staticcall with a Constant gas value -> does not fire."""
    from slither.slithir.variables import Constant

    from slither_plugins.hl_precompile import HLPrecompileGasOrIndex

    op = _mock_lowlevel_call(
        dest_value="0x0000000000000000000000000000000000000806",
        fn_name="staticcall",
    )
    # Constant gas value
    gas_const = MagicMock(spec=Constant)
    gas_const.__class__ = Constant
    op.call_gas = gas_const
    op.arguments = []

    func = _mock_function("getPositionSafe")
    func.parameters = []
    node = _mock_node([op])
    func.nodes = [node]

    contract = _mock_contract("PositionReaderSafe")
    contract.functions_and_modifiers = [func]

    det = _make_detector(HLPrecompileGasOrIndex, _mock_compilation_unit([contract]))
    results = det._detect()
    assert len(results) == 0, "HL-PC-02 should not fire: constant gas, no caller index"


# ---------------------------------------------------------------------------
# HL-BR-01
# ---------------------------------------------------------------------------

def test_hl_br_01_attributes():
    from slither_plugins.hl_bridge import HLBridgeDecimalsUnchecked
    assert HLBridgeDecimalsUnchecked.ARGUMENT == "hl-br-01"
    assert HLBridgeDecimalsUnchecked.IMPACT == DetectorClassification.HIGH


def test_hl_br_01_positive():
    """Positive: HYPE transfer in a function with no rounding op -> fires."""
    from slither_plugins.hl_bridge import HLBridgeDecimalsUnchecked

    op = _mock_highlevel_call(
        dest_value="0x2222222222222222222222222222222222222222",
        fn_name="transfer",
    )

    func = _mock_function("depositHype")
    node = _mock_node([op])
    node.sons = []
    func.nodes = [node]

    contract = _mock_contract("StakePos")
    contract.functions_and_modifiers = [func]

    det = _make_detector(HLBridgeDecimalsUnchecked, _mock_compilation_unit([contract]))
    results = det._detect()
    assert len(results) >= 1, "HL-BR-01 should fire: HYPE transfer without rounding"


def test_hl_br_01_negative():
    """Negative: transfer with a 'mod' op in the function -> does not fire."""
    from slither_plugins.hl_bridge import HLBridgeDecimalsUnchecked

    op = _mock_highlevel_call(
        dest_value="0x2222222222222222222222222222222222222222",
        fn_name="transfer",
    )

    # Add a mock op whose str representation contains "mod" to simulate rounding.
    rounding_op = MagicMock()
    rounding_op.__str__ = lambda self: "TMP = amount mod precision"

    func = _mock_function("depositHypeSafe")
    node = _mock_node([op])
    node.sons = []
    rounding_node = _mock_node([rounding_op])
    func.nodes = [node, rounding_node]

    contract = _mock_contract("StakeNeg")
    contract.functions_and_modifiers = [func]

    det = _make_detector(HLBridgeDecimalsUnchecked, _mock_compilation_unit([contract]))
    results = det._detect()
    assert len(results) == 0, "HL-BR-01 should not fire: rounding pattern present"


# ---------------------------------------------------------------------------
# HL-LK-02
# ---------------------------------------------------------------------------

def test_hl_lk_02_attributes():
    from slither_plugins.hl_linking import HLLinkingFinalizerSlotWritable
    assert HLLinkingFinalizerSlotWritable.ARGUMENT == "hl-lk-02"
    assert HLLinkingFinalizerSlotWritable.IMPACT == DetectorClassification.HIGH


def test_hl_lk_02_positive():
    """Positive: public function with Assignment to 'deployer' StateVariable -> fires."""
    from slither_plugins.hl_linking import HLLinkingFinalizerSlotWritable

    write_op = _mock_assignment("deployer", is_state_var=True)  # StateVariable write
    func = _mock_function("setDeployer", is_constructor=False, visibility="external")
    node = _mock_node([write_op])
    func.nodes = [node]

    contract = _mock_contract("LinkPos")
    contract.functions_and_modifiers = [func]

    det = _make_detector(HLLinkingFinalizerSlotWritable, _mock_compilation_unit([contract]))
    results = det._detect()
    assert len(results) >= 1, "HL-LK-02 should fire: deployer var written post-construction"


def test_hl_lk_02_negative():
    """Negative: only constructor writes 'deployer' StateVariable -> no fire."""
    from slither_plugins.hl_linking import HLLinkingFinalizerSlotWritable

    write_op = _mock_assignment("deployer", is_state_var=True)  # StateVariable but in constructor
    constructor = _mock_function("constructor", is_constructor=True, visibility="public")
    node = _mock_node([write_op])
    constructor.nodes = [node]

    contract = _mock_contract("LinkNeg")
    contract.functions_and_modifiers = [constructor]

    det = _make_detector(HLLinkingFinalizerSlotWritable, _mock_compilation_unit([contract]))
    results = det._detect()
    assert len(results) == 0, "HL-LK-02 should not fire: only constructor writes deployer"


# ---------------------------------------------------------------------------
# make_plugin
# ---------------------------------------------------------------------------

def test_make_plugin_returns_all_detectors():
    """Verify make_plugin() returns (detectors, []) with all 6 HL detector classes."""
    from slither_plugins import make_plugin
    detectors, printers = make_plugin()
    assert printers == []
    assert len(detectors) == 6
    args = {d.ARGUMENT for d in detectors}
    assert args == {"hl-cw-01", "hl-cw-04", "hl-pc-01", "hl-pc-02", "hl-br-01", "hl-lk-02"}
