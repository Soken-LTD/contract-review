"""Soken Slither plugin package (plan-v4 05 section 8.2): HL-* detectors; TRON shim in tron_shim/.

Detectors loaded by Slither via entry point `slither_analyzer.plugin` (F38):
  hl-cw-01  HL-CW-01: CoreWriter accounting assumption (evm.hyperevm.corewriter)
  hl-cw-04  HL-CW-04: CoreWriter missing coreUserExists check (evm.hyperevm.corewriter)
  hl-pc-01  HL-PC-01: Price precompile without bound/freshness check (evm.hyperevm.precompile)
  hl-pc-02  HL-PC-02: Precompile call without gas cap / caller-chosen index (evm.hyperevm.precompile)
  hl-br-01  HL-BR-01: Bridge decimals unchecked (evm.hyperevm.bridge_decimals)
  hl-lk-02  HL-LK-02: Finalizer slot writable after deploy (evm.hyperevm.linking)

Published under AGPL-3.0 (plan 05 section 8.2, D4).
Slither files are unmodified; detectors load through the public entry point only (05 8.2).
"""

from __future__ import annotations


def make_plugin() -> tuple[list, list]:
    """Entry point for slither_analyzer.plugin (F38): Slither unpacks (detectors, printers).

    Imports are local so `slither_plugins.tron_shim` loads without importing the detectors.

    Side-effect: apply_tron_shim() is called here so that the TRON type patches
    (trcToken, msg.tokenid, msg.tokenvalue) are active before Slither parses any
    source files (05 section 8.2, F23).  This is harmless for non-TRON analysis:
    the extra types are simply never encountered in EVM Solidity code.
    """
    from slither_plugins.hl_bridge import HLBridgeDecimalsUnchecked
    from slither_plugins.hl_corewriter import HLCoreWriterAccountingAssumption, HLCoreWriterMissingUserCheck
    from slither_plugins.hl_linking import HLLinkingFinalizerSlotWritable
    from slither_plugins.hl_precompile import HLPrecompileGasOrIndex, HLPrecompilePriceUnbounded
    from slither_plugins.tron_shim.shim import apply_tron_shim

    apply_tron_shim()

    return [
        HLCoreWriterAccountingAssumption,
        HLCoreWriterMissingUserCheck,
        HLPrecompilePriceUnbounded,
        HLPrecompileGasOrIndex,
        HLBridgeDecimalsUnchecked,
        HLLinkingFinalizerSlotWritable,
    ], []
