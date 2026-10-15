"""TRON chain adapter (05 sections 4.3, 6.3, 8.2, 9, 12.5).

Subclass/reuse of the EVM adapter with TRON-specific:
  - address codec (base58check T... <-> 0x41 hex, unit_label h6 per 3.4)
  - fetch: TronScan contract/info (step 1), Sourcify 728126428 (step 2)
  - TronGrid runtimecode + getchainparameters (window per 12.5)
  - tron-solc release cache (6.3)
  - Slither shim (AGPL-3.0, 8.2, F23) + TRON-* detectors
  - TRON window block attribution (12.5)
"""
