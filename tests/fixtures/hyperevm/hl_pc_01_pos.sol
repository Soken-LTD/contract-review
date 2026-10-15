// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HL-PC-01 positive fixture: price precompile value used without bounds check.
// Expected: HL-PC-01 fires.

contract HLPc01Pos {
    address constant PERP_MARK_PRICE = 0x0000000000000000000000000000000000000800;

    // Bug: price used directly in liquidation math without min/max bounds.
    function liquidate(address user) external returns (uint256 debt) {
        (bool ok, bytes memory raw) = PERP_MARK_PRICE.staticcall(abi.encode(uint32(0)));
        require(ok, "precompile failed");
        uint256 price = abi.decode(raw, (uint256));
        // No bounds check! Vulnerable to extreme oracle values. -- HL-PC-01
        debt = price * 1e18 / 1e8;
    }
}
