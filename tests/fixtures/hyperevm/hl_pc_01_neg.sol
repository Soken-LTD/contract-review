// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HL-PC-01 negative fixture: price precompile value has bounds check before use.
// Expected: HL-PC-01 does NOT fire.

contract HLPc01Neg {
    address constant PERP_MARK_PRICE = 0x0000000000000000000000000000000000000800;
    uint256 constant MIN_PRICE = 1e6;    // $0.01
    uint256 constant MAX_PRICE = 1e14;   // $1M

    function liquidate(address user) external returns (uint256 debt) {
        (bool ok, bytes memory raw) = PERP_MARK_PRICE.staticcall{gas: 50000}(abi.encode(uint32(0)));
        require(ok, "precompile failed");
        uint256 price = abi.decode(raw, (uint256));
        require(price >= MIN_PRICE && price <= MAX_PRICE, "price out of bounds"); // bound check OK
        debt = price * 1e18 / 1e8;
    }
}
