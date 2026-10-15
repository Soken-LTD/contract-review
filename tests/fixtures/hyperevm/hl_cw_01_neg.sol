// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HL-CW-01 negative fixture: no accounting after sendRawAction; balance updated separately.
// Expected: HL-CW-01 does NOT fire.

interface ICoreWriter {
    function sendRawAction(bytes calldata action) external payable;
}

contract HLCw01Neg {
    address constant CORE_WRITER = 0x3333333333333333333333333333333333333333;
    mapping(address => uint256) public balance;

    // Step 1: fire CoreWriter action — no accounting here.
    function sendAction(bytes calldata action) external {
        ICoreWriter(CORE_WRITER).sendRawAction(action);
    }

    // Step 2: called in a SEPARATE transaction after confirmation via precompile.
    function confirmDeposit(address user, uint256 amount) external {
        balance[user] += amount;
    }
}
