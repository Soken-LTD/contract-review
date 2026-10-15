// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HL-CW-01 positive fixture: accounting written after sendRawAction in same tx.
// The contract treats sendRawAction as synchronous; it writes balance immediately.
// Expected: HL-CW-01 fires.

interface ICoreWriter {
    function sendRawAction(bytes calldata action) external payable;
}

contract HLCw01Pos {
    address constant CORE_WRITER = 0x3333333333333333333333333333333333333333;
    mapping(address => uint256) public balance;

    // Bug: balance written immediately after sendRawAction (delayed by seconds, F15).
    function deposit(bytes calldata action) external {
        ICoreWriter(CORE_WRITER).sendRawAction(action);
        balance[msg.sender] += 100; // accounting assumes settlement -- HL-CW-01
    }
}
