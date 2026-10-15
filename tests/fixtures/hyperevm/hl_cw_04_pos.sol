// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HL-CW-04 positive fixture: sendRawAction called without coreUserExists check.
// Expected: HL-CW-04 fires.

interface ICoreWriter {
    function sendRawAction(bytes calldata action) external payable;
}

contract HLCw04Pos {
    address constant CORE_WRITER = 0x3333333333333333333333333333333333333333;

    // Bug: no check against coreUserExists (0x810) before sendRawAction.
    function placeOrder(bytes calldata action) external {
        ICoreWriter(CORE_WRITER).sendRawAction(action); // HL-CW-04: missing user check
    }
}
