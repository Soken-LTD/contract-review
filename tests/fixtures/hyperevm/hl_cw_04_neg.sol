// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HL-CW-04 negative fixture: coreUserExists (0x810) checked before sendRawAction.
// Expected: HL-CW-04 does NOT fire.

interface ICoreWriter {
    function sendRawAction(bytes calldata action) external payable;
}

contract HLCw04Neg {
    address constant CORE_WRITER = 0x3333333333333333333333333333333333333333;
    address constant CORE_USER_EXISTS = 0x0000000000000000000000000000000000000810;

    function placeOrder(address user, bytes calldata action) external {
        // Check user exists first (coreUserExists 0x810).
        (bool ok, bytes memory result) = CORE_USER_EXISTS.staticcall(abi.encode(user));
        require(ok && abi.decode(result, (bool)), "user not on HyperCore");
        ICoreWriter(CORE_WRITER).sendRawAction(action);
    }
}
