// SPDX-License-Identifier: MIT
// Minimal replica of OpenZeppelin v5 Context (test fixture, not pinned).
pragma solidity ^0.8.20;

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
}
