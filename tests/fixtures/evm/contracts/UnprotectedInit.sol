// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title UnprotectedInit - unprotected initializer fixture (test only)
contract UnprotectedInit {
    address public owner;
    bool private _initialized;

    // No initializer modifier - anyone can call this
    function initialize(address _owner) external {
        owner = _owner;
        _initialized = true;
    }

    function adminAction() external {
        require(msg.sender == owner, "not owner");
        // privileged action
    }
}
