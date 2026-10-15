// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HL-BR-01 negative fixture: HYPE amount truncated to EVM precision before recording.
// Expected: HL-BR-01 does NOT fire.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract HLBr01Neg {
    address constant HYPE = 0x2222222222222222222222222222222222222222;
    // EVM precision: 18 decimals; HyperCore may include 4 extra decimals (weiDecimals).
    uint256 constant PRECISION = 1e4; // truncate to EVM precision

    mapping(address => uint256) public deposited;

    function deposit(uint256 amount) external {
        IERC20(HYPE).transfer(address(this), amount);
        uint256 rounded = (amount / PRECISION) * PRECISION; // truncation applied -- safe
        deposited[msg.sender] += rounded;
    }
}
