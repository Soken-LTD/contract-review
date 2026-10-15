// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HL-BR-01 positive fixture: HYPE transfer amount recorded without rounding.
// Expected: HL-BR-01 fires.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract HLBr01Pos {
    address constant HYPE = 0x2222222222222222222222222222222222222222;

    mapping(address => uint256) public deposited;

    // Bug: raw amount stored without accounting for non-round HyperCore bridge amounts.
    function deposit(uint256 amount) external {
        IERC20(HYPE).transfer(address(this), amount);
        deposited[msg.sender] += amount; // HL-BR-01: no rounding applied
    }
}
