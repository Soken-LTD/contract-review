// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Fixture for map.v1 tests (04 2.1, 7.5, 16).
abstract contract Owned {
    address public owner;

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function _checkOwner() internal view {
        if (msg.sender != owner) revert();
    }
}

contract Vault is Owned {
    uint256 public constant MAX_FEE_BPS = 1_000;
    uint256 public constant DELAY = 2 days;
    uint256 public feeBps;
    uint256 private _locked = 1;
    mapping(address => uint256) public balances;

    modifier nonReentrant() {
        require(_locked == 1, "locked");
        _locked = 2;
        _;
        _locked = 1;
    }

    constructor() {
        owner = msg.sender;
    }

    function setFee(uint256 newFee) external onlyOwner {
        feeBps = newFee;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value - _chargeFee(msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send");
    }

    function sweep(address to) external {
        require(msg.sender == owner, "owner");
        payable(to).transfer(address(this).balance);
    }

    function _chargeFee(uint256 amount) internal view returns (uint256 fee) {
        fee = amount * feeBps / 10_000;
    }
}
