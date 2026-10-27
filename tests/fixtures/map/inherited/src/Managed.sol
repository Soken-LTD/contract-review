// SPDX-License-Identifier: MIT
// Pinned file of the inherited-guards fixture: guards come from lib/oz (never pinned).
pragma solidity ^0.8.20;

import {Ownable} from "oz/access/Ownable.sol";
import {Pausable} from "oz/utils/Pausable.sol";
import {ReentrancyGuard} from "oz/utils/ReentrancyGuard.sol";

contract Managed is Ownable, Pausable, ReentrancyGuard {
    address public keeper;
    uint256 public fee;
    mapping(address => uint256) public balances;

    error NotKeeper();

    modifier onlyKeeper() {
        if (msg.sender != keeper) revert NotKeeper();
        _;
    }

    constructor(address owner_) Ownable(owner_) {}

    function setFee(uint256 f) external onlyOwner {
        fee = f;
    }

    function setKeeper(address k) external onlyOwner {
        keeper = k;
    }

    function pause() external onlyOwner {
        _pause();
    }

    function harvest() external onlyKeeper {
        fee += 1;
    }

    function deposit() external payable whenNotPaused nonReentrant {
        balances[msg.sender] += msg.value;
    }

    function sweep(address to) external {
        _checkOwner();
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok);
    }

    function open() external {
        fee = 0;
    }
}
