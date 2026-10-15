// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice One function per guard rule and spoof (04 2.1 verified guards).
contract CallerRules {
    address public owner = msg.sender;
    address public constant ZERO = address(0);
    mapping(address => bool) public allowed;
    mapping(address => bool) public blacklist;
    uint256 public x;
    bool public paused;

    function okEq() external { require(msg.sender == owner, "o"); x = 1; }
    function okNe() external { if (msg.sender != owner) revert(); x = 1; }
    function okAnd() external { require(msg.sender == owner && x == 0, "o"); x = 1; }
    function okOrNegated() external { if (msg.sender != owner || paused) revert(); x = 1; }
    function okAllowList() external { require(allowed[msg.sender], "a"); x = 1; }
    function spoofSelf() external { require(msg.sender == msg.sender, "s"); x = 1; }
    function spoofZero() external { require(msg.sender != address(0), "z"); x = 1; }
    function spoofZeroConst() external { require(msg.sender == ZERO, "z"); x = 1; }
    function spoofParam(address a) external { require(msg.sender == a, "p"); x = 1; }
    function spoofReversed() external { if (msg.sender == owner) revert(); x = 1; }
    function spoofOr() external { require(msg.sender == owner || x > 0, "or"); x = 1; }
    function spoofNegatedAnd() external { if (msg.sender != owner && x > 0) revert(); x = 1; }
    function spoofBlacklist() external { require(!blacklist[msg.sender], "b"); x = 1; }
    function spoofTxOrigin() external { require(msg.sender == tx.origin, "t"); x = 1; }
}

contract PauseRules {
    bool public paused;
    uint256 public pausedCount;
    uint256 public x;

    function okPause() external { require(!paused, "p"); x = 1; }
    function spoofPauseCounter() external { require(pausedCount == 0, "c"); x = 1; }
    function spoofPauseLocal() external { bool isPaused = false; require(!isPaused, "l"); x = 1; }
}

contract LockRules {
    uint256 private _a;
    uint256 private _b;
    uint256 private _c;
    uint256 public x;

    modifier nonReentrant() {
        require(_a == 0, "r");
        _a = 1;
        _;
        _a = 0;
    }

    modifier noReentrancyOtherVar() {
        require(_b == 0, "r");
        _c = 1;
        _;
        _c = 0;
    }

    modifier lockNoWriteBack() {
        require(_b == 0, "r");
        _b = 1;
        _;
    }

    function okLock() external nonReentrant { x = 1; }
    function spoofOtherVar() external noReentrancyOtherVar { x = 2; }
    function spoofNoWriteBack() external lockNoWriteBack { x = 3; }
}

contract InitRules {
    bool private _inited;
    uint256 public x;

    modifier initializer() {
        require(!_inited, "i");
        _inited = true;
        _;
    }

    modifier reinitializer(uint8 v) {
        v;
        _;
    }

    function okInit() external initializer { x = 1; }
    function spoofInit() external reinitializer(2) { x = 2; }
}
