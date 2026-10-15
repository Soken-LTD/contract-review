// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Guard verification fixture (04 2.1): name-only guards must not count.
abstract contract ReentrancyGuard {
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;
    uint256 private _status = NOT_ENTERED;

    error ReentrancyGuardReentrantCall();

    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        if (_status == ENTERED) {
            revert ReentrancyGuardReentrantCall();
        }
        _status = ENTERED;
    }

    function _nonReentrantAfter() private {
        _status = NOT_ENTERED;
    }
}

contract Guards is ReentrancyGuard {
    address public owner = msg.sender;
    mapping(bytes32 => mapping(address => bool)) private _roles;
    bytes32 public constant KEEPER = keccak256("KEEPER");
    uint256 public x;

    modifier fakeNonReentrant() {
        _;
    }

    modifier onlyOwnerNoRevert() {
        if (msg.sender != owner) {
            x = 0;
        }
        _;
    }

    modifier onlyRole(bytes32 role) {
        _checkRole(role, msg.sender);
        _;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function _checkRole(bytes32 role, address account) internal view {
        if (!hasRole(role, account)) revert();
    }

    function _checkNothing(address account) internal pure {
        account;
    }

    function realLock() external nonReentrant {
        x = 1;
    }

    function fakeLock() external fakeNonReentrant {
        x = 2;
    }

    function noRevertOwner() external onlyOwnerNoRevert {
        x = 3;
    }

    function keeperOnly() external onlyRole(KEEPER) {
        x = 4;
    }

    function requireRole() external {
        require(hasRole(KEEPER, msg.sender), "role");
        x = 5;
    }

    function checkByName() external {
        _checkNothing(msg.sender);
        x = 6;
    }
}
