// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HL-LK-02 negative fixture: deployer slot written only in the constructor.
// Expected: HL-LK-02 does NOT fire.

contract HLLk02Neg {
    constructor(address initialDeployer) {
        // Only the constructor writes the deployer slot -- safe.
        bytes32 slot = keccak256("HyperCore deployer");
        assembly {
            sstore(slot, initialDeployer)
        }
    }

    // Read-only view -- no write.
    function getDeployer() external view returns (address deployer) {
        bytes32 slot = keccak256("HyperCore deployer");
        assembly {
            deployer := sload(slot)
        }
    }
}
