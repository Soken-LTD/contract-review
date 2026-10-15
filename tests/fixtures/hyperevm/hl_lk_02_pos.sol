// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HL-LK-02 positive fixture: finalizer slot writable after deployment.
// Expected: HL-LK-02 fires.

contract HLLk02Pos {
    // Bug: public function allows overwriting the HyperCore deployer slot.
    function setDeployer(address newDeployer) external {
        // Writes keccak256("HyperCore deployer") slot -- HL-LK-02
        bytes32 slot = keccak256("HyperCore deployer");
        assembly {
            sstore(slot, newDeployer)
        }
    }
}
