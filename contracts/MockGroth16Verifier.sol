// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./KiteAgentZKAttestation.sol";

/**
 * @title MockGroth16Verifier
 * @notice Mock implementation of BN254 Groth16 pairing verifier for testing Kite Agent Attestations
 */
contract MockGroth16Verifier is IKiteVerifier {
    bool public shouldPass = true;

    function setShouldPass(bool _pass) external {
        shouldPass = _pass;
    }

    function verifyProof(
        bytes calldata proof,
        uint256[4] calldata publicInputs
    ) external view override returns (bool) {
        // Enforce valid proof length (minimum 32 bytes)
        if (proof.length < 32) return false;
        // Non-zero public inputs validation
        if (publicInputs[0] == 0 || publicInputs[1] == 0) return false;
        return shouldPass;
    }
}
