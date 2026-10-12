// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/**
 * @title IKiteVerifier
 * @notice Verification interface for Kite Agent Zero-Knowledge Attestation proofs
 */
interface IKiteVerifier {
    function verifyProof(
        bytes calldata proof,
        uint256[4] calldata publicInputs
    ) external view returns (bool);
}

/**
 * @title KiteAgentZKAttestation
 * @author Anyi-zheng
 * @notice On-chain registry verifying zero-knowledge proofs of off-chain AI Agent execution
 *         and anchoring non-repudiable state attestations on Kite Chain (x402 protocol).
 */
contract KiteAgentZKAttestation {
    // Kite Chain ChainID: 2368 (Testnet) / 2366 (Mainnet)
    uint256 public immutable chainId;
    address public owner;
    IKiteVerifier public verifier;

    struct AttestationRecord {
        bytes32 agentId;
        bytes32 stateHash;
        uint256 computationEpoch;
        uint256 timestamp;
        address attestor;
        bytes32 x402ReceiptHash;
    }

    // Mapping from attestation digest to on-chain record
    mapping(bytes32 => AttestationRecord) public attestations;
    mapping(bytes32 => uint256) public agentLatestEpoch;

    event AttestationAnchored(
        bytes32 indexed attestationHash,
        bytes32 indexed agentId,
        bytes32 stateHash,
        uint256 computationEpoch,
        address indexed attestor,
        bytes32 x402ReceiptHash
    );

    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    error InvalidProof();
    error StaleComputationEpoch(uint256 provided, uint256 current);
    error AttestationAlreadyExists(bytes32 digest);
    error Unauthorized();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor(address _verifier) {
        owner = msg.sender;
        verifier = IKiteVerifier(_verifier);
        chainId = block.chainid;
    }

    function setVerifier(address _newVerifier) external onlyOwner {
        emit VerifierUpdated(address(verifier), _newVerifier);
        verifier = IKiteVerifier(_newVerifier);
    }

    /**
     * @notice Submits and verifies a zero-knowledge attestation of autonomous agent execution.
     * @param agentId Unique identifier of the Kite Autonomous Agent
     * @param stateHash Merkle root or digest representing internal agent memory/state
     * @param computationEpoch Monotonically increasing epoch sequence
     * @param x402ReceiptHash Linked EIP-712/x402 micropayment settlement hash
     * @param zkProof Snark/Groth16 cryptographic proof
     */
    function anchorAttestation(
        bytes32 agentId,
        bytes32 stateHash,
        uint256 computationEpoch,
        bytes32 x402ReceiptHash,
        bytes calldata zkProof
    ) external returns (bytes32 attestationHash) {
        if (computationEpoch <= agentLatestEpoch[agentId]) {
            revert StaleComputationEpoch(computationEpoch, agentLatestEpoch[agentId]);
        }

        attestationHash = keppetAttestationDigest(
            agentId,
            stateHash,
            computationEpoch,
            x402ReceiptHash
        );

        if (attestations[attestationHash].timestamp != 0) {
            revert AttestationAlreadyExists(attestationHash);
        }

        if (address(verifier) != address(0)) {
            uint256[4] memory publicInputs = [
                uint256(agentId),
                uint256(stateHash),
                computationEpoch,
                uint256(x402ReceiptHash)
            ];
            bool valid = verifier.verifyProof(zkProof, publicInputs);
            if (!valid) revert InvalidProof();
        }

        attestations[attestationHash] = AttestationRecord({
            agentId: agentId,
            stateHash: stateHash,
            computationEpoch: computationEpoch,
            timestamp: block.timestamp,
            attestor: msg.sender,
            x402ReceiptHash: x402ReceiptHash
        });

        agentLatestEpoch[agentId] = computationEpoch;

        emit AttestationAnchored(
            attestationHash,
            agentId,
            stateHash,
            computationEpoch,
            msg.sender,
            x402ReceiptHash
        );
    }

    function keppetAttestationDigest(
        bytes32 agentId,
        bytes32 stateHash,
        uint256 epoch,
        bytes32 receiptHash
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(agentId, stateHash, epoch, receiptHash));
    }
}
