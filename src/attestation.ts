import {
  encodePacked,
  keccak256,
  type Hex,
  toHex,
  pad,
} from 'viem';
import {
  AgentExecutionProof,
  AgentExecutionProofSchema,
  AttestationVerificationResult,
  KiteNetworkConfig,
  KITE_TESTNET_CONFIG,
} from './types.js';

export class KiteZKAttestationRelay {
  private config: KiteNetworkConfig;
  private knownEpochs: Map<string, bigint> = new Map();

  constructor(config: KiteNetworkConfig = KITE_TESTNET_CONFIG) {
    this.config = config;
  }

  /**
   * Computes the deterministic keccak256 attestation digest
   */
  public computeAttestationDigest(proof: AgentExecutionProof): Hex {
    return keccak256(
      encodePacked(
        ['bytes32', 'bytes32', 'uint256', 'bytes32'],
        [proof.agentId, proof.stateHash, proof.computationEpoch, proof.x402ReceiptHash]
      )
    );
  }

  /**
   * Validates local schema, epoch monotonic progression, and cryptographic bounds
   */
  public async verifyAttestationProof(
    rawProof: unknown
  ): Promise<AttestationVerificationResult> {
    const parseResult = AgentExecutionProofSchema.safeParse(rawProof);
    if (!parseResult.success) {
      return {
        valid: false,
        attestationDigest: '0x0' as Hex,
        epoch: 0n,
        agentId: '0x0' as Hex,
        rejectionReason: `Schema validation failed: ${parseResult.error.issues.map(i => i.message).join(', ')}`,
      };
    }

    const proof = parseResult.data;
    const digest = this.computeAttestationDigest(proof);
    const lastEpoch = this.knownEpochs.get(proof.agentId.toLowerCase()) ?? 0n;

    if (proof.computationEpoch <= lastEpoch) {
      return {
        valid: false,
        attestationDigest: digest,
        epoch: proof.computationEpoch,
        agentId: proof.agentId,
        rejectionReason: `Epoch rollback or replay detected: current epoch ${proof.computationEpoch} <= registered ${lastEpoch}`,
      };
    }

    // Verify mock ZK snark validity constraint (proof payload integrity check)
    if (proof.zkProof.length < 10) {
      return {
        valid: false,
        attestationDigest: digest,
        epoch: proof.computationEpoch,
        agentId: proof.agentId,
        rejectionReason: 'Invalid ZK proof payload byte length',
      };
    }

    // Anchor monotonic sequence in cache
    this.knownEpochs.set(proof.agentId.toLowerCase(), proof.computationEpoch);

    return {
      valid: true,
      attestationDigest: digest,
      epoch: proof.computationEpoch,
      agentId: proof.agentId,
    };
  }

  /**
   * Generates public inputs vector formatted for EVM Snark verifier contract
   */
  public generateVerifierPublicInputs(proof: AgentExecutionProof): readonly [Hex, Hex, Hex, Hex] {
    return [
      proof.agentId,
      proof.stateHash,
      pad(toHex(proof.computationEpoch), { size: 32 }),
      proof.x402ReceiptHash,
    ];
  }

  public getNetworkConfig(): KiteNetworkConfig {
    return this.config;
  }
}
