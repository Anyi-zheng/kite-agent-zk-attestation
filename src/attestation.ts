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

/** Implementations must bind the proof to these exact public inputs. */
export type AttestationProofVerifier = (
  proof: AgentExecutionProof,
  publicInputs: readonly [Hex, Hex, Hex, Hex]
) => boolean | Promise<boolean>;

export class KiteZKAttestationRelay {
  private config: KiteNetworkConfig;
  private knownEpochs: Map<string, bigint> = new Map();

  constructor(
    config: KiteNetworkConfig = KITE_TESTNET_CONFIG,
    private readonly verifyProof?: AttestationProofVerifier
  ) {
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

    if (!/^0x(?:[0-9a-fA-F]{2})+$/.test(proof.zkProof)) {
      return {
        valid: false,
        attestationDigest: digest,
        epoch: proof.computationEpoch,
        agentId: proof.agentId,
        rejectionReason: 'Invalid ZK proof payload byte length',
      };
    }

    if (!this.verifyProof) {
      return { valid: false, attestationDigest: digest, epoch: proof.computationEpoch,
        agentId: proof.agentId, rejectionReason: 'No proof verifier configured' };
    }
    try {
      if (await this.verifyProof(proof, this.generateVerifierPublicInputs(proof)) !== true) {
        return { valid: false, attestationDigest: digest, epoch: proof.computationEpoch,
          agentId: proof.agentId, rejectionReason: 'Proof verification failed' };
      }
    } catch {
      return { valid: false, attestationDigest: digest, epoch: proof.computationEpoch,
        agentId: proof.agentId, rejectionReason: 'Proof verifier unavailable' };
    }
    // Verification may complete out of order; do not regress a concurrently accepted epoch.
    const currentEpoch = this.knownEpochs.get(proof.agentId.toLowerCase()) ?? 0n;
    if (proof.computationEpoch <= currentEpoch) {
      return { valid: false, attestationDigest: digest, epoch: proof.computationEpoch,
        agentId: proof.agentId, rejectionReason: 'Epoch rollback or replay detected after verification' };
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
