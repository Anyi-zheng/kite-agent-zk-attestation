import {
  encodePacked,
  keccak256,
  type Hex,
  toHex,
  pad,
  zeroHash,
  isAddress,
  zeroAddress,
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

/**
 * Validates a proof at a public boundary. Every method that turns a proof into
 * digest or verifier bytes must call this first: `toHex` treats a non-bigint
 * epoch as UTF-8 text, so an unchecked JSON-decoded epoch would silently format
 * public inputs for a different epoch.
 */
function parseProofOrThrow(raw: unknown): AgentExecutionProof {
  const parseResult = AgentExecutionProofSchema.safeParse(raw);
  if (!parseResult.success) {
    const issues = parseResult.error.issues.map((i) => i.message).join(', ');
    throw new Error(`Invalid attestation proof: ${issues}`);
  }
  return parseResult.data;
}

function validateNetworkConfig(config: KiteNetworkConfig): void {
  if (typeof config.name !== 'string' || !config.name.trim()) {
    throw new Error('Network name must not be empty');
  }
  if (!Number.isSafeInteger(config.chainId) || config.chainId <= 0) {
    throw new Error('Network chain ID must be a positive safe integer');
  }
  // Strict mode: lowercase/uppercase addresses pass, mixed-case must carry a valid EIP-55 checksum.
  if (typeof config.contractAddress !== 'string' || !isAddress(config.contractAddress, { strict: true })) {
    throw new Error('Network contract address must be a 20-byte hex address with a valid EIP-55 checksum');
  }
  if (config.contractAddress.toLowerCase() === zeroAddress) {
    throw new Error('Network contract address must not be the zero address');
  }
  for (const [field, value] of [['RPC', config.rpcUrl], ['Facilitator', config.facilitatorUrl]] as const) {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new Error(`${field} URL must be an absolute HTTP(S) URL`);
    }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
      throw new Error(`${field} URL must be an HTTP(S) URL without credentials`);
    }
  }
}

export class KiteZKAttestationRelay {
  private config: KiteNetworkConfig;
  private knownEpochs: Map<string, bigint> = new Map();

  constructor(
    config: KiteNetworkConfig = KITE_TESTNET_CONFIG,
    private readonly verifyProof?: AttestationProofVerifier
  ) {
    if (typeof config !== 'object' || config === null || Array.isArray(config)) {
      throw new TypeError('Network config must be an object');
    }
    if (verifyProof !== undefined && typeof verifyProof !== 'function') {
      throw new TypeError('Proof verifier must be a function when provided');
    }
    const configSnapshot = { ...config };
    validateNetworkConfig(configSnapshot);
    this.config = configSnapshot;
  }

  /**
   * Computes the deterministic keccak256 attestation digest.
   * Validates the proof shape first so malformed inputs fail with a clear message
   * instead of propagating low-level ABI encoding errors.
   */
  public computeAttestationDigest(proof: AgentExecutionProof): Hex {
    const validated = parseProofOrThrow(proof);
    return keccak256(
      encodePacked(
        ['bytes32', 'bytes32', 'uint256', 'bytes32'],
        [validated.agentId, validated.stateHash, validated.computationEpoch, validated.x402ReceiptHash]
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
        // Use 32-byte zero sentinels so rejected results remain valid bytes32 values
        // for logging, ABI encoding and on-chain anchoring paths.
        attestationDigest: zeroHash,
        epoch: 0n,
        agentId: zeroHash,
        // Zod type errors such as "Required" do not say which field failed, so prefix the path.
        rejectionReason: `Schema validation failed: ${parseResult.error.issues.map(({ path, message }) => {
          const field = path.join('.') || 'proof';
          return message.startsWith(`${field} `) ? message : `${field}: ${message}`;
        }).join(', ')}`,
      };
    }

    // 验证器只能消费固定输入，不能改写已计算摘要所对应的证明与 epoch。
    const proof = Object.freeze(parseResult.data);
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
      if (await this.verifyProof(proof, Object.freeze(this.generateVerifierPublicInputs(proof))) !== true) {
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
   * Generates public inputs vector formatted for EVM Snark verifier contract.
   * The proof is validated first so a malformed epoch cannot be silently
   * re-encoded as UTF-8 bytes in the uint256 slot.
   */
  public generateVerifierPublicInputs(proof: AgentExecutionProof): readonly [Hex, Hex, Hex, Hex] {
    const validated = parseProofOrThrow(proof);
    return [
      validated.agentId,
      validated.stateHash,
      pad(toHex(validated.computationEpoch), { size: 32 }),
      validated.x402ReceiptHash,
    ];
  }

  public getNetworkConfig(): KiteNetworkConfig {
    return { ...this.config };
  }

  /** Number of agents currently tracked in the epoch cache. */
  public knownAgentCount(): number {
    return this.knownEpochs.size;
  }

  /** Highest accepted epoch registered for an agent, or null when untracked. */
  public lastAcceptedEpoch(agentId: Hex): bigint | null {
    if (!/^0x[0-9a-fA-F]{64}$/.test(agentId)) {
      throw new Error('agentId must be a 32-byte hex string');
    }
    const epoch = this.knownEpochs.get(agentId.toLowerCase());
    return epoch === undefined ? null : epoch;
  }

  /**
   * Removes an agent from the epoch cache so its operator can retire or re-register it.
   * Returns true when the agent was tracked. Callers must re-attest from a fresh epoch,
   * since forgetting an agent reopens its replay window.
   */
  public forgetAgent(agentId: Hex): boolean {
    if (!/^0x[0-9a-fA-F]{64}$/.test(agentId)) {
      throw new Error('agentId must be a 32-byte hex string');
    }
    return this.knownEpochs.delete(agentId.toLowerCase());
  }

  /** Drops every tracked agent from the epoch cache. */
  public clearKnownEpochs(): void {
    this.knownEpochs.clear();
  }
}
