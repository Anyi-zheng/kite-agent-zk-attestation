import { encodeAbiParameters, keccak256, stringToHex, type Hex } from 'viem';
import { AgentExecutionProofSchema, type AgentExecutionProof } from './types.js';

export interface ProofCompressionMetrics {
  originalByteLength: number;
  compressedByteLength: number;
  compressionRatio: number;
  foldedRecursionDepth: number;
}

export interface ProofBatchCommitment {
  commitment: Hex;
  proofDigests: Hex[];
}

/** Legacy result shape. aggregatedProof is a commitment, never a SNARK proof. */
export interface RecursiveBatchNode {
  nodeId: Hex;
  depth: number;
  aggregatedProof: Hex;
  subProofDigests: Hex[];
}

const itemDomain = keccak256(stringToHex('kite-proof-item-v1'));
const batchDomain = keccak256(stringToHex('kite-proof-batch-v1'));

function checkedProof(raw: AgentExecutionProof): AgentExecutionProof {
  const proof = AgentExecutionProofSchema.parse(raw);
  if (proof.computationEpoch >= 2n ** 256n || !/^0x(?:[0-9a-fA-F]{2})+$/.test(proof.zkProof)) {
    throw new Error('Proof must contain whole bytes and a uint256 epoch');
  }
  return proof;
}

/**
 * Builds ordered batch commitments. This does not prove execution, verify a
 * proof, compress proofs, or construct a recursive SNARK.
 * The historical class name is retained for source compatibility.
 */
export class SnarkRecursionOptimizer {
  constructor(_recursionThreshold = 4) {}

  /** No compression is performed; byte counts therefore remain equal. */
  public evaluateCompression(proofs: AgentExecutionProof[]): ProofCompressionMetrics {
    const originalByteLength = proofs.reduce((total, proof) => total + (checkedProof(proof).zkProof.length - 2) / 2, 0);
    return { originalByteLength, compressedByteLength: originalByteLength, compressionRatio: 1, foldedRecursionDepth: 0 };
  }

  /** Commits complete proof bytes and public inputs, preserving batch order and duplicates. */
  public commitProofs(proofs: AgentExecutionProof[]): ProofBatchCommitment {
    if (proofs.length === 0) throw new Error('Cannot fold an empty proof set');
    const proofDigests = proofs.map(raw => {
      const proof = checkedProof(raw);
      return keccak256(encodeAbiParameters(
        [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes32' }, { type: 'uint256' }, { type: 'bytes32' }, { type: 'bytes' }],
        [itemDomain, proof.agentId, proof.stateHash, proof.computationEpoch, proof.x402ReceiptHash, proof.zkProof]
      ));
    });
    const commitment = keccak256(encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'uint256' }, { type: 'bytes32[]' }],
      [batchDomain, BigInt(proofDigests.length), proofDigests]
    ));
    return { commitment, proofDigests };
  }

  /** @deprecated Use commitProofs. These legacy fields describe a hash commitment only. */
  public foldProofs(proofs: AgentExecutionProof[]): RecursiveBatchNode {
    const { commitment, proofDigests } = this.commitProofs(proofs);
    return { nodeId: commitment, depth: 0, aggregatedProof: commitment, subProofDigests: proofDigests };
  }
}
