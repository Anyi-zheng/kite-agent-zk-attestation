import { describe, it, expect } from 'vitest';
import { SnarkRecursionOptimizer } from '../src/optimizer.js';
import { AgentExecutionProof } from '../src/types.js';

describe('SnarkRecursionOptimizer', () => {
  const optimizer = new SnarkRecursionOptimizer();

  const mockProof = (epoch: bigint): AgentExecutionProof => ({
    agentId: '0x1111111111111111111111111111111111111111111111111111111111111111',
    stateHash: '0x2222222222222222222222222222222222222222222222222222222222222222',
    computationEpoch: epoch,
    x402ReceiptHash: '0x3333333333333333333333333333333333333333333333333333333333333333',
    zkProof: '0x' + '1234567890abcdef'.repeat(16), // 128 bytes
  });

  it('evaluates zero compression for empty batch', () => {
    const metrics = optimizer.evaluateCompression([]);
    expect(metrics.originalByteLength).toBe(0);
    expect(metrics.compressedByteLength).toBe(0);
  });

  it('reports unchanged sizes because commitments do not compress proofs', () => {
    const batch = [mockProof(1n), mockProof(2n), mockProof(3n), mockProof(4n)];
    const metrics = optimizer.evaluateCompression(batch);

    expect(metrics.originalByteLength).toBe(512); // 4 * 128
    expect(metrics.foldedRecursionDepth).toBe(0);
    expect(metrics.compressedByteLength).toBe(512);
    expect(metrics.compressionRatio).toBe(1);
  });

  it('retains the legacy result shape without claiming recursion', () => {
    const batch = [mockProof(1n), mockProof(2n)];
    const folded = optimizer.foldProofs(batch);

    expect(folded.depth).toBe(0);
    expect(folded.subProofDigests).toHaveLength(2);
    expect(folded.aggregatedProof.startsWith('0x')).toBe(true);
    expect(folded.nodeId.startsWith('0x')).toBe(true);
  });

  it('reports malformed proofs with the same message as the relay', () => {
    const jsonEpoch = { ...mockProof(1n), computationEpoch: '1' } as unknown as AgentExecutionProof;
    expect(() => optimizer.commitProofs([jsonEpoch])).toThrow('Invalid attestation proof');
    expect(() => optimizer.evaluateCompression([{ ...mockProof(1n), zkProof: '0x1' }])).toThrow('Invalid attestation proof');
  });

  it('throws on empty proof folding', () => {
    expect(() => optimizer.foldProofs([])).toThrow('Cannot fold an empty proof set');
  });
});

describe('SnarkRecursionOptimizer input validation', () => {
  const optimizer = new SnarkRecursionOptimizer();

  it.each([null, undefined, {}, 'proofs', 42])('rejects non-array proofs (%s) with a TypeError', (bad) => {
    expect(() => optimizer.commitProofs(bad as never)).toThrow(TypeError);
    expect(() => optimizer.commitProofs(bad as never)).toThrow('proofs must be an array');
    expect(() => optimizer.evaluateCompression(bad as never)).toThrow('proofs must be an array');
    expect(() => optimizer.foldProofs(bad as never)).toThrow('proofs must be an array');
  });
});
