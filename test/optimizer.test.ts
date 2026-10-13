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

  it('calculates recursive depth and compression ratio for multi-proof batch', () => {
    const batch = [mockProof(1n), mockProof(2n), mockProof(3n), mockProof(4n)];
    const metrics = optimizer.evaluateCompression(batch);

    expect(metrics.originalByteLength).toBe(512); // 4 * 128
    expect(metrics.foldedRecursionDepth).toBe(2);
    expect(metrics.compressionRatio).toBeGreaterThan(1);
  });

  it('folds batch into deterministic aggregated recursive node', () => {
    const batch = [mockProof(1n), mockProof(2n)];
    const folded = optimizer.foldProofs(batch);

    expect(folded.depth).toBe(1);
    expect(folded.subProofDigests).toHaveLength(2);
    expect(folded.aggregatedProof.startsWith('0x')).toBe(true);
    expect(folded.nodeId.startsWith('0x')).toBe(true);
  });

  it('throws on empty proof folding', () => {
    expect(() => optimizer.foldProofs([])).toThrow('Cannot fold an empty proof set');
  });
});
