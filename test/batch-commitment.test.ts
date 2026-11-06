import { describe, it, expect } from 'vitest';
import { encodeAbiParameters, keccak256, stringToHex } from 'viem';
import { SnarkRecursionOptimizer } from '../src/optimizer.js';
import type { AgentExecutionProof } from '../src/types.js';
const proof = (tail = '01'): AgentExecutionProof => ({ agentId: '0x' + '11'.repeat(32) as `0x${string}`, stateHash: '0x' + '22'.repeat(32) as `0x${string}`, computationEpoch: 1n, x402ReceiptHash: '0x' + '33'.repeat(32) as `0x${string}`, zkProof: '0x' + 'aa'.repeat(32) + tail as `0x${string}` });
const optimizer = new SnarkRecursionOptimizer();
describe('ordered proof batch commitments', () => {
  it('commits bytes beyond the first 32 and all public inputs', () => {
    const p = proof(), base = optimizer.commitProofs([p]).commitment;
    for (const changed of [proof('02'), { ...p, computationEpoch: 2n }, { ...p, agentId: p.stateHash }, { ...p, stateHash: p.agentId }, { ...p, x402ReceiptHash: p.agentId }]) {
      expect(optimizer.commitProofs([changed]).commitment).not.toBe(base);
    }
  });
  it('preserves order, multiplicity and duplicate contents', () => {
    const a = proof('01'), b = proof('02');
    expect(optimizer.commitProofs([a, b]).commitment).not.toBe(optimizer.commitProofs([b, a]).commitment);
    expect(optimizer.commitProofs([a, a]).commitment).not.toBe(optimizer.commitProofs([b, b]).commitment);
    expect(optimizer.commitProofs([a]).commitment).not.toBe(optimizer.commitProofs([a, a]).commitment);
  });
  it('matches an independently encoded versioned commitment vector', () => {
    const p = proof();
    const digest = keccak256(encodeAbiParameters([{type:'bytes32'}, {type:'bytes32'}, {type:'bytes32'}, {type:'uint256'}, {type:'bytes32'}, {type:'bytes'}], [keccak256(stringToHex('kite-proof-item-v1')), p.agentId, p.stateHash, p.computationEpoch, p.x402ReceiptHash, p.zkProof]));
    const expected = keccak256(encodeAbiParameters([{type:'bytes32'}, {type:'uint256'}, {type:'bytes32[]'}], [keccak256(stringToHex('kite-proof-batch-v1')), 1n, [digest]]));
    expect(optimizer.commitProofs([p])).toEqual({commitment: expected, proofDigests: [digest]});
    expect(optimizer.foldProofs([p])).toMatchObject({nodeId: expected, aggregatedProof: expected, depth: 0});
  });
  it('rejects empty batches, partial proof bytes and out-of-range epochs', () => {
    expect(() => optimizer.commitProofs([])).toThrow();
    for (const p of [{...proof(), zkProof: '0x1' as const}, {...proof(), computationEpoch: 2n ** 256n}]) expect(() => optimizer.commitProofs([p])).toThrow();
  });
});
