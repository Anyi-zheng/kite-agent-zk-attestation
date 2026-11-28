import { describe, it, expect } from 'vitest';
import { KiteZKAttestationRelay } from '../src/attestation.js';
import { BatchAttestationPipeline } from '../src/pipeline.js';
import { KITE_TESTNET_CONFIG, type AgentExecutionProof } from '../src/types.js';

describe('verified batch metadata', () => {
  it.each([false, true])('accepted summary uses verifier result metadata (strict=%s)', async (strictEpochOrdering) => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const relay = new KiteZKAttestationRelay(KITE_TESTNET_CONFIG, async () => { await gate; return true; });
    const proof: AgentExecutionProof = { agentId: `0x${'aa'.repeat(32)}`, stateHash: `0x${'11'.repeat(32)}`,
      computationEpoch: 1n, x402ReceiptHash: `0x${'22'.repeat(32)}`, zkProof: '0x1234' };
    const originalAgent = proof.agentId;
    const expectedDigest = relay.computeAttestationDigest(proof);
    const pending = new BatchAttestationPipeline(relay).processBatch({ proofs: [proof], strictEpochOrdering });
    // 验证器持有已解析的原始证明；调用方可在等待期间复用自己的对象。
    proof.agentId = `0x${'bb'.repeat(32)}`; proof.computationEpoch = 999n;
    release();
    const result = await pending;
    expect(result.anchoredDigests).toEqual([expectedDigest]);
    expect(result.perAgentLastAcceptedEpoch).toEqual({ [originalAgent]: 1n });
    expect(relay.lastAcceptedEpoch(originalAgent)).toBe(1n);
  });
});
