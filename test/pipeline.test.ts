import { describe, it, expect } from 'vitest';
import { KiteZKAttestationRelay } from '../src/attestation.js';
import { BatchAttestationPipeline } from '../src/pipeline.js';
import { AgentExecutionProof, KITE_TESTNET_CONFIG } from '../src/types.js';

describe('BatchAttestationPipeline', () => {
  it('bundles and processes heterogeneous agent attestation batches', async () => {
    const relay = new KiteZKAttestationRelay(KITE_TESTNET_CONFIG);
    const pipeline = new BatchAttestationPipeline(relay);

    const proofs: AgentExecutionProof[] = [
      {
        agentId: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        stateHash: '0x1111111111111111111111111111111111111111111111111111111111111111',
        computationEpoch: 10n,
        x402ReceiptHash: '0x2222222222222222222222222222222222222222222222222222222222222222',
        zkProof: '0x1234567890abcdef',
      },
      {
        agentId: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        stateHash: '0x3333333333333333333333333333333333333333333333333333333333333333',
        computationEpoch: 15n,
        x402ReceiptHash: '0x4444444444444444444444444444444444444444444444444444444444444444',
        zkProof: '0xabcdef1234567890',
      },
      {
        // Replayed epoch for agent A
        agentId: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        stateHash: '0x5555555555555555555555555555555555555555555555555555555555555555',
        computationEpoch: 8n,
        x402ReceiptHash: '0x6666666666666666666666666666666666666666666666666666666666666666',
        zkProof: '0xabcdef1234567890',
      },
    ];

    const res = await pipeline.processBatch({ proofs });
    expect(res.totalProcessed).toBe(3);
    expect(res.acceptedCount).toBe(2);
    expect(res.rejectedCount).toBe(1);
    expect(res.anchoredDigests).toHaveLength(2);
    expect(res.rejections[0].reason).toContain('Epoch rollback or replay');
  });
});
