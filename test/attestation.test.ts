import { describe, it, expect, beforeEach } from 'vitest';
import { KiteZKAttestationRelay } from '../src/attestation.js';
import { AgentExecutionProof, KITE_TESTNET_CONFIG } from '../src/types.js';

describe('KiteZKAttestationRelay', () => {
  let relay: KiteZKAttestationRelay;

  const validProof: AgentExecutionProof = {
    agentId: '0x1111111111111111111111111111111111111111111111111111111111111111',
    stateHash: '0x2222222222222222222222222222222222222222222222222222222222222222',
    computationEpoch: 100n,
    x402ReceiptHash: '0x3333333333333333333333333333333333333333333333333333333333333333',
    zkProof: '0xdeadbeef1234567890abcdef',
  };

  beforeEach(() => {
    relay = new KiteZKAttestationRelay(KITE_TESTNET_CONFIG);
  });

  it('computes deterministic keccak256 attestation digest', () => {
    const digest1 = relay.computeAttestationDigest(validProof);
    const digest2 = relay.computeAttestationDigest(validProof);
    expect(digest1).toBe(digest2);
    expect(digest1.startsWith('0x')).toBe(true);
    expect(digest1.length).toBe(66);
  });

  it('successfully verifies and anchors valid execution proof', async () => {
    const res = await relay.verifyAttestationProof(validProof);
    expect(res.valid).toBe(true);
    expect(res.epoch).toBe(100n);
    expect(res.agentId).toBe(validProof.agentId);
  });

  it('rejects stale or replay computation epochs', async () => {
    await relay.verifyAttestationProof(validProof);

    const replayedProof = { ...validProof, computationEpoch: 99n };
    const res = await relay.verifyAttestationProof(replayedProof);
    expect(res.valid).toBe(false);
    expect(res.rejectionReason).toContain('Epoch rollback or replay detected');
  });

  it('generates EVM-compatible 4-slot public inputs vector', () => {
    const inputs = relay.generateVerifierPublicInputs(validProof);
    expect(inputs).toHaveLength(4);
    expect(inputs[0]).toBe(validProof.agentId);
    expect(inputs[1]).toBe(validProof.stateHash);
    expect(inputs[3]).toBe(validProof.x402ReceiptHash);
  });
});
