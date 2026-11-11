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
    // Test fixture only: no cryptographic verification or on-chain anchoring.
    relay = new KiteZKAttestationRelay(KITE_TESTNET_CONFIG, () => true);
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

  it('fails closed without a verifier and does not accept arbitrary payloads', async () => {
    const result = await new KiteZKAttestationRelay().verifyAttestationProof(validProof);
    expect(result.valid).toBe(false);
    expect(result.rejectionReason).toContain('No proof verifier');
  });

  it('does not consume epochs after invalid proofs or verifier errors', async () => {
    let decision: boolean | Error = false;
    const checked = new KiteZKAttestationRelay(KITE_TESTNET_CONFIG, (_proof, inputs) => {
      expect(inputs[0]).toBe(validProof.agentId);
      expect(inputs[1]).toBe(validProof.stateHash);
      if (decision instanceof Error) throw decision;
      return decision;
    });
    expect((await checked.verifyAttestationProof(validProof)).valid).toBe(false);
    decision = new Error('offline');
    expect((await checked.verifyAttestationProof(validProof)).valid).toBe(false);
    decision = true;
    expect((await checked.verifyAttestationProof(validProof)).valid).toBe(true);
  });

  it('rejects late lower epochs after concurrent verification', async () => {
    let release!: () => void;
    const pending = new Promise<void>(resolve => { release = resolve; });
    const checked = new KiteZKAttestationRelay(KITE_TESTNET_CONFIG, async proof => {
      if (proof.computationEpoch === 99n) await pending;
      return true;
    });
    const older = checked.verifyAttestationProof({ ...validProof, computationEpoch: 99n });
    expect((await checked.verifyAttestationProof(validProof)).valid).toBe(true);
    release();
    expect((await older).valid).toBe(false);
  });

  it('rejects epochs outside the ABI uint256 bound without calling a verifier', async () => {
    const checked = new KiteZKAttestationRelay(KITE_TESTNET_CONFIG, () => { throw new Error('must not run'); });
    expect((await checked.verifyAttestationProof({ ...validProof, computationEpoch: 2n ** 256n })).valid).toBe(false);
  });
});
