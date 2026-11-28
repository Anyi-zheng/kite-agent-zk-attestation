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

  it('rejects malformed proofs when computing digest with a clear error', () => {
    const missing = { ...validProof, agentId: 'not-hex' } as unknown as AgentExecutionProof;
    expect(() => relay.computeAttestationDigest(missing)).toThrow('Invalid attestation proof');

    const short = { ...validProof, stateHash: '0x1234' } as unknown as AgentExecutionProof;
    expect(() => relay.computeAttestationDigest(short)).toThrow('Invalid attestation proof');

    const badEpoch = { ...validProof, computationEpoch: 0n } as unknown as AgentExecutionProof;
    expect(() => relay.computeAttestationDigest(badEpoch)).toThrow('Invalid attestation proof');
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
    expect(inputs[2]).toBe('0x' + '0'.repeat(62) + '64');
    expect(inputs[3]).toBe(validProof.x402ReceiptHash);
  });

  it('rejects malformed proofs before formatting verifier public inputs', () => {
    // A JSON-decoded epoch is a string. toHex would encode it as UTF-8 ("100" -> 0x313030)
    // and silently build public inputs for a different epoch instead of failing.
    const jsonEpoch = { ...validProof, computationEpoch: '100' } as unknown as AgentExecutionProof;
    expect(() => relay.generateVerifierPublicInputs(jsonEpoch)).toThrow('Invalid attestation proof');

    const unsafeNumberEpoch = { ...validProof, computationEpoch: 2 ** 53 } as unknown as AgentExecutionProof;
    expect(() => relay.generateVerifierPublicInputs(unsafeNumberEpoch)).toThrow('Invalid attestation proof');

    const shortStateHash = { ...validProof, stateHash: '0x1234' } as unknown as AgentExecutionProof;
    expect(() => relay.generateVerifierPublicInputs(shortStateHash)).toThrow('Invalid attestation proof');
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

  it('copies constructor network config so caller edits cannot retarget the relay', () => {
    const config = { ...KITE_TESTNET_CONFIG };
    const checked = new KiteZKAttestationRelay(config, () => true);
    config.chainId = 1;
    config.rpcUrl = 'https://attacker.invalid';

    expect(checked.getNetworkConfig()).toEqual(KITE_TESTNET_CONFIG);
  });

  it('returns network config snapshots that cannot mutate relay state', () => {
    const snapshot = relay.getNetworkConfig();
    snapshot.chainId = 1;
    snapshot.contractAddress = '0x0000000000000000000000000000000000000000';

    expect(relay.getNetworkConfig()).toEqual(KITE_TESTNET_CONFIG);
  });

  it.each([0, -1, 1.5, Number.NaN])('rejects invalid chain ID %s at construction', (chainId) => {
    const config = { ...KITE_TESTNET_CONFIG, chainId };
    expect(() => new KiteZKAttestationRelay(config, () => true)).toThrow('positive safe integer');
  });

  it.each(['0x0', '0x1234', 'not-an-address'])('rejects malformed contract address %s', (contractAddress) => {
    const config = { ...KITE_TESTNET_CONFIG, contractAddress };
    expect(() => new KiteZKAttestationRelay(config, () => true)).toThrow('20-byte hex address');
  });

  it('rejects malformed or credentialed endpoint URLs', () => {
    for (const rpcUrl of ['not-a-url', 'file:///tmp/rpc', 'https://user:secret@example.com']) {
      expect(() => new KiteZKAttestationRelay({ ...KITE_TESTNET_CONFIG, rpcUrl }, () => true)).toThrow('RPC URL');
    }
    expect(() => new KiteZKAttestationRelay({
      ...KITE_TESTNET_CONFIG,
      facilitatorUrl: 'ftp://facilitator.example.com',
    }, () => true)).toThrow('Facilitator URL');
  });

  it.each([null, {}, 'verifier', 42, true])('rejects non-function proof verifier %s at construction', (verifier) => {
    expect(() => new KiteZKAttestationRelay(KITE_TESTNET_CONFIG, verifier as never))
      .toThrow('Proof verifier must be a function');
  });

  it('still allows constructing a relay without a verifier', async () => {
    const unverified = new KiteZKAttestationRelay(KITE_TESTNET_CONFIG);
    const result = await unverified.verifyAttestationProof(validProof);
    expect(result.valid).toBe(false);
    expect(result.rejectionReason).toBe('No proof verifier configured');
  });

  it('rejects an empty network name', () => {
    expect(() => new KiteZKAttestationRelay({ ...KITE_TESTNET_CONFIG, name: '  ' }, () => true))
      .toThrow('Network name');
  });

  it('rejects epochs outside the ABI uint256 bound without calling a verifier', async () => {
    const checked = new KiteZKAttestationRelay(KITE_TESTNET_CONFIG, () => { throw new Error('must not run'); });
    expect((await checked.verifyAttestationProof({ ...validProof, computationEpoch: 2n ** 256n })).valid).toBe(false);
  });

  describe('epoch cache management', () => {
    const otherAgent = '0x4444444444444444444444444444444444444444444444444444444444444444';

    it('tracks accepted agents without growing for rejected proofs', async () => {
      expect(relay.knownAgentCount()).toBe(0);
      expect(relay.lastAcceptedEpoch(validProof.agentId)).toBeNull();
      await relay.verifyAttestationProof(validProof);
      expect(relay.knownAgentCount()).toBe(1);
      expect(relay.lastAcceptedEpoch(validProof.agentId)).toBe(100n);
      await relay.verifyAttestationProof({ ...validProof, computationEpoch: 99n });
      expect(relay.knownAgentCount()).toBe(1);
      expect(relay.lastAcceptedEpoch(validProof.agentId)).toBe(100n);
    });

    it('forgets a tracked agent and reopens its epoch range', async () => {
      await relay.verifyAttestationProof(validProof);
      expect(relay.forgetAgent(validProof.agentId)).toBe(true);
      expect(relay.knownAgentCount()).toBe(0);
      expect(relay.lastAcceptedEpoch(validProof.agentId)).toBeNull();
      const replayed = await relay.verifyAttestationProof(validProof);
      expect(replayed.valid).toBe(true);
    });

    it('returns false when forgetting an untracked agent', () => {
      expect(relay.forgetAgent(otherAgent)).toBe(false);
      expect(relay.knownAgentCount()).toBe(0);
    });

    it('clears every tracked agent at once', async () => {
      await relay.verifyAttestationProof(validProof);
      await relay.verifyAttestationProof({
        ...validProof,
        agentId: otherAgent,
        x402ReceiptHash: '0x5555555555555555555555555555555555555555555555555555555555555555',
      });
      expect(relay.knownAgentCount()).toBe(2);
      relay.clearKnownEpochs();
      expect(relay.knownAgentCount()).toBe(0);
      expect(relay.lastAcceptedEpoch(validProof.agentId)).toBeNull();
      expect(relay.lastAcceptedEpoch(otherAgent)).toBeNull();
    });

    it('rejects malformed agent IDs on cache reads and writes', () => {
      expect(() => relay.lastAcceptedEpoch('0x1234')).toThrow('32-byte hex string');
      expect(() => relay.forgetAgent('not-hex')).toThrow('32-byte hex string');
      expect(relay.knownAgentCount()).toBe(0);
    });
  });
});
