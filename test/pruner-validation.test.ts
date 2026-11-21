import { describe, it, expect } from 'vitest';
import { AttestationPrunerDaemon } from '../src/pruner.js';
import { type Hex } from 'viem';

const agent: Hex = '0x1111111111111111111111111111111111111111111111111111111111111111';
const digest: Hex = '0xaaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111';

describe('AttestationPrunerDaemon constructor validation', () => {
  it.each([-1, 0, 1.5, Number.NaN])('rejects invalid maxRetainedCapacity %s', (capacity) => {
    expect(() => new AttestationPrunerDaemon(3600_000, capacity)).toThrow(RangeError);
  });

  it.each([-1, Number.NaN, Number.POSITIVE_INFINITY])('rejects invalid defaultMaxAgeMs %s', (maxAge) => {
    expect(() => new AttestationPrunerDaemon(maxAge)).toThrow(RangeError);
  });

  it('accepts a capacity of 1 and keeps only the newest epoch', () => {
    const daemon = new AttestationPrunerDaemon(3600_000, 1);
    for (const epoch of [1n, 2n, 3n]) {
      daemon.recordAttestation({ agentId: agent, epoch, anchoredTimestamp: Date.now(), attestationDigest: digest });
    }
    expect(daemon.getRecordCount()).toBe(1);
    expect(daemon.getRecords()[0].epoch).toBe(3n);
  });

  it('keeps unbounded behaviour when capacity is omitted', () => {
    const daemon = new AttestationPrunerDaemon();
    daemon.recordAttestation({ agentId: agent, epoch: 1n, anchoredTimestamp: Date.now(), attestationDigest: digest });
    expect(daemon.getRecordCount()).toBe(1);
  });
});

describe('AttestationPrunerDaemon.recordAttestation validation', () => {
  const valid = { agentId: agent, epoch: 1n, anchoredTimestamp: Date.now(), attestationDigest: digest };

  it.each([
    ['agentId', { agentId: undefined }],
    ['agentId', { agentId: 'not-hex' }],
    ['attestationDigest', { attestationDigest: 12 }],
    ['epoch', { epoch: 'abc' }],
    ['epoch', { epoch: 0n }],
    ['epoch', { epoch: 2n ** 256n }],
  ])('rejects a malformed %s without storing the entry', (_field, override) => {
    const daemon = new AttestationPrunerDaemon();
    expect(() => daemon.recordAttestation({ ...valid, ...override } as never)).toThrow();
    expect(daemon.getRecordCount()).toBe(0);
    expect(() => daemon.getRecordsByAgent(agent)).not.toThrow();
    expect(() => daemon.prune({ targetAgentIds: [agent] })).not.toThrow();
  });

  it('rejects a non-object entry', () => {
    expect(() => new AttestationPrunerDaemon().recordAttestation(null as never)).toThrow(TypeError);
  });
});
