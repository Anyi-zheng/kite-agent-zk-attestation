import { describe, it, expect, beforeEach } from 'vitest';
import { AttestationPrunerDaemon } from '../src/pruner.js';
import { type Hex } from 'viem';

describe('AttestationPrunerDaemon', () => {
  let daemon: AttestationPrunerDaemon;

  const agent1: Hex = '0x1111111111111111111111111111111111111111111111111111111111111111';
  const digest1: Hex = '0xaaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111';

  beforeEach(() => {
    daemon = new AttestationPrunerDaemon(3600_000); // 1 hour default
  });

  it('records new attestation entries', () => {
    daemon.recordAttestation({
      agentId: agent1,
      epoch: 10n,
      anchoredTimestamp: Date.now(),
      attestationDigest: digest1,
    });

    expect(daemon.getRecordCount()).toBe(1);
    expect(daemon.getRecords()[0].epoch).toBe(10n);
  });

  it('prunes expired entries by timestamp age', () => {
    const twoHoursAgo = Date.now() - 7200_000;
    daemon.recordAttestation({
      agentId: agent1,
      epoch: 5n,
      anchoredTimestamp: twoHoursAgo,
      attestationDigest: digest1,
    });
    daemon.recordAttestation({
      agentId: agent1,
      epoch: 10n,
      anchoredTimestamp: Date.now(),
      attestationDigest: digest1,
    });

    const report = daemon.prune();
    expect(report.scannedCount).toBe(2);
    expect(report.prunedCount).toBe(1);
    expect(report.retainedCount).toBe(1);
    expect(daemon.getRecordCount()).toBe(1);
    expect(daemon.getRecords()[0].epoch).toBe(10n);
  });

  it('prunes entries by retention epoch threshold', () => {
    daemon.recordAttestation({
      agentId: agent1,
      epoch: 5n,
      anchoredTimestamp: Date.now(),
      attestationDigest: digest1,
    });
    daemon.recordAttestation({
      agentId: agent1,
      epoch: 15n,
      anchoredTimestamp: Date.now(),
      attestationDigest: digest1,
    });

    const report = daemon.prune({ retentionEpochThreshold: 10n });
    expect(report.prunedCount).toBe(1);
    expect(report.retainedCount).toBe(1);
    expect(daemon.getRecords()[0].epoch).toBe(15n);
  });
});
