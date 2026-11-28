import { describe, it, expect } from 'vitest';
import { AttestationPrunerDaemon } from '../src/pruner.js';

describe('README previewPrune example', () => {
  it('reports the documented candidate and exports its epoch as a decimal string', () => {
    const archive = new AttestationPrunerDaemon();
    const agentId = '0x' + '11'.repeat(32);
    const cutoff = 9007199254740994n;
    for (const epoch of [cutoff - 1n, cutoff]) {
      archive.recordAttestation({
        agentId,
        epoch,
        anchoredTimestamp: Date.now(),
        attestationDigest: '0x' + epoch.toString(16).padStart(64, '0'),
      });
    }

    const preview = archive.previewPrune({ targetAgentIds: [agentId], retentionEpochThreshold: cutoff });
    const json = JSON.parse(JSON.stringify(preview, (_, value) => typeof value === 'bigint' ? value.toString() : value));

    expect(json).toEqual({
      scannedCount: 2,
      prunedCount: 1,
      retainedCount: 1,
      prunedEpochs: [{ agentId, epoch: '9007199254740993' }],
    });
    expect(BigInt(json.prunedEpochs[0].epoch)).toBe(cutoff - 1n);
    expect(archive.getRecordCount()).toBe(2);
  });
});
