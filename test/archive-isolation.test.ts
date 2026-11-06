import { expect, it } from 'vitest';
import { AttestationPrunerDaemon, type EpochArchiveEntry } from '../src/pruner.js';
const entry = (): EpochArchiveEntry => ({ agentId: '0x01', epoch: 5n, anchoredTimestamp: Date.now(), attestationDigest: '0x02' });
it('copies records at ingestion so later caller edits cannot change pruning', () => {
  const archive = new AttestationPrunerDaemon();
  const written = entry(); archive.recordAttestation(written);
  written.anchoredTimestamp = 0; written.epoch = 1n;
  expect(archive.prune({retentionEpochThreshold: 5n}).prunedCount).toBe(0);
  expect(archive.getRecords()[0]!.epoch).toBe(5n);
});
it('copies queried records and arrays so edits cannot remove retained data', () => {
  const archive = new AttestationPrunerDaemon(); archive.recordAttestation(entry());
  const read = archive.getRecords(); read[0]!.anchoredTimestamp = 0; read[0]!.epoch = 0n;
  expect(archive.prune({retentionEpochThreshold: 5n})).toMatchObject({prunedCount: 0, retainedCount: 1});
  expect(archive.getRecords()[0]!.epoch).toBe(5n);
});
