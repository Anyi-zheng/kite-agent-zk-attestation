import { type Hex } from 'viem';

export interface PruningFilter {
  maxAgeMs?: number;
  retentionEpochThreshold?: bigint;
}

export interface EpochArchiveEntry {
  agentId: Hex;
  epoch: bigint;
  anchoredTimestamp: number;
  attestationDigest: Hex;
}

export interface PruningReport {
  scannedCount: number;
  prunedCount: number;
  retainedCount: number;
  prunedEpochs: Array<{ agentId: Hex; epoch: bigint }>;
}

/**
 * AttestationPrunerDaemon
 * Manages cache lifecycle and purges expired epoch attestation proofs from local hot storage
 */
export class AttestationPrunerDaemon {
  private archive: EpochArchiveEntry[] = [];
  private defaultMaxAgeMs: number;

  constructor(defaultMaxAgeMs: number = 86_400_000) {
    this.defaultMaxAgeMs = defaultMaxAgeMs;
  }

  public recordAttestation(entry: EpochArchiveEntry): void {
    this.archive.push(entry);
  }

  public getRecordCount(): number {
    return this.archive.length;
  }

  public getRecords(): readonly EpochArchiveEntry[] {
    return [...this.archive];
  }

  /**
   * Runs GC cycle based on age and epoch boundaries
   */
  public prune(filter: PruningFilter = {}): PruningReport {
    const maxAgeMs = filter.maxAgeMs ?? this.defaultMaxAgeMs;
    const now = Date.now();
    const thresholdEpoch = filter.retentionEpochThreshold;

    const retained: EpochArchiveEntry[] = [];
    const pruned: EpochArchiveEntry[] = [];

    for (const item of this.archive) {
      const isExpiredByAge = now - item.anchoredTimestamp > maxAgeMs;
      const isExpiredByEpoch = thresholdEpoch !== undefined && item.epoch < thresholdEpoch;

      if (isExpiredByAge || isExpiredByEpoch) {
        pruned.push(item);
      } else {
        retained.push(item);
      }
    }

    this.archive = retained;

    return {
      scannedCount: retained.length + pruned.length,
      prunedCount: pruned.length,
      retainedCount: retained.length,
      prunedEpochs: pruned.map((p) => ({ agentId: p.agentId, epoch: p.epoch })),
    };
  }
}
