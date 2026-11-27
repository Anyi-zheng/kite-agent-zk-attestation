import { type Hex, isHex } from 'viem';

export interface PruningFilter {
  maxAgeMs?: number;
  retentionEpochThreshold?: bigint;
  /**
   * Optional whitelist of agent IDs to selectively prune or retain.
   */
  targetAgentIds?: Hex[];
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

function assertMaxAgeMs(value: number, field: string): void {
  if (!Number.isFinite(value) || value < 0) {
    throw new RangeError(`${field} must be a non-negative finite number`);
  }
}

function assertHexString(value: unknown, field: string): void {
  if (typeof value !== 'string' || !isHex(value)) {
    throw new TypeError(`${field} must be a hex string (0x...)`);
  }
}

function assertEntry(entry: EpochArchiveEntry): void {
  if (typeof entry !== 'object' || entry === null) {
    throw new TypeError('entry must be an object');
  }
  assertHexString(entry.agentId, 'agentId');
  assertHexString(entry.attestationDigest, 'attestationDigest');
  if (typeof entry.epoch !== 'bigint' || entry.epoch < 1n || entry.epoch >= 2n ** 256n) {
    throw new RangeError('epoch must be a positive bigint between 1 and 2^256 - 1');
  }
}

/**
 * AttestationPrunerDaemon
 * Manages cache lifecycle and purges expired epoch attestation proofs from local hot storage
 */
export class AttestationPrunerDaemon {
  private archive: EpochArchiveEntry[] = [];
  private defaultMaxAgeMs: number;
  private maxRetainedCapacity?: number;

  constructor(defaultMaxAgeMs: number = 86_400_000, maxRetainedCapacity?: number) {
    assertMaxAgeMs(defaultMaxAgeMs, 'defaultMaxAgeMs');
    this.defaultMaxAgeMs = defaultMaxAgeMs;
    if (maxRetainedCapacity !== undefined
      && (!Number.isSafeInteger(maxRetainedCapacity) || maxRetainedCapacity <= 0)) {
      throw new RangeError('maxRetainedCapacity must be a positive safe integer');
    }
    this.maxRetainedCapacity = maxRetainedCapacity;
  }

  public recordAttestation(entry: EpochArchiveEntry): void {
    assertEntry(entry);
    if (!Number.isFinite(entry.anchoredTimestamp) || entry.anchoredTimestamp <= 0) {
      throw new RangeError('anchoredTimestamp must be a positive finite number');
    }
    this.archive.push({ ...entry });

    // Enforce high-watermark capacity if set
    if (this.maxRetainedCapacity !== undefined && this.archive.length > this.maxRetainedCapacity) {
      while (this.archive.length > this.maxRetainedCapacity) {
        // Epochs are only ordered within one agent, so they cannot determine
        // which record is oldest across the whole archive. On timestamp ties,
        // retaining the first index preserves FIFO insertion order.
        let oldestIndex = 0;
        for (let i = 1; i < this.archive.length; i++) {
          if (this.archive[i].anchoredTimestamp < this.archive[oldestIndex].anchoredTimestamp) {
            oldestIndex = i;
          }
        }
        this.archive.splice(oldestIndex, 1);
      }
    }
  }

  public getRecordCount(): number {
    return this.archive.length;
  }

  public getRecords(): readonly EpochArchiveEntry[] {
    return this.archive.map((entry) => ({ ...entry }));
  }

  public getRecordsByAgent(agentId: Hex): readonly EpochArchiveEntry[] {
    const target = agentId.toLowerCase();
    return this.archive
      .filter((entry) => entry.agentId.toLowerCase() === target)
      .map((entry) => ({ ...entry }));
  }

  /**
   * Runs GC cycle based on age, epoch boundaries, and optional agent filters
   */
  public prune(filter: PruningFilter = {}): PruningReport {
    const retained: EpochArchiveEntry[] = [];
    const report = this.scanArchive(filter, retained);
    this.archive = retained;
    return report;
  }

  /** Report what prune would remove from the current archive at the current time. */
  public previewPrune(filter: PruningFilter = {}): PruningReport {
    return this.scanArchive(filter);
  }

  private scanArchive(filter: PruningFilter, retained?: EpochArchiveEntry[]): PruningReport {
    const maxAgeMs = filter.maxAgeMs ?? this.defaultMaxAgeMs;
    assertMaxAgeMs(maxAgeMs, 'maxAgeMs');
    const now = Date.now();
    const thresholdEpoch = filter.retentionEpochThreshold;
    if (thresholdEpoch !== undefined && (typeof thresholdEpoch !== 'bigint' || thresholdEpoch < 0n)) {
      throw new RangeError('retentionEpochThreshold must be a non-negative bigint');
    }
    if (filter.targetAgentIds !== undefined) {
      // An empty string is iterable and falsy: it would pass the entry check below and
      // then drop the whitelist, widening the prune to every agent.
      if (!Array.isArray(filter.targetAgentIds)) {
        throw new TypeError('targetAgentIds must be an array of hex strings');
      }
      for (const id of filter.targetAgentIds) {
        if (!isHex(id)) {
          throw new Error('targetAgentIds entries must be hex strings');
        }
      }
    }
    const targetAgents = filter.targetAgentIds
      ? new Set(filter.targetAgentIds.map(id => id.toLowerCase()))
      : undefined;

    const prunedEpochs: PruningReport['prunedEpochs'] = [];

    for (const item of this.archive) {
      const matchesAgent = !targetAgents || targetAgents.has(item.agentId.toLowerCase());
      if (matchesAgent) {
        const isExpiredByAge = now - item.anchoredTimestamp > maxAgeMs;
        const isExpiredByEpoch = thresholdEpoch !== undefined && item.epoch < thresholdEpoch;

        if (isExpiredByAge || isExpiredByEpoch) {
          prunedEpochs.push({ agentId: item.agentId, epoch: item.epoch });
          continue;
        }
      }
      retained?.push(item);
    }

    return {
      scannedCount: this.archive.length,
      prunedCount: prunedEpochs.length,
      retainedCount: this.archive.length - prunedEpochs.length,
      prunedEpochs,
    };
  }
}
