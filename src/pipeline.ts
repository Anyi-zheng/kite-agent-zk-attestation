import { KiteZKAttestationRelay } from './attestation.js';
import { AgentExecutionProof } from './types.js';
import { type Hex } from 'viem';

export interface BatchAnchorRequest {
  proofs: AgentExecutionProof[];
  strictEpochOrdering?: boolean;
}

export interface BatchAnchorSummary {
  totalProcessed: number;
  acceptedCount: number;
  rejectedCount: number;
  anchoredDigests: Hex[];
  rejections: Array<{
    agentId: Hex;
    epoch: bigint;
    reason: string;
  }>;
}

/**
 * Pipeline processor for high-frequency agent swarm attestations
 */
export class BatchAttestationPipeline {
  private relay: KiteZKAttestationRelay;

  constructor(relay: KiteZKAttestationRelay) {
    this.relay = relay;
  }

  public async processBatch(request: BatchAnchorRequest): Promise<BatchAnchorSummary> {
    const summary: BatchAnchorSummary = {
      totalProcessed: request.proofs.length,
      acceptedCount: 0,
      rejectedCount: 0,
      anchoredDigests: [],
      rejections: [],
    };

    for (const proof of request.proofs) {
      const res = await this.relay.verifyAttestationProof(proof);
      if (res.valid) {
        summary.acceptedCount++;
        summary.anchoredDigests.push(res.attestationDigest);
      } else {
        summary.rejectedCount++;
        summary.rejections.push({
          agentId: res.agentId,
          epoch: res.epoch,
          reason: res.rejectionReason ?? 'Unknown validation failure',
        });
      }
    }

    return summary;
  }
}
