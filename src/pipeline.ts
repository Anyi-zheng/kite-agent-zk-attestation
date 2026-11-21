import { KiteZKAttestationRelay } from "./attestation.js";
import { AgentExecutionProof } from "./types.js";
import { type Hex } from "viem";

export interface BatchAnchorRequest {
  proofs: AgentExecutionProof[];
  /**
   * When true, verifies that sequential proofs for the same agentId have strictly increasing epochs.
   * If an out-of-order or duplicate epoch occurs within the batch, it is rejected immediately.
   */
  strictEpochOrdering?: boolean;
  /**
   * When true, halts execution on the first rejected attestation proof.
   * Default is false (best-effort partial settlement).
   */
  stopOnFirstRejection?: boolean;
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
      totalProcessed: 0,
      acceptedCount: 0,
      rejectedCount: 0,
      anchoredDigests: [],
      rejections: [],
    };

    // Tracks the highest epoch observed in this batch per agentId if strict ordering is active
    const batchSeenEpochs = new Map<string, bigint>();

    for (const proof of request.proofs) {
      summary.totalProcessed++;

      // Strict in-batch monotonicity check
      // Malformed entries skip this check and are rejected by the relay's schema validation
      // instead of crashing the whole batch.
      if (
        request.strictEpochOrdering &&
        typeof proof?.agentId === "string" &&
        typeof proof.computationEpoch === "bigint"
      ) {
        const lastSeen = batchSeenEpochs.get(proof.agentId.toLowerCase());
        if (lastSeen !== undefined && proof.computationEpoch <= lastSeen) {
          summary.rejectedCount++;
          summary.rejections.push({
            agentId: proof.agentId,
            epoch: proof.computationEpoch,
            reason: `Strict ordering violation: epoch ${proof.computationEpoch} is not strictly greater than previous batch epoch ${lastSeen}`,
          });

          if (request.stopOnFirstRejection) {
            break;
          }
          continue;
        }
        batchSeenEpochs.set(proof.agentId.toLowerCase(), proof.computationEpoch);
      }

      const res = await this.relay.verifyAttestationProof(proof);
      if (res.valid) {
        summary.acceptedCount++;
        summary.anchoredDigests.push(res.attestationDigest);
      } else {
        summary.rejectedCount++;
        summary.rejections.push({
          agentId: res.agentId,
          epoch: res.epoch,
          reason: res.rejectionReason ?? "Unknown validation failure",
        });

        if (request.stopOnFirstRejection) {
          break;
        }
      }
    }

    return summary;
  }
}
