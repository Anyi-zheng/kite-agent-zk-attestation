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
  /**
   * Maps each accepted agentId (lowercased) to the highest epoch accepted in this batch.
   * Useful for callers that need to persist or display per-agent sequence progress.
   */
  perAgentLastAcceptedEpoch: Record<string, bigint>;
}

/**
 * Pipeline processor for high-frequency agent swarm attestations
 */
export class BatchAttestationPipeline {
  private relay: KiteZKAttestationRelay;

  constructor(relay: KiteZKAttestationRelay) {
    if (typeof relay?.verifyAttestationProof !== "function") {
      throw new TypeError("relay must provide a verifyAttestationProof function");
    }
    this.relay = relay;
  }

  public async processBatch(request: BatchAnchorRequest): Promise<BatchAnchorSummary> {
    // Reject non-array input up front: iterating a string or Set would otherwise be
    // reported as a batch of bogus per-character/per-item rejections.
    if (!Array.isArray(request?.proofs)) {
      throw new TypeError("request.proofs must be an array of attestation proofs");
    }

    // 批次开始后策略固定，异步验证期间调用方修改请求不能改变本次处理规则。
    const { strictEpochOrdering, stopOnFirstRejection } = request;
    const summary: BatchAnchorSummary = {
      totalProcessed: 0,
      acceptedCount: 0,
      rejectedCount: 0,
      anchoredDigests: [],
      rejections: [],
      perAgentLastAcceptedEpoch: {},
    };

    // Tracks the highest accepted epoch per agentId in this batch.
    const acceptedEpochs = new Map<string, bigint>();

    // Tracks the highest epoch observed in this batch per agentId if strict ordering is active
    const batchSeenEpochs = new Map<string, bigint>();

    // Iterate over a copy taken before the first await, so a caller that drains or refills
    // its queue while proofs are being verified cannot change which proofs this batch covers.
    for (const proof of [...request.proofs]) {
      summary.totalProcessed++;

      // Strict in-batch monotonicity check
      // Malformed entries skip this check and are rejected by the relay's schema validation
      // instead of crashing the whole batch.
      if (
        strictEpochOrdering &&
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

          if (stopOnFirstRejection) {
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
        // await 期间原证明对象可能已被调用方复用，归因只能使用中继实际验证的结果。
        const key = res.agentId.toLowerCase();
        batchSeenEpochs.set(key, res.epoch);
        const previous = acceptedEpochs.get(key);
        if (previous === undefined || res.epoch > previous) {
          acceptedEpochs.set(key, res.epoch);
        }
      } else {
        summary.rejectedCount++;
        summary.rejections.push({
          agentId: res.agentId,
          epoch: res.epoch,
          reason: res.rejectionReason ?? "Unknown validation failure",
        });

        if (stopOnFirstRejection) {
          break;
        }
      }
    }

    for (const [agentId, epoch] of acceptedEpochs) {
      summary.perAgentLastAcceptedEpoch[agentId] = epoch;
    }

    return summary;
  }
}
