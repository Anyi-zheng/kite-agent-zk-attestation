import { describe, it, expect } from "vitest";
import { KiteZKAttestationRelay } from "../src/attestation.js";
import { BatchAttestationPipeline } from "../src/pipeline.js";
import { AgentExecutionProof, KITE_TESTNET_CONFIG } from "../src/types.js";

describe("BatchAttestationPipeline", () => {
  it("bundles and processes heterogeneous agent attestation batches", async () => {
    const relay = new KiteZKAttestationRelay(KITE_TESTNET_CONFIG, () => true);
    const pipeline = new BatchAttestationPipeline(relay);

    const proofs: AgentExecutionProof[] = [
      {
        agentId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        stateHash: "0x1111111111111111111111111111111111111111111111111111111111111111",
        computationEpoch: 10n,
        x402ReceiptHash: "0x2222222222222222222222222222222222222222222222222222222222222222",
        zkProof: "0x1234567890abcdef",
      },
      {
        agentId: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        stateHash: "0x3333333333333333333333333333333333333333333333333333333333333333",
        computationEpoch: 15n,
        x402ReceiptHash: "0x4444444444444444444444444444444444444444444444444444444444444444",
        zkProof: "0xabcdef1234567890",
      },
      {
        // Replayed epoch for agent A
        agentId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        stateHash: "0x5555555555555555555555555555555555555555555555555555555555555555",
        computationEpoch: 8n,
        x402ReceiptHash: "0x6666666666666666666666666666666666666666666666666666666666666666",
        zkProof: "0xabcdef1234567890",
      },
    ];

    const res = await pipeline.processBatch({ proofs });
    expect(res.totalProcessed).toBe(3);
    expect(res.acceptedCount).toBe(2);
    expect(res.rejectedCount).toBe(1);
    expect(res.anchoredDigests).toHaveLength(2);
    expect(res.rejections[0].reason).toContain("Epoch rollback or replay");
  });

  it("enforces strict in-batch epoch ordering when strictEpochOrdering is enabled", async () => {
    const relay = new KiteZKAttestationRelay(KITE_TESTNET_CONFIG, () => true);
    const pipeline = new BatchAttestationPipeline(relay);

    const agentId = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const proofs: AgentExecutionProof[] = [
      {
        agentId,
        stateHash: "0x1111111111111111111111111111111111111111111111111111111111111111",
        computationEpoch: 10n,
        x402ReceiptHash: "0x2222222222222222222222222222222222222222222222222222222222222222",
        zkProof: "0x1111",
      },
      {
        // Non-increasing epoch within same batch
        agentId,
        stateHash: "0x2222222222222222222222222222222222222222222222222222222222222222",
        computationEpoch: 10n,
        x402ReceiptHash: "0x3333333333333333333333333333333333333333333333333333333333333333",
        zkProof: "0x2222",
      },
      {
        agentId,
        stateHash: "0x3333333333333333333333333333333333333333333333333333333333333333",
        computationEpoch: 12n,
        x402ReceiptHash: "0x4444444444444444444444444444444444444444444444444444444444444444",
        zkProof: "0x3333",
      },
    ];

    const res = await pipeline.processBatch({ proofs, strictEpochOrdering: true });
    expect(res.totalProcessed).toBe(3);
    expect(res.acceptedCount).toBe(2);
    expect(res.rejectedCount).toBe(1);
    expect(res.rejections[0].reason).toContain("Strict ordering violation");
  });

  it("aborts execution early when stopOnFirstRejection is enabled", async () => {
    const relay = new KiteZKAttestationRelay(KITE_TESTNET_CONFIG, () => true);
    const pipeline = new BatchAttestationPipeline(relay);

    const agentId = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const proofs: AgentExecutionProof[] = [
      {
        agentId,
        stateHash: "0x1111111111111111111111111111111111111111111111111111111111111111",
        computationEpoch: 10n,
        x402ReceiptHash: "0x2222222222222222222222222222222222222222222222222222222222222222",
        zkProof: "0x1111",
      },
      {
        // Out-of-order rejection
        agentId,
        stateHash: "0x2222222222222222222222222222222222222222222222222222222222222222",
        computationEpoch: 5n,
        x402ReceiptHash: "0x3333333333333333333333333333333333333333333333333333333333333333",
        zkProof: "0x2222",
      },
      {
        // Should not be processed
        agentId,
        stateHash: "0x3333333333333333333333333333333333333333333333333333333333333333",
        computationEpoch: 20n,
        x402ReceiptHash: "0x4444444444444444444444444444444444444444444444444444444444444444",
        zkProof: "0x3333",
      },
    ];

    const res = await pipeline.processBatch({
      proofs,
      strictEpochOrdering: true,
      stopOnFirstRejection: true,
    });

    expect(res.totalProcessed).toBe(2);
    expect(res.acceptedCount).toBe(1);
    expect(res.rejectedCount).toBe(1);
  });

  it("keeps rejected proofs in the strict in-batch epoch sequence", async () => {
    const relay = new KiteZKAttestationRelay(
      KITE_TESTNET_CONFIG,
      (proof) => proof.computationEpoch !== 100n
    );
    const pipeline = new BatchAttestationPipeline(relay);
    const agentId = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const proofs = [100n, 99n, 101n].map((computationEpoch) => ({
      agentId,
      stateHash: "0x1111111111111111111111111111111111111111111111111111111111111111",
      computationEpoch,
      x402ReceiptHash: "0x2222222222222222222222222222222222222222222222222222222222222222",
      zkProof: "0x1234567890abcdef",
    }));

    const res = await pipeline.processBatch({ proofs, strictEpochOrdering: true });
    expect(res.totalProcessed).toBe(3);
    expect(res.acceptedCount).toBe(1);
    expect(res.rejectedCount).toBe(2);
    expect(res.rejections[0].reason).toContain("Proof verification failed");
    expect(res.rejections[1].reason).toContain("Strict ordering violation");
    expect(res.anchoredDigests).toHaveLength(1);
  });

  it("rejects malformed proofs without throwing when strictEpochOrdering is enabled", async () => {
    const relay = new KiteZKAttestationRelay(KITE_TESTNET_CONFIG, () => true);
    const pipeline = new BatchAttestationPipeline(relay);

    const valid = {
      agentId: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      stateHash: "0x1111111111111111111111111111111111111111111111111111111111111111",
      computationEpoch: 1n,
      x402ReceiptHash: "0x2222222222222222222222222222222222222222222222222222222222222222",
      zkProof: "0x1234567890abcdef",
    } as AgentExecutionProof;
    const malformed = { stateHash: valid.stateHash, computationEpoch: 2n } as unknown as AgentExecutionProof;

    const res = await pipeline.processBatch({ proofs: [malformed, valid], strictEpochOrdering: true });
    expect(res.totalProcessed).toBe(2);
    expect(res.acceptedCount).toBe(1);
    expect(res.rejectedCount).toBe(1);
    expect(res.rejections[0].reason).toContain("Schema validation failed");
  });
});
