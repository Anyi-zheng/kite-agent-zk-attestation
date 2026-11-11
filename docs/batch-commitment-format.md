# Proof batch commitments v1

This module produces an ordered commitment to proof bytes and public inputs. It does not verify those proofs, produce a recursive SNARK, or reduce the proof bytes needed for verification.

Each item digest is keccak256(abi.encode(itemDomain, agentId, stateHash, computationEpoch, x402ReceiptHash, zkProof)), with types bytes32, bytes32, bytes32, uint256, bytes32, bytes. itemDomain is keccak256 of UTF-8 kite-proof-item-v1. The batch commitment is keccak256(abi.encode(batchDomain, itemCount, itemDigests)), with types bytes32, uint256, bytes32[]. batchDomain is keccak256 of UTF-8 kite-proof-batch-v1. Order and duplicate occurrences are retained; timestamps are local metadata, not part of the public inputs.

Every previous node ID and aggregate changes. Recompute identifiers from complete original proofs, version persisted metadata, and never mix these digests with the former truncated/XOR format. A digest alone cannot reconstruct a proof.

Prefer commitProofs(). foldProofs() preserves the legacy object fields, but aggregatedProof and nodeId both hold this commitment and depth is zero. evaluateCompression() reports the original byte count as unchanged, ratio one and recursion depth zero. Real recursive proving requires a circuit, proving/verifying keys and an independently verified prover/verifier integration.
