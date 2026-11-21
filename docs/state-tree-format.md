# State tree format

The old demo fold discarded the left input of each pair. Its roots do not
commit all actions and must not be used as integrity evidence.

The corrected format accepts 32-byte action digests. Leaves are
`keccak256(0x00 || digest)` and internal nodes are
`keccak256(0x01 || left || right)`. Order is significant. An unpaired node
is promoted unchanged; an empty tree retains the all-zero sentinel.

All nonempty roots change, including single-leaf trees. Rebuild trees from
their original ordered action digests and version any stored root metadata.
Do not compare a legacy root with a corrected root or claim old attestations
were retroactively verified. This changes the state commitment only; it does
not introduce a ZK circuit or verify on-chain attestations.

## Disclosing a single action

Call `tree.getInclusionPath(index)` with a zero-based index into the ordered
action digests. Send the digest and returned sibling steps to the reader.
Start with the tagged leaf hash described above. For each step, use its
position to place the sibling on the indicated side of the running hash,
then apply the tagged internal hash. Compare the final hash to the trusted
state root in the Kite attestation. Promoted nodes have no step. A
single-action tree has an empty path. Invalid indices throw RangeError.
Generate a fresh path after appending actions to match the new root.
The first root or path query on a nonempty tree builds and retains O(n)
hashes. Until the next append, reading the root takes O(1) time and
generating another path takes O(log n) time.

The reader can call the exported helper directly:

```ts
const included = verifyInclusionPath(actionDigest, siblingSteps, trustedStateRoot);
```

Obtain the root independently from the attestation being checked. The
function checks membership of the action digest and returns false on a
mismatch or malformed step. It does not establish an action index, tree
size, or correctness of the attestation's ZK proof.
