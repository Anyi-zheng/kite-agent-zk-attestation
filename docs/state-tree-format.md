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
