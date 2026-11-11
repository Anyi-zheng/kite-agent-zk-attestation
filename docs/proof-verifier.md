# Explicit proof verification

`verifyAttestationProof` no longer treats payload length as proof validity.
Constructing the relay without a second argument now returns an invalid result.
Supply a verifier that checks the selected proof system and binds the proof to
all four public inputs. A verifier returning false, throwing, or returning any
value other than true leaves the epoch cache unchanged.

The injected `() => true` functions in tests are fixtures, not production
verifiers. This proposal does not provide a Groth16 circuit or verification key.
An application must select and audit those independently before using the API
as cryptographic evidence. Accepted digests and the batch `anchoredDigests`
collection remain local results; no transaction is submitted or confirmed.

This is an intentional behavior change for callers that previously relied on
mock validation. The missing-verifier result is fail-closed, rather than a
fallback to the former mock. Concurrent completions cannot move epochs back.
