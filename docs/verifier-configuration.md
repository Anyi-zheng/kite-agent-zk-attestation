# Verifier configuration

The registry requires a deployed verifier contract at construction and on every
update. A zero address or an externally owned account is rejected. The anchor
path rechecks code presence and always invokes verification before writing a
record or changing the latest epoch. Only the owner can change the verifier.

This intentionally removes the implicit zero-address bypass. Deploy tests with
`MockGroth16Verifier` rather than disabling verification. That mock is not a
production verifier; code presence is a configuration check and does not prove
the configured contract implements a correct proof system. Production still
requires an independently selected, audited verifier and matching circuit.

These source changes do not upgrade an existing deployment or establish the
provenance of addresses in the README. Existing deployments need a separately
reviewed migration. No live-chain transaction is part of this proposal.
