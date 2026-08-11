# Release Notes

## Native Falcon-1024

APlane now supports Algorand protocol-native Falcon-1024 accounts under the
exact key type `falcon1024`. Generation and import are available on signer
nodes through the ordinary key-management workflows. Recovery uses a 25-word
Algorand mnemonic, signing emits top-level `PQsig` scheme `f1`, and APlane
accounts for the protocol's additional post-quantum fee contribution.

This type requires consensus v42 or an explicitly recognized compatible
network. It is distinct from the existing LogicSig type
`aplane.falcon1024.v1`, whose 24-word mnemonic, derivation, key material, and
TEAL authorization remain unchanged and are not convertible.

The implementation temporarily pins the official Algorand Go SDK commit
`967fcacfacdf` through pseudo-version
`v2.11.2-0.20260731180711-967fcacfacdf`. Return to the first tagged SDK release
that contains the same native-PQ wire types and v42 support.

## First supported release

This is APlane's first supported release. There is no supported migration from
earlier internal tags, including their stores, backup archives, or admin
protocols. Initialize a fresh store and create new credential backups with this
release.

`apstore endpoint export` now reads endpoint defaults through authenticated
admin IPC. The signer daemon must be running, and unattended scripts must
provide the same admin authentication used by other daemon-backed `apstore`
operations.

Pre-1.0 releases may intentionally make incompatible storage, archive, config,
or protocol changes when needed to establish a sound supported contract. This
is a pre-1.0 policy, not a permanent promise that every APlane release will be
incompatible. Before 1.0, each release's notes will state its compatibility and
migration requirements explicitly; the 1.0 release will define the stable
compatibility policy.
