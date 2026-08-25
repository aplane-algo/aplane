# Release Notes

## Unified guarded and bounded-sentry signing flow

Guarded and bounded-sentry signing now share `/plan`, `/sign/component`, and
`/sign/assemble`. Component requests use explicit `user`, `sentry`, or
`bounded-base` targets over one frozen group; assembly uses discriminated
`guarded` or `bounded-sentry` targets. `/plan` is the sole canonicalizer, and
bounded authorization is reconstructed from signer-held metadata before the
operator approves the exact frozen bytes.

The pre-release `/sign/bounded-component` and `/sign/bounded-assemble` routes
were removed and return 404. SDK callers must use `requestComponents` and
`requestAssemble` (with language-appropriate naming). Mixed `sentry1` and
`bounded-sentry1` targets remain rejected pending an atomic multi-gate signing
implementation. Contract-admin `bounded1` remains separate through `aprekey`
and `/sign/bounded-admin`.

## Fixed single-product runtime

APlane is a single-operator, single-signing-authority product. Every
signer or sentry process owns exactly one runtime at `identities/default/`.
Any additional direct entry under `identities/` fails startup before token,
key, policy, template, or watcher loading. HTTP and SSH bind the fixed product
runtime; admin protocol v5 and product CLIs expose no runtime selector.

The runtime has no runtime routing, keyed admin-session registry, mutable grant
graph, or owner-keyed template-provider accounting. SDK token enrollment uses
the fixed SSH username `request-token`; normal SSH uses `aplane`. HTTP status,
admin protocol, and audit records carry no runtime identifier.

## Native Falcon-1024

APlane now supports Algorand protocol-native Falcon-1024 accounts under the
exact key type `falcon1024`. Generation and import are available on signer
nodes through the ordinary key-management workflows. Recovery uses a 25-word
Algorand mnemonic, signing emits top-level `PQsig` scheme `f1`, and APlane
accounts for the protocol's additional post-quantum fee contribution.

This release supports exactly the consensus-v42 authorization contract. It is
distinct
from the LogicSig type `aplane.falcon1024.v1`, whose
24-word mnemonic and LogicSig key material are not convertible to native
Falcon.

The implementation temporarily pins the official Algorand Go SDK commit
`967fcacfacdf` through pseudo-version
`v2.11.2-0.20260731180711-967fcacfacdf`. Return to the first tagged SDK release
that contains the same native-PQ wire types and v42 support.

## TEAL v13 LogicSig planning

Bundled APlane LogicSig key types now compile as TEAL v13 and use algod's
compiler-owned auto-salting. APlane persists the final compiler-returned
bytecode and independently verifies its derived address is off-curve. Because
this is a pre-release in-place migration, previously generated development
LogicSig keys and addresses must be regenerated.

Group planning now models LogicSig program bytes, argument bytes, and opcode
cost separately under one compiled v42 contract. Dummies are added only for
pooled arguments or opcode capacity; excess program bytes are paid through the
group-wide consensus fee. Clients validate algod's consensus identifier and
own ordinary transaction fee selection. The signer does not contact a network
algod during `/plan` or `/sign`; it adds only authorization-induced dummy,
program, and native-PQ fees. Foreign slots use the structured
`lsig_resources` wire field, replacing the former combined `lsig_size` scalar.
Plugins and SDKs must provide `programBytes`, `argumentBytes`, and
`maxOpcodeCost` and use the signer's `/plan` output as the canonical group.
Passthrough LogicSig requests must retain that structured declaration through
final `/sign`; apsigner verifies the observable program/argument sizes and uses
the reviewed opcode ceiling instead of guessing. First-party executable paths
also refresh the live algod v42 check before signature release or verbatim
pregrouped submission. First-party `plan()` performs the same check; the
apsigner `/plan` endpoint remains network-independent.
The breaking plugin wire change uses the one-way protocol declaration
`initialize.result.protocol: "aplane-plugin/2"`; the host sends no protocol
token that a legacy plugin could echo. JavaScript
`plan()` and `presign-plan` plugin signers can declare native Falcon foreign
slots with `pqScheme: "f1"` so the planner includes their PQ fee contribution.

## First supported release

This is APlane's first supported release. There is no supported migration from
earlier internal tags, including their stores, backup archives, or admin
protocols. Initialize a fresh store and create new credential backups with this
release.

`apadmin endpoint export` now reads endpoint defaults through authenticated
admin IPC. The signer daemon must be running, and unattended scripts must
provide the same admin authentication used by other live `apadmin`
operations.

Pre-1.0 releases may intentionally make incompatible storage, archive, config,
or protocol changes when needed to establish a sound supported contract. This
is a pre-1.0 policy, not a permanent promise that every APlane release will be
incompatible. Before 1.0, each release's notes will state its compatibility and
migration requirements explicitly; the 1.0 release will define the stable
compatibility policy.
