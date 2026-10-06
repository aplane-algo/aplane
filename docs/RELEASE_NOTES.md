# Release Notes

## Edit policy JSON in apadmin

The apadmin TUI can now edit a policy document in place. In Policies (`p`),
press `e` on a policy to open its JSON in an editor, and `ctrl+s` to check it.
The edit goes through the same check, diff review, and confirmed apply as a
loaded policy file; nothing is stored before the apply.

A cosigner key that has no policy opens on a starting document with no routes,
which rejects every request, so a new key's policy is always edited up from
zero permissions. Syntax errors are reported with a line and column, a rejected
document keeps the editor open with the node's problems, and leaving the review
returns to the editor with the text intact.

No policy format, admin RPC, or stored state changed: a key with no policy
still has no stored document until one is applied.

## Cosigner setup in three actions and `endpoints add`

Setting up a cosigner-protected account now takes three actions with one public
setup file: export it on the cosigner, choose it while generating the account
on the signer, and run `endpoints add <file>` on each client.

- apshell `endpoints add` replaces `cosigner add`, which still works and
  forwards with a notice. The command stores a connection to a cosigner, not a
  key, so a later key on the same cosigner needs no client change and running
  the command again reuses the existing connection without prompts. The
  connection name is suggested from the endpoint host.
- Guided setup confirms through `/status` that the node is a cosigner, and
  reports the connection, the key from the file, and account routes as separate
  results. It fails only for the connection being added, so cosigners can be
  set up one at a time.
- apadmin's account-generation **Cosigner** field offers **Use setup file...**
  and **Paste public JSON...**, and reuses a key that is already imported. The
  Cosigners manager is no longer a required step. The cosigner-side export is
  labelled **Export Setup File**.
- `endpoints add` is blocked through MCP; other `endpoints` subcommands are
  unchanged.

No file format, admin RPC, HTTP API, or SDK contract changed.

### Fix: a replaced endpoint no longer inherits the previous token

An endpoint token is now presented only to the destination that issued it.
Previously, replacing an alias's URL or SSH-backed API port left the previous
destination's token in place, so `endpoints import`, `endpoints create`, or an
interrupted and rerun `cosigner add` could present it to the new destination.

A token now lives and dies with one endpoint:

- Creating an endpoint removes any token file already at its path.
- Changing an endpoint's destination removes its token before the new route is
  written.
- `endpoints delete` removes the endpoint's token with it.
- `request-token` discards a token whose endpoint changed while the request
  awaited approval.

A token file that another endpoint also uses is never removed; creating or
re-pointing an endpoint onto it is refused instead.

**Action needed for manually installed tokens:** install the token file after
the endpoint exists. A token copied into place before `endpoints import`,
`endpoints create`, or `endpoints add` creates the endpoint is removed, and the
output says so. After changing a destination, request or install a token for
the new one.

## Unified guarded and bounded-cosigner signing flow

Guarded and bounded-cosigner signing now share `/plan`, `/sign/component`, and
`/sign/assemble`. Component requests use explicit `user`, `cosigner`, or
`bounded-base` targets over one frozen group; assembly uses discriminated
`guarded` or `bounded-cosigner` targets. `/plan` is the sole canonicalizer, and
bounded authorization is reconstructed from signer-held metadata before the
operator approves the exact frozen bytes.

The pre-release `/sign/bounded-component` and `/sign/bounded-assemble` routes
were removed and return 404. SDK callers must use `requestComponents` and
`requestAssemble` (with language-appropriate naming). Mixed `cosigner1` and
`bounded-cosigner1` targets remain rejected pending an atomic multi-gate signing
implementation. Contract-admin `bounded1` remains separate through `aprekey`
and `/sign/bounded-admin`.

## Fixed single-product runtime

APlane is a single-operator, single-signing-authority product. Every
signer or cosigner process owns exactly one runtime at `identities/default/`.
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
