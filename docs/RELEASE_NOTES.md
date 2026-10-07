# Release Notes

## Enrollment requests wait for the operator

`request-enrollment` no longer waits for the operator. The node queues the
request and answers `pending <fingerprint>` at once; apshell prints that the
request is waiting and returns. The operator approves or rejects it whenever
convenient: it pops up in `apadmin` if an operator is connected, every
waiting request is shown again at the next login, and the **Enrolled
Clients** screen lists them under *Waiting for approval* (`a` approve, `x`
reject). `apapprover` shows them too and answers by fingerprint. Once
approved, the client runs `connect`. The old "no operator connected"
refusal, the wait for approval, the one-request-at-a-time limit, and the
preemption of an enrollment prompt by a signing request are gone, along with
the `client_enrollment_response` and `client_enrollment_request_canceled`
admin messages.

The queue is `identities/default/.ssh/pending_enrollments.json`, written only
by the daemon and loaded at startup like the registry, so requests survive a
restart. It holds one entry per key (a repeat refreshes it), at most 16 keys,
and drops an entry after 7 days. A client that finds the queue full is told
so.

The operator can also pre-enroll a client without a request from it, by
importing its public key file: `i` on the Enrolled Clients screen, or
`apadmin clients import <public-key-file|-> [--label <text>]`. The new batch
commands `apadmin clients list|approve|reject|revoke|import` cover the whole
registry without the TUI. Admin protocol: `list_pending_enrollments`,
`approve_enrollment`, `reject_enrollment`, and `import_client_key` (with their
results), and `pending_count` on `enrolled_keys_list`. Audit logs record
`CLIENT_ENROLLMENT_REQUESTED` when a request is queued and
`CLIENT_ENROLLMENT_REJECTED` when one is rejected; `CLIENT_ENROLLED` now
carries the approving admin session.

Guided cosigner setup (`endpoints add`) submits the enrollment request and
stops with the connection configured when the cosigner's operator has to
approve it; rerun setup afterwards. The SDKs' `requestEnrollment` now reports
whether the request is pending.

## The client's SSH key is its only credential

The API token is gone. A client no longer holds `aplane.token` or
`tokens/<alias>.token`, no request carries an `Authorization` header, and the
signer no longer keeps a product token under `identities/default/`. A client
authenticates once, at the SSH handshake, with the key the operator enrolled;
the node's SSH server hands each tunneled API channel to its REST handler with
that identity (`client:<SHA256 fingerprint>`) attached. The daemon's loopback
REST port carries no identity and now answers only `GET /health`.

`request-enrollment [--endpoint <alias>] [--label <text>]` replaces
`request-token`. It still creates the client key if needed and performs host
trust, and the operator still approves the fingerprint in `apadmin` or
`apapprover`; the difference is that nothing is issued or saved afterwards.
The SSH username for the request is now `request-enrollment`. Guided cosigner
setup (`endpoints add`) enrolls automatically when a cosigner refuses the key.

The operator manages keys from the new **Enrolled Clients** panel in `apadmin`
(`c` on the Admin panel): it lists each key's fingerprint, label, type, and
connection state, and can revoke one key or every key. Revocation closes the
key's live connections at once and the next handshake is refused. The old
token revoke (`t`) and the `revoke_token` admin message are gone, replaced by
`list_enrolled_keys`, `revoke_enrolled_key`, and `revoke_all_enrolled_keys`.
Audit logs record `CLIENT_ENROLLED` and `CLIENT_KEY_REVOKED` instead of
`TOKEN_PROVISIONED`.

The registry is `identities/default/.ssh/authorized_keys`, written only by
the daemon: option-free lines are client keys, options beginning `aplane-`
are reserved, and a duplicate key is refused. The server setting
`endpoint.ssh.authorized_keys_path` is removed. In client `endpoints.yaml`,
`token_file` joins `signer_port` and `local_port` as a retired key: ignored on
load, dropped on the next write. Endpoints no longer carry a token, so
creating, re-importing, or deleting one no longer retires anything.

The SDKs are updated separately to authenticate with the SSH key.

## Client endpoints name only the address

The client-side `signer_port` and `local_port` fields are gone from
`endpoints.yaml`, together with `--cosigner-port` on `endpoints add`,
`--cosignerport` on `endpoints create`, and the `signer_port` / `local_port`
members of the `aplane.endpoint.v1` envelope that `apadmin endpoint export`
writes. They never did anything: a node's SSH server accepts only loopback
channel destinations and forwards every channel to its own REST listener, so
the client never chose the remote port, and the signer-role tunnel always
bound a free local port at connect time. A connection is now identified by its
URL alone, which is also what the token rules compare.

Existing `endpoints.yaml` files keep working: the two retired keys are ignored
on load and dropped by the next write. An endpoint envelope that still carries
them is refused as having unknown fields. The signer-side `endpoint.signer_port`
in `config.yaml`, the daemon's real REST bind port, is unchanged, and the apadmin
settings panel still shows it. The apadmin header no longer shows it, since a
client has no use for it; the header keeps the endpoint address.

## The cosigner export is the key only; clients are given the address

A cosigner's exported file is now the public key reference
(`aplane.witness-key-public.v1`) and nothing else. The
`aplane.cosigner-enrollment.v1` setup file that also carried the cosigner's
endpoint is gone, with the `apadmin cosigner enrollment export|import`
commands, the export screen's host field and loopback warning, and the
signer-side `endpoint_import` result that never did anything. The signer
imports the key file as before, with **Use key file...**, **Paste public
JSON...**, or `apadmin cosigner import`, and refuses a file that carries
anything more.

The client is configured by hand with the cosigner's address:
`endpoints add <cosigner-url>` (for example
`endpoints add ssh://cosigner.example:1127`). It no longer takes a file or a
pasted document, and no longer compares a key from a file against the node;
it reports how many keys the cosigner advertises and leaves key trust to the
signer. The guided checks are otherwise unchanged: a connection already
configured for the URL is reused, the node must report the cosigner role,
access is requested over SSH, and routes are reported. Handing the client the
key file is refused with that guidance. The apadmin export result screen shows
the address to give clients, from `endpoint.advertise_url` when it is
configured, so the installer's client-reachable address prompt keeps its
purpose.

A client that has already added a cosigner needs no change for later keys on
it. Two keys on one cosigner therefore never leave a client wondering which
file to add: no file is added at all.
## Policies start with self-transfers only

A new signer store now starts with routing enabled and one route,
`self-transfer`, which lets any account send any asset to itself on any
network, with `on_no_route: reject`. Opt-ins and self-sends pass; a transfer
to any other address, a close-out, or a clawback is rejected until a route
allows it. Before, a new store had routing off and every transfer went to the
operator's approval default. The cosigner starting document that the apadmin
editor and `apadmin policy template` begin from holds the same route; a
cosigner key still has no stored document until one is applied.

Existing stores are not changed: the starting document is written only at
`apstore initialize` and `apstore rebuild`. The integration test environment
applies its own permissive policy, as before.

## Comments in policy files and an annotated starting template

Policy files may now carry `//` and `/* */` comments outside strings. The
`apadmin policy` commands and the apadmin TUI (file load and editor) remove
them before the document reaches the node, so the node still accepts, digests,
and stores strict JSON and `apadmin policy export` returns the document without
them. `apstore policy check|sign` read the store directly and still require
plain JSON there.

`apadmin policy template signer|cosigner` writes the node's starting document
with a comment on its self-transfer route. It needs no node and no
passphrase; `--key` fills in a cosigner key. The TUI editor
opens a cosigner key with no policy, or a signer whose policy is still the
initial one, on the same template; stripped of comments it decodes equal to
the starting document, so applying it unedited changes nothing.

No policy format, admin RPC, or stored state changed.

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
