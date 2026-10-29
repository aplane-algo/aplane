# Release Notes

Entries are newest first and include pre-release development history. Older
token, setup-file, and protocol-v5 entries describe behavior superseded by the
enrolled-key model and current admin protocol v6.0; they are not current setup
instructions. See [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) for current contracts.

## Rotating accounts in own-account groups

- A rotating account's transaction can share an atomic group with
  transactions the same signer signs with ordinary keys, such as a hot
  account paying a fee leg or a funding payment. The group holds one
  rotating transaction; other members' signing keys must be held, ordinary,
  non-bounded keys. Other parties' transactions remain excluded. apshell
  routes such groups automatically, including `atomicSend`.
- `/sign/rotating/prepare` and `/sign/rotating/sign` accept a group form,
  `requests`, in the ordinary slot grammar. On these endpoints an omitted
  `auth_address` means the sender's own key. The single-transaction forms
  remain accepted and take the same path.
- Both responses add `rotations` (index, stage, target, and `rekey_to` or
  `txid`) and the prepare response adds `owned_indexes`; the scalar `stage`,
  `target`, `rekey_to` and `txid` fields repeat the single rotation for
  clients that predate the list.
- Rotating groups are built by the same planner as `/sign`: resource
  dummies count every member's pooled budget, and the ordinary fee allocator
  may raise any member's fee, with every change reported in
  `mutations.fees_modified`. Every member shares the rotating transaction's
  validity window.
- The signer signs owned transactions before the stage signature, so an
  owned key failure, a policy refusal or a cancellation releases nothing.
  `rotating_stage_changed` now says no signature was released, since owned
  transactions may already have been signed in memory and discarded.
- Both rotating endpoints now require canonical transaction encodings.
- The approval binding, which refuses to sign anything other than what was
  approved, now also covers each request's LogicSig arguments and a rotating
  group's rotation, on every signing path.
- apshell forwards app-call metadata for the rotating transaction too, so
  the approval prompt can name its ABI method.

## Rotating XMSS triple accounts and consensus v43

- In-place upgrade now requires an existing install of v0.44.0 or newer: the
  installer's minimum supported upgrade version is v0.44.0. A v0.43.0 install,
  or a development build between v0.43.0 and v0.44.0, needs a fresh install
  root; stores written by v0.43.0 are not read, because the rotating key types
  were renamed.
- Support exactly consensus v42 and v43 with Algorand Go SDK v2.14.0, replacing
  the temporary SDK commit pin. Clients accept either protocol while rejecting
  unknown versions; the signer uses their shared LogicSig and native-PQ rules.
  Account close-out preparation now checks aggregate minimum balance, including
  application size sponsorship, for both `close` and payments with close-out.
  Algod 5.0.4 enforces this check on v42 before the v43 consensus activation.
- The rotating key types are renamed for the hash-based scheme they carry:
  `aplane.rotating-triple-hybrid.v1` (shipped in v0.43.0) is now
  `aplane.rotating-triple-wots.v1`, and the new XMSS type is
  `aplane.rotating-triple-xmss.v1`. Derivation, stage programs and account
  addresses are unchanged. The old identifier is not accepted; a store
  written by v0.43.0 is not upgraded.
- New rotating key type `aplane.rotating-triple-xmss.v1`: Falcon-1024,
  RFC 8391 XMSS (`XMSS-SHA2_16_256`) and Ed25519 per stage, with one XMSS
  tree serving 1,024 stages and 64 leaves per stage. A stage can release up
  to 64 distinct transactions before any one-time leaf repeats, so retries
  and repairs keep all three hedges; a repeat is reported as it is for a
  twice-signed triple stage. Creating an account builds the first tree
  (seconds); spends pay five minimum fees, one more than the WOTS triple.
  After the signer starts or unlocks, the first spend from each XMSS account
  can wait about 16 seconds (on four cores) while that account's current tree
  is rebuilt in memory; the next tree is built ahead in the background, so
  later spends and tree boundaries do not wait.
  The signature format and verifier are RFC 8391, with the stage
  additionally requiring a message checksum of at most 511, which bounds
  its verification cost and which the signer meets by choosing the
  randomizer deterministically among PRF outputs; leaf management is best
  effort and the signer claims no RFC or SP 800-208 conformance for its
  signing procedure. `ROTATING_RELEASE` audit entries gain `rotating_tree`
  and `rotating_index` for this type. The WOTS triple is unchanged.
- A rotating account's own rekey, the rotation to the next stage the signer
  derives and proves itself, is no longer a warning-level finding. Warning
  analysis reports nothing for it, so `always_review_warnings` no longer
  forces review of every rotating spend and the approval prompt no longer
  shows a rekey warning for it. Any other dangerous field on the spend still
  warns, and a rekey to any other address still warns.
- User Auto-Approve now satisfies all signer review requirements without an
  operator prompt, including warning, transaction-type, routing, foreign-leg,
  and bounded admin-operation review. Unattended agents no longer need a
  connected apadmin for those requests. Hard policy rejections, authentication,
  key unlock, and signing validation still apply. Matched review rules remain
  in audit records and console output.

## Bounded rotating stage recovery

The stage table worker no longer scans without a ceiling for a rotating
account whose authorizer it cannot place. Before, such an account was
derived one batch per tick, the seed opened each time, until the key was
deleted. Now the worker classifies the authorizer first (stage 0, a cached
stage, a key this signer holds, or unknown) and searches only for an
unknown one, under a recovery grant bounded by a per-account, per-unlock
allowance (`rotating.recovery_max_stages`, default 1,024 past the cache,
never replenished within the unlock; `rotating.recovery_timeout`, default
5m, caps its derivation time). An exhausted search leaves the account
unresolved with a `/status` note and a stopped reason, the way a
non-rotating account rekeyed to an unknown address is left alone; it is not
an alert, and it never claims the account was exited. Lookahead to
`rotating.stage_horizon` is unchanged; `stage_horizon` is not deprecated.
Operators get `rotate recover <account>` (new signer route
`POST /admin/rotating/recover`, new client action `keys.recover`, audited as
`ROTATING_RECOVERY`): a search with the operator's own budget, optionally
with a stage hint that is derived directly and probed around, then the
cache is filled up to the found stage; `cancel` stops it. `/status` gains
`rotating[]` with each account's observed authorizer, classification,
cached stages and recovery state, and `rotate status` shows it. Prepares
are unchanged: a request whose stage is not cached still runs its own
bounded discovery. Unchanged and stated plainly: the worker still derives
to the horizon on a timer and opens the seed to do so; this bounds the
pathological case and does not narrow idle secret handling. Contract
fixtures `rotating_recover_{request,response}.json` and
`status_response_rotating.json` are added.

## Admin rekeys stay in the signer's custody

An admin-key bounded rekey (`/sign/bounded-admin`, `aprekey rekey`) may now
only move the account to a nonrotating signing credential the same signer
holds: a native Ed25519 or Falcon-1024 key, or a plain `aplane.falcon1024.v1`
or `aplane.ed25519.v1` LogicSig account. Unheld addresses and bounded,
guarded, composed, generic, witness or rotating credentials are refused with
the new wire code `bounded_admin_target_rejected` before policy and approval,
and the credential is loaded, bound to the target address (a LogicSig
target's program is re-derived through its family provider and must match
the stored bytecode) and self-tested again at release. A rekey of the
bounded account to itself still passes; a
rekey-to-self of another account under the bounded program's authority is
checked like any other target. The rule is a
signer invariant independent of `reject_foreign_rekey`; moving an account out
of APlane custody is an admin rekey to a local key followed by an ordinary
rekey from that key. The error code is added to the signer API contract
fixtures and the SDK code tables; no other wire change.

## One rotating key type

The Falcon hybrid (`aplane.rotating-hybrid.v1`) and hash hybrid
(`aplane.rotating-wots-hybrid.v1`) rotating key types are removed, before
any external use. `aplane.rotating-triple-hybrid.v1` is the only rotating
account: it dominates both on security, since a forgery needs Falcon, SHA-256
and Ed25519 broken together, and the fee difference is a few thousandths of
an ALGO per spend. The `rotating1` flow, commands, stage address cache,
alerts, restore behavior, endpoints and DTOs are unchanged; the signer API
contract fixture `keys_response_rotating.json` now describes the triple and
`keys_response_rotating_wots.json` is gone. Key files of the removed types
are rejected at scan as unregistered rotating key types.

## Rotating triple hybrid accounts

New library-visible key type `aplane.rotating-triple-hybrid.v1`: the rotating
account whose every stage requires a Falcon-1024, a WOTS-w16 (SHA-256) and an
Ed25519 signature over the TxID, each derived from one signer-held seed under
the type's own derivation label. A forgery needs breaks of lattices, SHA-256
and Ed25519 at once. It uses the same `rotating1` flow, commands, stage
address cache, alerts and restore behavior as the other rotating types; a
spend carries three resource dummies and pays four minimum fees. A stage
that released twice loses only its WOTS protection and rests on Falcon-1024
and Ed25519 until one of its transactions lands; the reuse warning now names
what a reused stage still rests on for each type. The Falcon and hash
hybrids are unchanged and remain the cheaper options. `/keys` and
`/keytypes` report the type with `signing_flow: rotating1`; no new error
codes.

## Per-key signer policy

Policy is now one document per key with a node default behind it, laid out
the same way on signer and cosigner nodes. Every store holds `default.json`,
seeded at `apstore initialize` and `rebuild` from the shipped default for the
role, and zero or one `policies/<key>.json` per key (the address on a signer
node, the Witness Key ID on a cosigner node). A key with a file of its own is
governed by that file alone; a key without one follows the default. There is
no inheritance: `key_overrides` is gone, and so are `transfer_policy.enabled`,
the `aplane.signer-policy.v1` and `aplane.cosigner-policy.v1` formats, and the
cosigner-only rule ids `cosigner:non_transfer`,
`cosigner:deterministic_routing`, `cosigner:transfer_policy_required`, and
`cosigner_key_has_no_policy`.

- One format, `aplane.policy.v1`, with a required `role` (`signer` or
  `cosigner`, matching the node) and `key` (`default` or the key the file
  governs). Every verdict-bearing field is required and unknown fields are
  rejected. The new required `transaction_types` map gives each transaction
  type (or `*`) `allow`, `review`, or `reject`, evaluated before every other
  rule with rule id `transaction_type:<type>`; on a cosigner node only `pay`
  and `axfer` may be `allow`, and no cosigner document may express `review`.
- The shipped signer default rejects a foreign rekey, reviews warning-level
  fields, and leaves everything else to the operator default, so with
  `user_auto_approve` on, a key with no file signs whatever the default does
  not reject or force to review. The shipped cosigner default is deny-all: a
  cosigner key signs nothing until it is given a file.
- `apadmin policy template [--key K]` writes the node's current default, or
  it with the key filled in, as the starting point for a key file;
  `template --embedded signer|cosigner [--key K]` writes the shipped default
  and is the only form that needs no node. `remove` now deletes a key's own
  file on either role (the default cannot be removed), `status` lists the
  default and each held key as `own policy` or `default`, and diffs are
  effective: a new key file is compared with the default the key followed.
  `apstore policy check|verify|sign` cover every stored document, backups
  carry a key's own file as `policies/<key>.apb` on both roles, and the
  apadmin TUI lists the default first and opens a key without a file on the
  default with the key filled in.
- Approval warnings, which force review under `always_review_warnings`, now
  also cover application update, asset reconfigure (naming the manager,
  reserve, freeze, and clawback addresses) and destroy, and asset freeze or
  unfreeze.

Stores from earlier releases are not read: there is no compatibility shim for
`policy.json`, the old formats, or `key_overrides`. Re-initialize the store, or
rewrite its policy documents in the new format before starting the node. The
installer's in-place upgrade floor moves to v0.41.0 accordingly: an install
from an earlier release needs a fresh install root rather than an upgrade.

## Rotating hash hybrid accounts

New library-visible key type `aplane.rotating-wots-hybrid.v1`: the rotating
account with a hash-based stage. Each stage checks a Winternitz one-time
signature (SHA-256 only, w = 16, 67 chains) and an Ed25519 signature, both
derived from one signer-held seed, so the post-quantum half rests on SHA-256
alone. It uses the same `rotating1` flow, commands, stage address cache,
alerts and restore behavior as the Falcon hybrid and differs only in its
stage program: about 300 bytes, a 2,144-byte signature, a worst-case opcode
cost of 58,063 (two resource dummies per spend) and stage derivation in
microseconds. A stage that released twice (an expired release and its
repair, or a client re-signing a rebuilt transaction) is Ed25519-only until
one of its transactions lands; the signer's release memory now marks the
reuse and reports it as a warning for this type until a chain read shows the
account moved. The same mark appears in the Falcon hybrid's in-flight note,
where it is harmless. `/keys` and `/keytypes` report the type with
`signing_flow: rotating1`; no new error codes.

## Rotating hybrid accounts

New library-visible key type `aplane.rotating-hybrid.v1`: an account whose
address never changes while the program that authorizes it changes on every
spend. Each stage checks a Falcon-1024 and an Ed25519 signature derived from
one signer-held seed, and every spend rekeys the account to the next stage,
whose keys have never been revealed. Enable it with `apadmin keytype enable
aplane.rotating-hybrid.v1` and generate with the `network` parameter.

- Signing uses a new flow, `rotating1`: `POST /sign/rotating/prepare` and
  `POST /sign/rotating/sign`. `/keys` and `/keytypes` report
  `signing_flow: rotating1`. `/plan`, `/sign`, `/sign/bounded-admin` and
  `/sign/component` refuse these accounts with the new error code
  `rotating_signing_required`; the new flow adds `rotating_stage_unproven`
  and `rotating_stage_changed` (both `409`). Clients that do not know
  `rotating1` fail closed.
- The signer keeps no durable state for these accounts. It reads the live
  stage from its own node (`networks.<net>.algod`) at every request, and
  caches stage addresses in plaintext under `identities/default/stages/`,
  which it rebuilds from the seed whenever missing or damaged. A restored
  backup signs again without any recovery step. New setting
  `rotating.stage_horizon` (default 4096) bounds the background lookahead.
- apshell routes sends from these accounts automatically and adds
  `rotate <account>` and `rotate status`.
- A rotation's target counts as the signer's own address for
  `reject_foreign_rekey`.
- The signer alerts, in the daemon log, `/status` warnings, a new optional
  `warnings` list on the admin `status` message shown in apadmin, and
  apshell's `rotate status`, when a signed transaction expired while its
  stage still controls the account. Releases still in flight appear in the
  new `/status` `notes` field. A new durable audit entry,
  `ROTATING_RELEASE`, records every release and rebuilds this memory at
  unlock.

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
results). Audit logs record
`CLIENT_ENROLLMENT_REQUESTED` when a request is queued and
`CLIENT_ENROLLMENT_REJECTED` when one is rejected; `CLIENT_ENROLLED` now
carries the approving admin session.

Guided cosigner setup (`endpoints add`) submits the enrollment request and
stops with the connection configured when the cosigner's operator has to
approve it; rerun setup afterwards. The SDKs' `requestEnrollment` now reports
whether the request is pending.

The **Enrolled Clients** screen now opens with `c` from the key list rather
than from Settings, and keeps itself current: the signer sends a new
`enrollment_changed` admin notification whenever a request is queued,
approved, rejected, imported, or a key is revoked, and whenever an enrolled
client connects or disconnects, and the screen re-fetches its lists on each
one. The screen's `R` refresh key is gone. Admin clients that do not know the
notification ignore it.

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
(`c` on the key list): it lists each key's fingerprint, label, type, and
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
