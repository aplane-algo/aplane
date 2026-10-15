# Signer Policy

Signer policy is the product-scoped safety layer that decides whether a
signing request should be rejected, forced through operator review, explicitly
approved, or left to the operator default.

## One Default, A File Per Key When Needed

Every node holds one default policy, `default.json`. It is the rulebook for
every key the node holds that has no policy of its own. A key that needs
different rules gets its own file, `policies/<key>.json`, and that file
replaces the default for that key wholesale: nothing is inherited, every field
is written out, and a change to the default no longer reaches the key. A key
without a file follows the default, including every later change to it.

Both node roles use the same document format and the same rules; they differ
in what a key is and in what the role may express:

- **On a signer node, a key is a signing address.** The default governs every
  key the node holds, whatever its type, including the user side of a guarded
  (cosigner-backed) key. Generating or importing a key adds it to the default's
  set; nothing is written per key until you give the key a file of its own.
- **On a cosigner node, a key is a cosigner witness, selected by its Witness
  Key ID.** A cosigner key's policy governs every account whose guarded key was
  composed with that witness. This set is virtual: the cosigner does not hold
  those accounts and cannot list them. Any signer holding the key's public
  reference can compose new accounts with it, and the cosigner learns of one
  when a request for it arrives. Routes with `sources: ["*"]` accept every such
  account; routes naming addresses or sets pin the document to accounts the
  operator has agreed to witness for.

A guarded account is governed on both nodes at once, and a transfer must be
allowed by both: the signer's policy for the user key and the cosigner's policy
for the witness. The stricter document decides. The aPlane client asks the
signer first, so a rejection reported as a signer error means the signer's
policy said no and the cosigner was not consulted.

### Where policy lives

Policy is a set of v1 JSON documents stored beside the product keys in the
selected store generation:

```text
identities/default/generations/<selected-generation>/default.json
identities/default/generations/<selected-generation>/default.json.hmac
identities/default/generations/<selected-generation>/policies/<key>.json
identities/default/generations/<selected-generation>/policies/<key>.json.hmac
identities/default/generations/<selected-generation>/deleted/policies/   # files of deleted keys
```

`<key>` is the signing address on a signer node and the Witness Key ID on a
cosigner node. Each `.hmac` sidecar authenticates the exact document bytes. A
missing or mismatched sidecar, a document that does not decode, or a
generation with no `default.json` makes the node refuse to load rather than
silently loading something else. Deleting a key archives its file under
`deleted/policies/`; a key's file travels with the key in backups.

The document format, field types, and acceptance rules are specified in
[ARCH_POLICY.md](ARCH_POLICY.md#the-boundary); the machine-readable schema is
[`pkg/policyschema/policy.v1.schema.json`](../pkg/policyschema/policy.v1.schema.json).

### The shipped signer default

`apstore initialize` and `apstore rebuild` seed `default.json` from the
shipped default for the node role. On a signer node that is:

```json
{
  "format": "aplane.policy.v1",
  "role": "signer",
  "key": "default",
  "reject_foreign_rekey": true,
  "reject_close_remainder": false,
  "reject_asset_close": false,
  "reject_clawback": false,
  "always_review_warnings": true,
  "auto_approve_self_noop_transfer": false,
  "max_fee_microalgos": "0",
  "transaction_types": { "*": "allow" },
  "transfer_policy": {
    "on_no_route": "operator_default",
    "close_on_no_route": "operator_default",
    "clawback_on_no_route": "operator_default",
    "routes": [
      {
        "id": "self-transfer",
        "description": "Any account may send any asset to itself",
        "networks": ["*"],
        "sources": ["*"],
        "assets": ["*"],
        "destinations": ["self"]
      }
    ]
  }
}
```

A key with no file therefore rejects a rekey to an address this node does not
hold, forces operator review of anything warning analysis flags (a rekey, an
ALGO or ASA close-out, a clawback, an application delete, clear-state, or
update, an asset reconfigure, destroy, freeze, or unfreeze, or a fee above 1
ALGO), and leaves everything else to the operator default. Every transaction
type is allowed through, there is no fee cap, and a transfer that matches no
route is neither rejected nor reviewed by routing: with `user_auto_approve:
false` the operator is asked, with `user_auto_approve: true` it is signed.
Tighten the default before turning the operator switch on, or give the keys
that matter files of their own.

### The shipped cosigner default

A cosigner node's shipped default denies everything:

```json
{
  "format": "aplane.policy.v1",
  "role": "cosigner",
  "key": "default",
  "reject_close_remainder": false,
  "reject_asset_close": false,
  "reject_clawback": false,
  "reject_rekey": true,
  "max_fee_microalgos": "0",
  "transaction_types": { "*": "reject" },
  "transfer_policy": {
    "routes": []
  }
}
```

A cosigner key with no file signs nothing. Cosigner policy has only two
outcomes, reject or sign, so the default cannot defer to an operator; giving a
cosigner key a file is the act of saying what it may witness.

### When to give a key its own file

Keep keys on the default while one rulebook fits them all: the default is
reviewed once, and every key added later is covered without a policy change.
Give a key a file when its rules differ in kind, not only in degree:

- a treasury key whose transfers are an allowlist with `on_no_route: reject`
  while the other keys stay on the operator default,
- a key that may never sign application calls or key registrations,
- a key with a tighter fee cap or an earlier review threshold,
- on a cosigner node, every witness that is meant to sign at all.

A key file is a complete document, so a shared address or asset set is copied
into every file that uses it; `apply` takes several files in one commit and
`diff` shows each, which keeps the copies reviewable. A node holds at most
8,192 key files.

## What Policy Controls

Policy applies after request planning has identified the transactions this
signer controls. It is separate from:

- authentication and authorization, which decide who may ask for signing,
- key unlock state, which decides whether signing keys are usable,
- `user_auto_approve`, the operator default used only when policy has no
  stronger verdict,
- app-call inner transaction behavior, which is not inspected by transfer
  routing.

Policy verdicts are ordered conservatively:

```text
Always Deny > Always Review > Always Approve > Operator Default
```

This means a reject rule cannot be approved through an operator prompt, and a
review rule blocks both `user_auto_approve:true` and any matching auto-approval
rule. Within Always Deny and Always Review, the `transaction_types` verdict is
evaluated first: a rejected type never reaches the other rules, and the
rejection names the type.

The policy for a request is resolved per signing key from one snapshot taken
when the request's signing service is built: the key's own file if it has one,
otherwise the default. A policy reload never changes a request already in
flight, and a key whose policy cannot be resolved fails closed.

## Editing Policy

Write or edit a policy file outside the node, review it with
`apadmin policy check FILE`, then install it with `apadmin policy apply FILE`.
While `apsigner` is stopped, use the `apadmin policy rescue` forms instead.

`apadmin policy` connects through authenticated local admin IPC, follows the
daemon's node role, unlocks the product when required, and never needs
filesystem access to the private signer store.

```bash
apadmin policy status
apadmin policy export > default.json
apadmin policy export --key <key> > key.json
apadmin policy check default.json key.json
apadmin policy apply default.json key.json
apadmin policy apply - < default.json
```

Each file is one document and names what it is in its `key` field:
`"default"` for the node default, or the key it governs. `apply` replaces the
listed documents and leaves every other key's document unchanged.

To start a file for a key, write out the node's current default with the key
filled in and edit it:

```bash
apadmin policy template --key <key> > key.json
apadmin policy template > default.json
```

The template carries a `//` comment saying what it is and that every field is
required; a template applied unchanged gives the key exactly the rules it was
already following. Policy files may carry `//` and `/* */` comments anywhere
outside strings. `apadmin` removes them before the document reaches the node,
so `apadmin policy export` returns the stored document without them; keep the
commented file if you want the notes. `apstore policy check` and `sign` read
documents already in the store, which must be plain JSON.

`apadmin policy template --embedded signer|cosigner [--key K]` writes the
shipped default for that role instead of the node's own. It is the only form
that needs no node and no passphrase, for writing policy on a machine that
has no store.

The apadmin TUI can also load one policy file: open Policies (`p`), press `a`,
and enter the file path. The TUI checks the file, shows the same diff as
`apadmin policy diff`, and applies it only after you press `y`. The file's
`"key"` field names the document, and the TUI refuses a file for a key the
node does not hold; generate or import the key first. The path must name a
regular file, not a symlink. The TUI does not remove documents or take several
files at once; `apadmin policy` covers those.

### Editing a policy in apadmin

To change a policy without a file, open Policies (`p`), select the document,
and press `e`. The list shows the node default first, labelled "node default
(governs every key without its own policy)", then every held key marked "own
policy" or "default", and any stored file for a key the node no longer holds
("policy, key not held"). The document's JSON opens in an editor. Edit it,
then press `ctrl+s`: apadmin checks the text, shows the same diff as a file
load, and applies it only after you press `y`. Nothing is stored before that.

- **A key on the default opens on the default.** Selecting a key that has no
  file of its own opens the editor on the node default with the key filled in,
  marked "No policy of its own yet". Applying it, changed or not, gives the key
  its own policy. Any other document opens exactly as stored.
- **Comments are allowed.** `//` and `/* */` comments outside strings are
  removed before the text reaches the node, so they never appear in the
  stored document. A syntax error is still reported at the line and column
  of the text as you see it.
- **Errors keep your text.** A JSON syntax error is reported with its line and
  column. If the node rejects the document, its problems appear under the
  text. Pressing `n` in the review, or leaving a failed apply, returns to the
  editor with the text as you left it.
- **Leaving.** `esc` closes the editor. If the text changed, it asks once
  before discarding.
- **Pasting.** Use your terminal's paste (for example `ctrl+shift+v` or
  `cmd+v`). `ctrl+v` inside the editor does nothing.
- **Very large policies.** A policy of more than 10,000 lines is not opened in
  the editor; export it with `apadmin policy export`, edit the file, and load
  it with `a`.
- **One document at a time.** The `"key"` field must stay the document you
  opened; to set another key's policy, load a file or open that key.

Editing in apadmin uses the session you are already logged in to. Unlike the
batch `apadmin policy` commands, it does not take over from a running apadmin
or lock the node when it finishes.

`apadmin policy` requires a verb:

| Verb | Meaning |
|------|---------|
| `status` | List the node's default policy and each held key's coverage, with size, SHA-256, and applied time per document, and the `policy_set_sha256` of the whole set |
| `export [--key K]` | Write one document to stdout exactly as stored: the node default, or key K's own policy |
| `check FILE...` | Validate files against the node without writing; `-` reads one file from stdin |
| `diff FILE...` | Describe how the files differ from the policy that governs each key now, marking each change tightened, loosened, or changed |
| `apply FILE...` | Check, show the diff, ask for confirmation, then replace the documents in one commit; `-` reads one file from stdin |
| `remove K...` | Show the diff, ask for confirmation, then delete the keys' own policies; the keys follow the node default. The default cannot be removed |
| `template [--key K]` | Write the node's current default policy as the starting document for key K, or annotated as the default itself |
| `template --embedded signer\|cosigner [--key K]` | Write the shipped default for that role instead; the only form that needs no node and no passphrase |

`apply` and `remove` ask "Apply these changes?" on the terminal. Pass `--yes`
to skip the question in scripts; without a terminal and without `--yes` they
refuse. Reformatting a file changes nothing, so applying it reports
`policy unchanged`. The other verbs are noninteractive.

`status` prints one line per document and one per held key:

```text
signer policy
  default       sha256 3f1c9b...  812 bytes  applied 2026-10-14T09:12:40Z
keys (3)
  CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM  own policy    sha256 9a7e02...  1431 bytes  applied 2026-10-14T10:03:11Z
  EIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDOHSEZI  default
  GMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZ6LH5CFA  key not held  sha256 c41d77...  980 bytes  applied 2026-09-30T16:20:05Z
policy_set_sha256 7d2a4e...
```

`own policy` is a key governed by its own file, `default` a key following the
node default, and `key not held` a stored file whose key this node does not
hold (for example after the key was deleted elsewhere and restored without
it, or a file applied before the key was imported).

`diff` compares each file with the document that governs its key now. A new
key file is compared with the default the key followed, headed "the key gets a
policy of its own; compared with the node default it followed"; a replacement
is compared with the key's own document; a removal is compared with the
default the key will follow, headed "policy of its own removed; the key
follows the node default". A change to the default also names the held keys
it governs ("governs 2 held key(s): ...", or "governs no held key; every held
key has a policy of its own"). Each line is marked `tightened`, `loosened`, or
`changed`:

```text
key.json:
  changed    /: the key gets a policy of its own; compared with the node default it followed
  tightened  /max_fee_microalgos: no cap → 0.01 ALGO
  tightened  /transaction_types/appl: allow → review
  tightened  /transfer_policy/on_no_route: operator_default → reject
```

`check` prints errors with the JSON Pointer of the failing field and prints
warnings that do not block an apply: a file for a key the node does not hold
("policy is for a key this node does not hold"), reject settings that override
a route's `allow_close` or `allow_clawback`, routes for a transfer type the
document's `transaction_types` rejects, and a cosigner document whose routes
permit movements with no fee cap.

`apply` runs `check` first, prints its warnings, and stops on errors. It then
applies the change against the `policy_set_sha256` it read at the start, so the
signer rejects the change if the active policy changed in the meantime. On
success the signer writes the exact submitted bytes plus fresh sidecars as a
new store generation and activates the resulting runtime policy immediately;
`apply` prints the new generation ID and `policy_set_sha256`. Each apply leaves
a retained generation until explicit generation pruning; see
[USER_STORE_MGMT.md](USER_STORE_MGMT.md).

"Immediately" means for requests that arrive after the apply. A request is
evaluated against the policy in force when it arrives, and it keeps that
verdict for its whole life, including while its approval prompt waits in
apadmin or apapprover and while it is queued behind another prompt. Approving
such a request signs it under the policy it was evaluated against, not the one
you just applied. If a tighter policy must also cover requests already waiting,
reject the waiting prompts (or lock the signer, which fails every pending
approval) before or after the apply; the clients retry and are evaluated under
the new policy.

Every online verb authenticates first; if the daemon is locked, even the
read-only `status`, `export`, and `check` commands unlock it before reading
policy state and are therefore not guaranteed to preserve the daemon's lock
state.

### Migration from the retired policy binary

The former `appolicy` binary is no longer installed. Replace its command shapes
as follows:

| Former command | Current command |
|---|---|
| `appolicy --online` | `apadmin policy export`, edit the file, then `apadmin policy check FILE` and `apadmin policy apply FILE` |
| `appolicy --online --check FILE` | `apadmin policy check FILE` |
| `appolicy --online --yaml FILE` | `apadmin policy export` |
| `appolicy --online --sha256 FILE` | `apadmin policy status` |
| `appolicy --online --save` | `apadmin policy apply -` |
| `appolicy FILE` | `apadmin policy rescue check FILE`, then `apadmin policy rescue apply FILE` |
| `appolicy --check FILE` | `apadmin policy rescue check FILE` |
| `appolicy --yaml FILE` | `apadmin policy rescue export` |
| `appolicy --sha256 FILE` | `apadmin policy rescue status` |
| `appolicy --save` | `apadmin policy rescue apply -` |

There is no wrapper or automatic online-to-rescue fallback.

`apadmin policy rescue` is the stopped-service rescue command family. It takes
the same verbs, reads the store named by `APSIGNER_DATA` or `-d` directly, and
follows the node role recorded in the store. Reads (`status`, `export`,
`check`, `diff`, `template`) hold the shared store lock; `apply` and `remove`
hold the exclusive store lock and require a stopped daemon. Rescue applies use
the same check and commit rules as the daemon and also commit a new
generation. On a systemd store, run rescue as root only while `apsigner` is
stopped.

Rescue commands need the store passphrase to verify the sidecars:

```bash
apadmin -d "$APSIGNER_DATA" policy rescue status
apadmin -d "$APSIGNER_DATA" policy rescue export > default.json
APSIGNER_PASSPHRASE="$passphrase" apadmin -d "$APSIGNER_DATA" policy rescue apply - < default.json
```

`APSIGNER_PASSPHRASE` supplies the passphrase for local IPC and rescue policy
commands. A command that reads its policy from a named file may also read one
passphrase line from nonterminal stdin. `check -` and `apply -` reserve stdin
for the document and require the environment passphrase or a controlling
terminal. For remote administration, SSH into the signer machine and run
apadmin there; all named paths then refer to that machine.

For documents placed or edited by hand in the selected generation:

```bash
apstore -d "$APSIGNER_DATA" policy check
apstore -d "$APSIGNER_DATA" policy sign
apstore -d "$APSIGNER_DATA" policy verify
```

`apstore policy check` validates every stored document (the default and each
key file) without verifying sidecars, reports a document that has no sidecar
yet, and warns about files for keys the node does not hold. `apstore policy
sign` writes fresh sidecars for every stored document. `apstore policy verify`
verifies every sidecar and compiles the policy. These are offline maintenance
operations; stop `apsigner` and use `sudo` for a systemd store. Hand edits take
effect only after the next successful signer start, reload, or unlock. Normal
production changes should use `apadmin policy check` and `apadmin policy
apply`.

## Fields

Every document is complete: each verdict-bearing field is required, nothing is
filled in by the node, and an unknown field is rejected. Fields a role does
not support are rejected in that role's documents. Amounts are decimal strings
in base units, and ASA IDs are written `asa:<id>`.

| Field | Role | Required | Meaning |
|-------|------|----------|---------|
| `format` | both | yes | `"aplane.policy.v1"`. |
| `role` | both | yes | `"signer"` or `"cosigner"`; must match the node. |
| `key` | both | yes | `"default"` for the node default, or the key the file governs: a signing address on a signer node, a Witness Key ID on a cosigner node. Must match the file name. |
| `description` | both | no | Notes for reviewers. |
| `reject_foreign_rekey` | signer | yes | Reject txns whose non-zero `RekeyTo` target is not held by this node. |
| `reject_rekey` | cosigner | yes | Coarse deny-all switch for txns with non-zero `RekeyTo`. With `false`, a rekey still fails unless `rekey_policy` allows the edge. |
| `reject_close_remainder` | both | yes | Reject payment txns with non-zero `CloseRemainderTo`. |
| `reject_asset_close` | both | yes | Reject ASA transfer txns with non-zero `AssetCloseTo`. |
| `reject_clawback` | both | yes | Reject ASA clawback txns using `AssetSender`. |
| `always_review_warnings` | signer | yes | Require operator review for warning-level findings, even with `user_auto_approve: true`. |
| `auto_approve_self_noop_transfer` | signer | yes | Auto-approve exact low-risk 0-amount self-transfer shapes. |
| `max_fee_microalgos` | both | yes | Reject txns whose fee exceeds this microAlgo ceiling; `"0"` means no cap. |
| `transaction_types` | both | yes | Map from transaction type (`pay`, `axfer`, `acfg`, `afrz`, `appl`, `keyreg`, `stpf`, `hb`) or `*` to `allow`, `review`, or `reject`; `*` is required and covers every type not named. A cosigner document may `allow` only `pay` and `axfer` and may not use `review`. |
| `limits` | both | no | Per-network, per-asset `review_above` / `reject_above` thresholds in base units; cosigner documents take `reject_above` only. |
| `address_sets` | both | no | Named address sets for routes, local to this document. |
| `asset_sets` | both | no | Named per-network asset sets for routes, local to this document. |
| `transfer_policy` | both | yes | Source/asset/destination route table for direct ALGO and ASA movements: `routes` (required, may be empty) and `blocked_destinations`. Signer documents also require `on_no_route`, `close_on_no_route`, and `clawback_on_no_route`. |
| `rekey_policy` | cosigner | no | Allow-list for pure 0 ALGO self-payment rekeys by sender and target. |

Cosigner policy never produces review verdicts: there is no `review_above`, no
`review` type verdict, and no `on_no_route` family (an unmatched movement,
close-out, or clawback is always rejected).

`transaction_types` is evaluated before everything else. `reject` is Always
Deny for the type (rule id `transaction_type:<type>`), `review` is Always
Review, and `allow` lets the type continue to the other rules. A type the
map does not name takes the `*` verdict.

Limits are keyed by network, then by asset:

```json
"limits": {
  "mainnet": {
    "algo": { "review_above": "100000000", "reject_above": "1000000000" },
    "asa:31566704": { "reject_above": "5000000000" }
  }
}
```

Document-level and route-level limits are separate checks and both apply.

For cosigner rekey authorization, set `"reject_rekey": true` for a coarse
deny-all policy. To authorize a controlled rekey, set `"reject_rekey": false`
and add `rekey_policy.allowed` entries:

```json
"rekey_policy": {
  "allowed": [
    { "sender": "SENDERADDR...", "targets": ["TARGETADDR..."] }
  ]
}
```

Each `sender` and `targets` item may be an Algorand address or a reference to
a flat `address_sets` entry such as `@corridor_accounts`. Network-specific
address sets are not accepted for rekey policy. The target transaction must be
a pure 0 ALGO self-payment with non-zero `RekeyTo` and no close remainder.

`rekey_policy` applies to dedicated `cosigner1` guarded accounts. Corridor v1's
cosigner is spend-only; its pure rekey instead requires the separate offline
contract-admin witness and does not contact the cosigner.

## Writing a key policy

This section builds one signer key's document from the template to a
complete policy with guards, a type allow-list, limits, named sets, and
routes. Each step changes a part of the document; the complete result is in
[step 7](#7-the-complete-document) and can be checked and applied as it
stands. The addresses and asset IDs are examples: replace them with your own.
The same steps, applied to `template` with no `--key`, rewrite the node
default. A cosigner key's document uses the same sets and routes with no
review fields; see [Cosigner Documents](USER_TRANSFER_ROUTING.md#cosigner-documents).

### 1. Start from the template

```bash
apadmin policy template --key CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM > treasury.json
```

The template is the node's current default with the key filled in. On a fresh
store that is the shipped default from
[above](#the-shipped-signer-default) with
`"key": "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"` and a
`//` header saying so. Applied unchanged, it gives the key exactly the rules it
was already following; the point of the file is what you change next. Every
field stays in the file: a key file is complete, and `check` rejects one that
drops a required field.

### 2. Set document-wide guards

Edit the scalar settings at the top level, next to `key`:

```json
  "description": "Treasury key",
  "reject_foreign_rekey": true,
  "reject_close_remainder": true,
  "reject_asset_close": false,
  "reject_clawback": true,
  "always_review_warnings": true,
  "auto_approve_self_noop_transfer": false,
  "max_fee_microalgos": "10000",
```

- `reject_*` settings are Always Deny: a matching transaction is rejected
  before any prompt and cannot be approved by an operator. Here ALGO
  close-outs and clawbacks are rejected for this key, and a rekey to an
  address this node does not hold stays rejected.
- `always_review_warnings` forces an operator prompt, even with
  `user_auto_approve: true`, when warning analysis finds a rekey, an ALGO or
  ASA close-out, a clawback, an application delete, clear-state, or update, an
  asset reconfigure, destroy, freeze, or unfreeze, or a fee above 1 ALGO.
- `max_fee_microalgos` rejects a transaction whose fee, as finally signed,
  exceeds the cap. That fee includes anything the signer adds for LogicSig
  budget or post-quantum keys, so set the cap above what those keys need.
  `"0"` is no cap.

### 3. Allow only the transaction types the key needs

```json
  "transaction_types": {
    "*": "reject",
    "pay": "allow",
    "axfer": "allow",
    "keyreg": "review"
  },
```

The treasury key moves funds and, with an operator watching, registers
participation keys. Every other type (`acfg`, `afrz`, `appl`, `stpf`, `hb`) is
rejected by `*` before any other rule runs; the rejection is reported as
`transaction_type:appl` and the like. `review` is Always Review: a `keyreg`
prompts even with `user_auto_approve: true`. Keep `*` in the map; it is
required.

### 4. Add document-level limits

```json
  "limits": {
    "mainnet": {
      "algo": { "review_above": "100000000", "reject_above": "1000000000" },
      "asa:31566704": { "reject_above": "5000000000" }
    }
  },
```

Document limits are ceilings for this key on that network: a mainnet ALGO
payment above 100 ALGO needs operator review, one above 1000 ALGO is
rejected, and a USDC transfer above 5000 USDC is rejected. Amounts are
decimal strings in base units (microAlgos; USDC has 6 decimals), and
`review_above` must not exceed `reject_above`. Routes cannot raise these
ceilings; they can only add thresholds of their own. A network named here
must be one the node's configuration maps a genesis hash to.

### 5. Name the accounts and assets

```json
  "address_sets": {
    "treasury": ["CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"],
    "ops": {
      "mainnet": ["EIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDOHSEZI"],
      "testnet": ["GMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZ6LH5CFA"]
    }
  },
  "asset_sets": {
    "usd": {
      "mainnet": ["asa:31566704"],
      "testnet": ["asa:10458941"]
    }
  },
```

An address set is either a flat list, which applies on every network, or a
map from network to addresses. Asset sets are always per network because ASA
IDs are network-local. Sets do nothing on their own; routes reference them as
`@treasury`, `@ops`, and `@usd`. Sets are local to the document: a key file
that needs the same sets as the default carries its own copy.

### 6. Make transfers an allowlist

Replace `transfer_policy`, keeping the `self-transfer` route:

```json
  "transfer_policy": {
    "on_no_route": "reject",
    "close_on_no_route": "reject",
    "clawback_on_no_route": "reject",
    "blocked_destinations": ["KVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVDNKFTE"],
    "routes": [
      { "id": "self-transfer", "...": "as in the template" },
      {
        "id": "treasury-to-ops",
        "description": "Treasury tops up ops in ALGO",
        "networks": ["mainnet"],
        "sources": ["@treasury"],
        "assets": ["algo"],
        "destinations": ["@ops"],
        "limits": {
          "mainnet": { "algo": { "review_above": "500000000" } }
        }
      },
      {
        "id": "treasury-usd-payouts",
        "description": "Treasury pays anyone in USD, capped per payment",
        "networks": ["mainnet", "testnet"],
        "sources": ["@treasury"],
        "assets": ["@usd"],
        "destinations": ["*"],
        "limits": {
          "mainnet": { "asa:31566704": { "reject_above": "1000000000" } },
          "testnet": { "asa:10458941": { "reject_above": "1000000000" } }
        }
      }
    ]
  }
```

How to read this:

- The three `*_on_no_route` fields decide what happens to a direct transfer,
  close-out, or clawback that matches no route. The template inherited
  `operator_default` from the shipped default, which leaves misses to the
  operator; `reject` turns the route list into an allowlist. The values are
  `reject`, `review`, and `operator_default`.
- A route is an allowance for direct ALGO and ASA transfers from `sources`
  of `assets` to `destinations` on `networks`. Treasury may pay ops in ALGO
  on mainnet and anyone in USD on either network; every other direct
  transfer from this key is a route miss and is rejected. Routes whose
  `sources` do not include this key never match it; in a key file, name the
  key or `*`.
- A route match lets the transfer continue through the other rules; it is
  not an approval. The document limits from step 4 and the warning review
  from step 2 still apply.
- Route `limits` add thresholds for that route. Treasury payments to ops
  above 500 ALGO are reviewed; USD payouts above 1000 USDC are rejected. A
  route's limits may only name networks and assets the route covers.
- When several routes match one transfer, the lowest threshold among them
  wins. A wildcard route with a limit therefore caps every narrower route it
  overlaps; put key-wide ceilings in the document `limits` instead.
- `blocked_destinations` is checked before any route, so the wildcard
  `treasury-usd-payouts` route cannot pay the blocked address.
- Close-outs and clawbacks are rejected unless a matching route sets
  `allow_close` or `allow_clawback`, and the `reject_*` settings from step 2
  override even that. For those routes, asset opt-ins, and the exact
  matching rules, see [USER_TRANSFER_ROUTING.md](USER_TRANSFER_ROUTING.md).

### 7. The complete document

```json
{
  "format": "aplane.policy.v1",
  "role": "signer",
  "key": "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM",
  "description": "Treasury key",
  "reject_foreign_rekey": true,
  "reject_close_remainder": true,
  "reject_asset_close": false,
  "reject_clawback": true,
  "always_review_warnings": true,
  "auto_approve_self_noop_transfer": false,
  "max_fee_microalgos": "10000",
  "transaction_types": {
    "*": "reject",
    "pay": "allow",
    "axfer": "allow",
    "keyreg": "review"
  },
  "limits": {
    "mainnet": {
      "algo": { "review_above": "100000000", "reject_above": "1000000000" },
      "asa:31566704": { "reject_above": "5000000000" }
    }
  },
  "address_sets": {
    "treasury": ["CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"],
    "ops": {
      "mainnet": ["EIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDOHSEZI"],
      "testnet": ["GMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZ6LH5CFA"]
    }
  },
  "asset_sets": {
    "usd": {
      "mainnet": ["asa:31566704"],
      "testnet": ["asa:10458941"]
    }
  },
  "transfer_policy": {
    "on_no_route": "reject",
    "close_on_no_route": "reject",
    "clawback_on_no_route": "reject",
    "blocked_destinations": ["KVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVDNKFTE"],
    "routes": [
      {
        "id": "self-transfer",
        "description": "Any account may send any asset to itself",
        "networks": ["*"],
        "sources": ["*"],
        "assets": ["*"],
        "destinations": ["self"]
      },
      {
        "id": "treasury-to-ops",
        "description": "Treasury tops up ops in ALGO",
        "networks": ["mainnet"],
        "sources": ["@treasury"],
        "assets": ["algo"],
        "destinations": ["@ops"],
        "limits": {
          "mainnet": { "algo": { "review_above": "500000000" } }
        }
      },
      {
        "id": "treasury-usd-payouts",
        "description": "Treasury pays anyone in USD, capped per payment",
        "networks": ["mainnet", "testnet"],
        "sources": ["@treasury"],
        "assets": ["@usd"],
        "destinations": ["*"],
        "limits": {
          "mainnet": { "asa:31566704": { "reject_above": "1000000000" } },
          "testnet": { "asa:10458941": { "reject_above": "1000000000" } }
        }
      }
    ]
  }
}
```

A larger variant with close-out and clawback routes is the contract fixture
[`test/contracts/policy/v1/signer_key_full.json`](../test/contracts/policy/v1/signer_key_full.json),
which the schema and decoder tests keep valid; its cosigner counterpart is
`cosigner_key_full.json` beside it.

### 8. Check, diff, and apply

```bash
apadmin policy check treasury.json
apadmin policy diff treasury.json
apadmin policy apply treasury.json
```

`check` reports errors with the JSON Pointer of the failing field and prints
warnings; for this document there are none. Against a fresh store, `diff`
opens with "the key gets a policy of its own; compared with the node default
it followed", then marks the guards, the type verdicts, the fee cap, the
limits, the route-miss actions, and the blocked destination `tightened`, the
two new routes `loosened`, and the description and sets `changed`. Confirm the
changes are the ones you intended, then apply. `status` now lists the key as
`own policy`. Work through the [Validation Checklist](#validation-checklist)
before relying on the policy.

To take the key back to the default later, `apadmin policy remove <key>`
shows the effective change (marked `loosened` where the default is more
permissive) and asks before deleting the file.

### What this policy does not control

- **Inner transactions.** Routing inspects the signed transaction only, not
  what an application does with it.
- **Group totals.** Thresholds apply to each transaction. A group of several
  transfers that are each below a threshold is not summed against it.
- **Accounts after a rekey.** A key file is selected by the key that signs.
  Once an account is rekeyed to another key this node holds, that key's
  policy governs it, file or default.
- **The operator default.** `user_auto_approve` lives in
  `identities/default/config.yaml`, outside the policy documents.
- **Who may ask and whether keys are unlocked.** Client enrollment and
  unlock state are separate from policy.

## Basic Example

A node default that keeps the shipped guards, rejects ALGO close-outs, and
caps fees at 1 ALGO:

```json
{
  "format": "aplane.policy.v1",
  "role": "signer",
  "key": "default",
  "reject_foreign_rekey": true,
  "reject_close_remainder": true,
  "reject_asset_close": false,
  "reject_clawback": false,
  "always_review_warnings": true,
  "auto_approve_self_noop_transfer": false,
  "max_fee_microalgos": "1000000",
  "transaction_types": { "*": "allow" },
  "transfer_policy": {
    "on_no_route": "operator_default",
    "close_on_no_route": "operator_default",
    "clawback_on_no_route": "operator_default",
    "routes": [
      {
        "id": "self-transfer",
        "description": "Any account may send any asset to itself",
        "networks": ["*"],
        "sources": ["*"],
        "assets": ["*"],
        "destinations": ["self"]
      }
    ]
  }
}
```

This rejects foreign rekeys and ALGO close-outs, forces review for
warning-level findings, and rejects any transaction fee above 1 ALGO. Route
misses stay with the operator default. Apply it with
`"key": "default"` and it governs every key without a file of its own;
[Writing a key policy](#writing-a-key-policy) builds a document that makes
one key's transfers an allowlist.

## Transfer Routing

`transfer_policy` is the route table for direct signer-controlled ALGO and ASA
movements. It can constrain:

- source account,
- asset,
- destination,
- network,
- amount thresholds,
- close-out and clawback behavior.

A matching route means the movement may continue through the remaining policy
pipeline. It is not an approval. Routing can reject a movement or force review,
but it never auto-approves signing.

Minimal signer shape (the other required fields omitted here for brevity):

```json
  "transfer_policy": {
    "on_no_route": "reject",
    "close_on_no_route": "reject",
    "clawback_on_no_route": "reject",
    "blocked_destinations": [],
    "routes": []
  }
```

`on_no_route` controls in-scope transfer movements that match no route:

| Value | Meaning |
|-------|---------|
| `reject` | Route misses are rejected. This is the allowlist mode. |
| `review` | Route misses require operator review. This is useful during rollout. |
| `operator_default` | Route misses produce no routing verdict. |

`close_on_no_route` and `clawback_on_no_route` accept the same values and are
required too, so the stricter close-out and clawback fallback is always
explicit. They apply only when no route matches; a matching route that lacks
`"allow_close": true` or `"allow_clawback": true` still rejects.

`blocked_destinations` is checked before route matching, so a wildcard route
cannot rescue a blocked recipient.

For detailed route fields, movement extraction, amount unit rules, close-out
and clawback behavior, grouped transactions, cosigner documents, and routing
audit IDs, see [USER_TRANSFER_ROUTING.md](USER_TRANSFER_ROUTING.md).

## Common Allowlist Example

This signer default allows all direct ALGO and ASA transfers to two approved
recipients and denies direct transfers to all other recipients, for every key
without a file of its own:

```json
{
  "format": "aplane.policy.v1",
  "role": "signer",
  "key": "default",
  "reject_foreign_rekey": true,
  "reject_close_remainder": false,
  "reject_asset_close": false,
  "reject_clawback": false,
  "always_review_warnings": true,
  "auto_approve_self_noop_transfer": false,
  "max_fee_microalgos": "0",
  "transaction_types": { "*": "allow" },
  "transfer_policy": {
    "on_no_route": "reject",
    "close_on_no_route": "reject",
    "clawback_on_no_route": "reject",
    "routes": [
      {
        "id": "approved_recipients_all_assets",
        "description": "Allow all assets to approved recipients.",
        "networks": ["*"],
        "sources": ["*"],
        "assets": ["*"],
        "destinations": ["APPROVEDADDRESS1...", "APPROVEDADDRESS2..."]
      }
    ]
  }
}
```

With `"on_no_route": "reject"`, any covered transfer movement that does not
match the route is rejected, including an ASA opt-in, since the
`self-transfer` route is not in this document. Non-transfer policy layers
still apply independently.

The cosigner equivalent is one file per witness key. Its `transfer_policy`
holds only `routes` and `blocked_destinations`, its `transaction_types` may
allow only `pay` and `axfer`, and a finite fee cap keeps a permitted
self-payment from carrying any fee (a cosigner has no warning review, and
`check` warns when routes exist with no cap):

```json
{
  "format": "aplane.policy.v1",
  "role": "cosigner",
  "key": "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ",
  "reject_close_remainder": false,
  "reject_asset_close": false,
  "reject_clawback": false,
  "reject_rekey": true,
  "max_fee_microalgos": "5000",
  "transaction_types": {
    "*": "reject",
    "pay": "allow",
    "axfer": "allow"
  },
  "transfer_policy": {
    "routes": [
      {
        "id": "approved_recipients_all_assets",
        "networks": ["*"],
        "sources": ["*"],
        "assets": ["*"],
        "destinations": ["APPROVEDADDRESS1...", "APPROVEDADDRESS2..."]
      }
    ]
  }
}
```

Start such a file with `apadmin policy template --key <WitnessKeyID>` on the
cosigner node: it writes the deny-all default with the key filled in, and the
allow-list is what you add.

## Validation Checklist

Before relying on a policy:

1. Run `apadmin policy check FILE` (or `apadmin policy rescue check FILE`
   while the daemon is stopped) and read its warnings.
2. Confirm the route miss behavior is intentional, especially
   `"on_no_route": "reject"`, `"close_on_no_route": "reject"`, and
   `"clawback_on_no_route": "reject"`, and that `transaction_types` rejects
   nothing the key legitimately signs.
3. Confirm address and asset set names resolve on the intended networks.
4. Confirm amounts are decimal strings in raw base units.
5. Run `apadmin policy status` and confirm each held key shows the coverage
   you expect: `own policy` or `default`. On a cosigner node, a key on the
   shipped default rejects every request.
6. Install the policy with `apadmin policy apply FILE`, which signs the
   sidecars and activates the policy. For hand-placed documents, run
   `apstore policy sign` and start the signer.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| Edited policy has no effect | The file was checked but not applied, or a hand-placed document was signed while the signer was running and it has not restarted since. |
| A change to the default has no effect on one key | The key has a policy of its own; `apadmin policy status` shows it as `own policy`. Edit that file, or `remove` it so the key follows the default. |
| Signer refuses to load policy | A sidecar is missing or does not match its document, a document does not decode, or the generation has no `default.json`. |
| `apply` fails with `policy_snapshot_changed` | The active policy changed after `apply` read it; check the current state with `apadmin policy status` and apply again. |
| `check` rejects a file with "missing required field" | Key files and defaults are complete documents; start from `apadmin policy template --key K` rather than a fragment. |
| `check` rejects a file with "is not accepted in a cosigner document" | The file carries a signer-only field (`reject_foreign_rekey`, `always_review_warnings`, `auto_approve_self_noop_transfer`, the `*_on_no_route` family, `review_above`, or a `review` type verdict). |
| `export --key K` fails with `policy_document_not_found` | The key has no policy of its own; it follows the default, which `export` without `--key` returns. |
| A cosigner key rejects every request | It has no file and follows the deny-all default; give it one with `apadmin policy template --key <WitnessKeyID>`, edited and applied. |
| A request is rejected with `transaction_type:<type>` | The governing document's `transaction_types` rejects that type, directly or through `*`. |
| A transfer is rejected unexpectedly | `"on_no_route": "reject"`, a blocked destination, close/clawback denial, or a stricter matching route threshold. |
| A route does not match an ASA | ASA IDs are network-local; check the transaction network and any `asset_sets` mapping. |
| A route in a key file never matches | Its `sources` do not include the key; a key file's routes match only transfers that key signs. |

For implementation-level details, see [ARCH_POLICY.md](ARCH_POLICY.md). For
network token rules, see [ARCH_NETWORKS.md](ARCH_NETWORKS.md).
