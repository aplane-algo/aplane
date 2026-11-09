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
  key the node holds, whatever its type, including the spending key's side of a
  cosigned (cosigner-backed) account. Generating or importing a key adds it to the default's
  set; nothing is written per key until you give the key a file of its own.
- **On a cosigner node, a key is a cosigner witness, selected by its Witness
  Key ID.** A cosigner key's policy governs every cosigned account composed with
  that witness. This set is virtual: the cosigner does not hold
  those accounts and cannot list them. Any signer holding the key's public
  reference can compose new accounts with it, and the cosigner learns of one
  when a request for it arrives. Routes with `sources: ["*"]` accept every such
  account; routes naming addresses or sets pin the document to accounts the
  operator has agreed to witness for.

A cosigned account is governed on both nodes at once, and a transfer must be
allowed by both: the signer's policy for the account and the cosigner's policy
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
  "rekeys": "reject_foreign_rekey",
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

### Cosigner presets

To give a cosigner key (or the cosigner default) rules without writing routes
from nothing, start from a preset: a named starting document for one common
intent. A preset is only starting text. It goes through the same `check`,
`diff`, and `apply` as any other document, and the diff shows exactly what it
opens compared with what governs the key now.

| Preset | Allows | Placeholders |
|--------|--------|--------------|
| `deny-all` | Nothing | none |
| `self-only` | Any account sending any asset to itself (ASA opt-ins, self-payments) | none |
| `listed-destinations` | Any account sending any asset to the addresses in `@destinations` | the destination addresses |
| `capped-any` | Any transfer anywhere, refusing an ALGO transfer above the cap on a capped network | the mainnet ALGO cap; add other networks yourself |
| `any-transfer` | Any transfer anywhere; no spend protection, for testing | none |

Every preset refuses close-outs, clawbacks, rekeys, and every transaction type
other than payments and asset transfers, and caps the fee at 0.01 ALGO; edit
the document to change any of that. A placeholder looks like
`REPLACE-WITH-DESTINATION-ADDRESS` and is never a valid value, so `check`
rejects the document at the placeholder until you fill it in.

```bash
apadmin policy template --list-presets
apadmin policy template --preset listed-destinations --key <WitnessKeyID> > key.json
```

`--preset` needs no node and no passphrase. In the apadmin TUI, pressing `e`
on a cosigner key without a policy of its own, or on the cosigner default,
first asks for the starting text: the current document, or one of the
presets.

### Signer presets

A signer key has presets too, stricter starting points than the shipped
signer default (which allows every transaction type and leaves routing
misses to the operator default). They share three names with the cosigner
presets but not their meaning, so the command line takes `--role signer` to
select them; without `--role`, `--preset` and `--list-presets` mean the
cosigner presets, as before.

| Preset | Allows | Placeholders |
|--------|--------|--------------|
| `deny-all` | Nothing: every transaction is rejected | none |
| `self-only` | Payments and asset transfers to the sender itself (ASA opt-ins, self-payments, nonzero ones too) | none |
| `listed-destinations` | Payments and asset transfers to the addresses in `@destinations`; an ASA opt-in passes only if the sender is listed | the destination addresses |
| `transfers-only` | Payments and asset transfers to any address; amounts are not capped | none |

Every signer preset rejects every other transaction type (application calls,
asset configuration and freezes, key registration), close-outs, clawbacks
and routing misses; rejects rekeys to an address this node does not hold;
sends warnings to review; and leaves self no-op auto-approval off. What the
presets do not do:

- **They do not approve anything.** A permitted transaction goes to the
  Operator Default (or to review, when a warning asks for it), so it follows
  User Auto-Approve: with it off, you approve each one; with it on, nothing
  asks. No preset changes that setting.
- **They do not forbid rekeys.** A rekey to another key this signer holds can
  still be allowed, and that key's own policy then governs the account. A
  preset limits destinations and transaction types; it is not a custody
  boundary.
- **They do not cap amounts.** Only the fee is capped, at 0.08 ALGO per
  transaction. That stops a client burning the balance in fees on transfers
  the routes allow. It covers a full group of 16 payments or asset
  transfers at the minimum fee, every member at its most expensive
  authorization (a Falcon-delegated LogicSig at the largest program size)
  with the largest note allowed (76,916 microAlgos). It does not cover a group that
  pools other transactions' fees onto this key's, such as an app call
  paying for its inner transactions, or fees under network congestion:
  raise `max_fee_microalgos` for those.
- **They do not inherit.** A preset for one key replaces the node default for
  that key, and may be looser than it.

Routes match the transaction's sender, so `sources: ["*"]` also covers
accounts rekeyed to the key.

```bash
apadmin policy template --role signer --list-presets
apadmin policy template --role signer --preset listed-destinations --key <ADDRESS> > key.json
```

In the apadmin TUI, `e` on the signer default or on a held key without a
policy of its own offers the same choice of starting text as on a cosigner.
appolicy's `n` offers the role's presets after the shipped default and the
workspace's documents. Both show the notes above before you choose.

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
- `user_auto_approve`, which satisfies review requirements without a prompt
  and approves unmatched requests, but cannot override a rejection,
- app-call inner transaction behavior, which is not inspected by transfer
  routing.

Policy verdicts are ordered conservatively:

```text
Always Deny > Always Review > Always Approve > Operator Default
```

This means a reject rule cannot be approved through an operator prompt, and a
review rule blocks matching policy auto-approval rules. With
`user_auto_approve:true`, review requirements are satisfied automatically,
so no connected apadmin is needed. Hard rejection rules still apply. Nothing
is displayed on that path, so transaction types the approval screen cannot
show (state proof, heartbeat) sign as well; reject them by type for a key an
agent drives if it must never issue them. Within Always Deny and Always Review, the `transaction_types` verdict is
evaluated first: a rejected type never reaches the other rules, and the
rejection names the type. A spending-key, cosigned or listed rekey of a bounded
account always needs review (rule id `bounded_rekey_requires_review`), ahead of
every approval rule; User Auto-Approve satisfies it.

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
apadmin policy export --all ~/policy-export   # every document, with the node's context
apadmin policy check default.json key.json
apadmin policy apply default.json key.json
apadmin policy apply - < default.json
```

Each file is one document and names what it is in its `key` field:
`"default"` for the node default, or the key it governs. `apply` replaces the
listed documents and leaves every other key's document unchanged.

### Exporting the whole policy

`apadmin policy export --all DIR` writes every active document, exactly as
stored, into the new or empty directory `DIR`: the default as `default.json`
and each key's own document as `<key>.json`, mode 0600. It also writes the
node's policy context to `DIR/.appolicy/node.json`: its role, the networks it
maps, its ASA set, and the digests of the documents it held. `appolicy` uses
that file to check the documents against this node rather than against the
built-in tables (see [Checking policy files offline](#checking-policy-files-offline-with-appolicy)).
The export reads every document from one state of the node and writes
nothing if the policy or its context changes while it is being read; run it
again. An export that fails part way leaves a marker in `.appolicy`, and
`appolicy` and `apadmin` refuse its files until you export again into a new
directory.

Reviews show each ASA threshold in the node's terms: an asset in the
node's ASA set as display units with its base units, decimals, asset ID and
network, for example `2.5 USDC (2500000 base units; 6 decimals, asset
31566704 on mainnet)`, and any other asset in base units only.

When `check`, `diff` or `apply` is given files from an export, it first
compares the node with the export. If the node's policy, ASA set or network
map changed since, it stops before showing any review:

```text
apadmin: the export DIR/.appolicy/node.json (taken 2026-11-01T12:00:00Z) is stale: the node's policy changed since; export again and carry your edits over (policy_export_stale)
```

The old export does not track what changed, so apadmin cannot tell whether
your edits still fit the node. There are two ways on:

- **Export again.** Export into a new directory and carry your edits over.
  Each file is a complete document, so carrying an edited file over means
  copying it into the new export in place of the fresh copy. If the same
  document also changed on the node since the old export, merge the two by
  hand.
- **Review against the node as it is now.** `--no-node-context` skips the
  export comparison:

  ```bash
  apadmin policy diff --no-node-context DIR/<key>.json
  apadmin policy apply --no-node-context DIR/<key>.json
  ```

  `diff` and `apply` always compare a file with the document that governs
  its key now, not with the export, so the review shows exactly what the
  apply changes on the live node. Apply when the review shows only your
  edits. If it shows a change you did not make, the file would undo a change
  made on the node since the export; export again instead.

After any successful apply, an export taken before it is stale, including
the rest of the same export. Applying several files from one export in one
command keeps them together. Files from two exports, or from an export and
elsewhere, are refused in one command. `--node-context FILE` names the
context to compare instead of the one beside the files.

A file is from an export when its directory holds `.appolicy/`. Files
elsewhere (and stdin) are applied as before, and apadmin notes that there is
no export baseline to compare. Either way, the node still checks the review
against its state at commit: an apply is refused if anything the review saw
changed before it is committed.

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
shipped default for that role instead of the node's own, and
`apadmin policy template [--role signer|cosigner] --preset NAME [--key K]`
writes a [cosigner preset](#cosigner-presets), or with `--role signer` a
[signer preset](#signer-presets). These, with `--list-presets`, are the
forms that need no node and no passphrase, for writing policy on a machine
that has no store.

The apadmin TUI can also load one policy file: open Policies (`p`), press `a`,
and enter the file path, or press `ctrl+o` to browse for it. The browser
starts in your newest `~/policy-export-*` directory and lists `.json` files.
The TUI checks the file, shows the same diff as `apadmin policy diff`, and
applies it only after you press `y`. The file's `"key"` field names the
document, and the TUI refuses a file for a key the node does not hold; generate or import the key first. The path must name a
regular file, not a symlink. A file from an export is compared with the node
as `apadmin policy apply` does: the TUI refuses an unfinished export, and a
stale one before the review. The TUI has no `--no-node-context`. To load a
file from a stale export, export again, or copy the file into a directory
that has no `.appolicy/` and load the copy. The TUI then reviews the copy
against the node as it is now, the same as `--no-node-context`. Apply it only
when the review shows just your edits (see
[Exporting the whole policy](#exporting-the-whole-policy)). The TUI does not
remove documents or take several files at once; `apadmin policy` covers
those.

To take a copy of the node's current policy, open Policies (`p`) and press
`x`. The TUI writes the same export as `apadmin policy export --all`, into a
new or empty directory (the prompt suggests `~/policy-export-<time>`): the
node default as `default.json`, each key's own document as `<key>.json`, and
the node's context as `.appolicy/node.json`; `ctrl+o` browses for where to
create it. It refuses a directory that already holds files, and it writes
nothing if the policy or its context changed while the documents were being
read; refresh and export again. The files can be checked, explained, and
edited offline with `appolicy`, and installed again with `apadmin policy
apply`.

### Editing a policy in apadmin

To change a policy without a file, open Policies (`p`), select the document,
and press `e`. The list shows the node default first, labelled "node default",
then every held key marked "own policy" or "default", and any stored file for
a key the node no longer holds ("key not held"). Below the list, the selected
row shows its status in full and its document's size, SHA-256, and applied
time. The document's JSON opens in an editor. Edit it, then press `ctrl+s`: apadmin checks the text, shows the same diff as a file
load, and applies it only after you press `y`. Nothing is stored before that.

- **A key on the default opens on the default.** Selecting a key that has no
  file of its own opens the editor on the node default with the key filled in,
  marked "No policy of its own yet". Applying it, changed or not, gives the key
  its own policy. Any other document opens exactly as stored.
- **Presets.** `e` on the default or on a key without a policy of its own
  first asks what to start from: the document it would open on anyway, or
  one of the role's presets ([cosigner](#cosigner-presets),
  [signer](#signer-presets)).
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
| `template --embedded signer\|cosigner [--key K]` | Write the shipped default for that role instead; needs no node and no passphrase |
| `template [--role signer\|cosigner] --preset NAME [--key K]` | Write a preset instead (cosigner without `--role`); needs no node and no passphrase |
| `template [--role signer\|cosigner] --list-presets` | List the presets for the role (cosigner without `--role`) |

`check`, `diff` and `apply` also take `--node-context FILE`, to compare the
node with that export context instead of the one beside the files, and
`--no-node-context`, to compare it with none; see
[Exporting the whole policy](#exporting-the-whole-policy).

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
`apply` prints the new generation ID and `policy_set_sha256`. An apply that
would leave the policy set unchanged prints `policy unchanged` and writes no
generation. Each apply that changes the set leaves a retained generation until
explicit generation pruning; see
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

### The node's ASA set

A node keeps an ASA set: the built-in asset table plus the assets you confirm
on it. It does two things only: it labels assets (name, unit name, decimals),
and it decides which specific assets your policy documents may name. It never
decides what a transaction may do: a route with `"assets": ["*"]` still lets
any asset through, listed or not.

An asset is identified by its chain and its ID. The same ID on another
network is another asset, or none: `31566704` is USDC on mainnet only.

```bash
apadmin asa list                       # built-ins and confirmations, with the network naming each chain now
apadmin asa add private-dev 1234567    # look it up on the node and confirm it
apadmin asa remove private-dev 1234567 # remove a confirmation
```

- **add** reads the asset from the network's configured algod, after
  checking that node serves the network's chain, and shows its chain, name,
  unit name, decimals, total, creator and issuer addresses. A clawback or
  freeze address is called out: it means the issuer can take or freeze
  holdings. Only the name, unit name and decimals are recorded; the issuer's
  addresses can change later. You confirm before anything is stored
  (`--yes` skips the prompt), and the node reads the asset again and adds it
  only if nothing changed. A built-in asset needs no confirmation.
- **remove** is refused while any of the node's policy documents names the
  asset, and lists where. An entry whose network now names another chain is
  shown as inactive and removed with `--genesis HASH ID`.
- Adding and removing commit a new store generation, like a policy apply.
  Backups do not carry the ASA set: after restoring a backup onto a fresh
  node, confirm the assets again.

`apadmin policy check` and `apply` refuse a document you submit that names
something the node does not know:

- a network the node does not map (a typo such as `mainet` in a `limits` key
  would otherwise silently drop that limit);
- an asset outside the ASA set;
- a direct `asa:<id>` route term in a route over several networks or `*`,
  since the ID names an asset on one chain only (list one network, or use an
  asset set with a member per network);
- a route that has no asset on one of the networks it applies to (`*` means
  every network the node knows).

Only documents you submit are checked. A document already stored keeps
working as it did, and never blocks an apply of other documents or an ASA set
change; its problems appear as alerts in the node's status until you fix it.
Submitting it again, even unchanged, requires fixing it, and removing it needs
no repair first. `appolicy` reports the same problems offline: as errors for
files from an export, which carries the node's networks and ASA set, and as
warnings otherwise.

#### Fixing documents the node refuses

A direct `asa:<id>` term in a route over several networks names a different
asset, or none, on each chain. Nothing rewrites it for you, because only you
know which asset you meant on each network. Either give the route one
network:

```json
{"id": "usdc-out", "networks": ["mainnet"], "sources": ["*"],
 "assets": ["asa:31566704"], "destinations": ["*"]}
```

or name the asset on each network with an asset set, which may hold members
for only some networks:

```json
"asset_sets": {
  "usdc": {"mainnet": ["asa:31566704"], "testnet": ["asa:10458941"]}
},
"transfer_policy": {"routes": [
  {"id": "usdc-out", "networks": ["mainnet", "testnet"], "sources": ["*"],
   "assets": ["@usdc"], "destinations": ["*"]}
]}
```

A route over `"*"` with an asset set needs a member on every network the node
knows, or an `algo` or `*` alternative for the others; list the networks
instead when the route is meant for some of them. A network the node does not
map is usually a typo; otherwise map it in the node's `networks` config. An
asset outside the ASA set is added with `apadmin asa add NETWORK ID` after
checking what the lookup shows.

Amounts in approval prompts and limit messages come from the same ASA set:
a known asset in its display units with its base units beside them, for
example `ASA Transfer: 1.5 XYZ (150 base units), asset #9, private-dev`, and
any other in base units with "Not in this node's ASA set". Limit messages,
from document limits and route limits alike, name the asset and network, for
example `transfer routing amount 1.5 XYZ (150 base units) of asset #9 exceeds
reject threshold 1 XYZ (100 base units) on private-dev`. A prompt keeps the
values it was created with even if the ASA set changes while it waits.

### Checking policy files offline with appolicy

`appolicy` edits, checks, formats, explains, tries, and tests policy files without a node,
a store, or a passphrase. It is installed with the signer binaries.

```bash
apadmin policy export --all policy/ # on the node: the documents and the node context
appolicy policy/                    # browse and edit the files in a terminal UI
appolicy check treasury.json        # errors and warnings, by JSON Pointer
appolicy check policy/              # every *.json file in a directory
appolicy check --json policy/       # the same report as JSON, for CI
appolicy fmt policy/                # rewrite files in canonical form
appolicy explain treasury.json      # one document in plain language
appolicy try treasury.json --from ADDR --to ADDR --amount 600000000 --network mainnet
                                    # what the document decides for one transaction
appolicy test policy/               # re-run the saved cases in policy/.appolicy/cases.json
```

- **The node context.** Files from an export
  (`apadmin policy export --all DIR`) are checked against the node the export
  was taken from, using `DIR/.appolicy/node.json`: its networks, its ASA set
  (the assets it knows, with their decimals and names) and its role. A
  network the node does not map, an asset outside its set, an ambiguous
  `asa:<id>` route term, or a route with no asset on one of its networks is
  an error, since the node would refuse to admit it; the role of the node
  seeds new documents, and a document for the other role is an error. Other
  files are checked against the built-in networks and assets only, and those
  problems are warnings. `--node-context FILE` uses a context from elsewhere.
  `check` says which it used and how old the export is: the context is an
  offline snapshot, and `apadmin policy apply` refuses files from an export
  the node has since moved on from. An unfinished export, a damaged context
  file, or files from two exports is an error, never a quiet fallback to the
  built-in tables. appolicy never reads a signer's data directory; the
  removed `--signer-data` flag is refused with a pointer to the export.

- **The editor.** `appolicy PATH...` (or `appolicy open PATH...`) opens a
  terminal UI on the named files. A directory lists its files; a single file
  opens straight on it. Each document is shown as an outline (summary, guards,
  fee cap, transaction types, limits, sets, transfers, routes) beside a form
  of the selected section's fields, with every problem shown on the field it
  concerns. Fields the document lacks are marked missing, optional fields that
  are not set are shown so they can be set, and members the format does not
  define are listed under "Other fields", so nothing in the file is hidden.
  - **Reading:** `v` shows a field in full, `]` and `[` jump between problems,
    `p` lists them, `x` explains the document, `c` compares it with the
    workspace default or another file you pick, and `?` lists every key.
  - **Editing:** enter edits the selected field and space toggles a yes/no
    one. Choices offer only what the node role allows; amounts are typed in
    display units when the asset's decimals are known (the editor shows them
    and where they came from) and stored in base units; address lists are
    checked as you type, and tab inserts a suggestion the field accepts
    (`*`, `self`, a set of the right kind, a network, or an address or asset
    the document already uses). An asset is typed by its ID, bare
    (`31566704`) or as `asa:31566704`, and stored as `asa:<id>`; files
    themselves must use `asa:<id>`, which check and fmt never repair.
    Before you press enter, the editor shows what the ID is on the field's
    network: an asset-set member's network, a route's one network, or the
    network you name in a new limit. With an export it says whether the
    node's ASA set has it, as the export recorded it; without one it says
    whether the built-in table has it, or that its decimals are unknown and
    amounts are in base units. A direct ID in a route over several networks
    or `*` gets no identity: name the asset per network in an asset set. For
    a list, the asset being typed is shown, with a count of problems among
    all of them. `a` adds to a section (a route, a set, a
    member, a limit, a transaction type, a rekey edge, or a starting value
    for a missing or broken part), `C` copies the selected route, address or
    rekey edge (sets are copied with `a`), `d` removes the selected field or
    route, and `u` and ctrl+r undo and redo. Every edit is checked at once,
    the same way check does.
  - **Saving:** `s` shows the changes against the file as loaded, with
    tightened and loosened labels, and writes only after `y`, in canonical
    form. A new file has nothing loaded to compare with: it is compared with
    the workspace default when there is one for its role, and `b` picks
    another workspace file (as edited, unsaved edits included) or none. That
    comparison reference is a local file, not the policy the node runs, and
    it never changes what is written or which file the save checks for
    conflicts. A save that would not pass check is allowed as a draft and
    says so, and a file's comments are not kept. While the open document
    has an error (its own, a workspace rule such as two files for one key,
    or what the node's export would refuse), the status line starts with
    "does not pass check"; warnings alone do not set it. If the file changed on disk, was
    deleted, or appeared since it was loaded, nothing is written: you choose
    to reload it (discarding your edits), save your edits to a new file, or
    overwrite it after seeing what the overwrite replaces. The check is
    best-effort; another program can still write the file between the check
    and the write.
  - **Trying and saved cases:** `t` opens a form to try a transaction
    against the open document as edited, saved or not, with the same answer
    and assumptions as `appolicy try`; on a signer key's own document the
    sender starts as that key. Enter tries it and `ctrl+s` keeps the answer
    as a saved case under a name. The saved cases run again after every key
    against the documents as edited: the header shows how many pass or fail,
    and `T` lists them with what each got and expected, so an edit that
    changes a decision shows before you save it. Networks come from the
    node context as for try.
  - **New documents:** `n` asks which document (the default or a key), what
    it starts from (the shipped default for the role, a copy of a workspace
    document, or one of the role's presets), and its file name, and opens it
    unsaved.
  - A file that is not valid JSON opens read-only: repair it in a text
    editor and press `r`. Quitting with unsaved edits asks first.
- **check** decodes each file with the node's own decoder, so it reports the
  same errors at the same JSON Pointers, and the same warnings, as
  `apadmin policy check`. It exits 0 when no file has an error and 1 when one
  does; warnings never fail it. Every file named, directly or through a
  directory, is checked as one set: each document is identified by its
  `"key"` field, not its file name, and check also reports a second `default`
  document, a key in two files, or documents for different roles.
- **What it cannot know.** It does not see the node: which keys the node
  holds or which policy it runs now. From an export it knows the node's
  networks and ASA set as they were when the export was taken. Run
  `apadmin policy diff` and `apply` to review and install a file.
- **fmt** rewrites a file with two-space indentation and fields in a fixed
  order, so repeated edits give stable diffs. It leaves a file that is not
  valid JSON untouched, refuses a file with comments unless you pass
  `--strip-comments` (move notes into `description` fields), and refuses to
  overwrite a file that changed on disk after it was read. `--check` only
  lists the files it would change.
- **try** asks what one valid document decides for one transaction, through
  the same policy evaluator the signer runs. A signer document rejects the
  transaction, requires review (naming the rule), approves it without review
  (the self no-op rule), or leaves it to the operator default; a cosigner
  document permits or rejects it. Describe the transaction with `--from`,
  `--to` (an address or `self`), `--amount` in base units (microAlgos, or the
  asset's raw units), and optionally `--asset`, `--network` (default
  `testnet`), `--fee` (default 1000), `--close-to`, `--clawback-from` and
  `--rekey-to`. A rekey is foreign unless you add `--rekey-held` to say the
  node holds the target's key; `reject_foreign_rekey` treats a target on the
  signing account's rekey-to list the same way, so try a listed target with
  `--rekey-held`. `--json` prints the result as JSON. It exits 0
  whatever the verdict and 2 for bad input.

  The answer is the document's, not the node's, and it lists what it
  assumed: the fee you entered, no fee or dummies the signer adds for
  LogicSig or post-quantum keys, an unknown key type, and no refusals the
  signer makes before policy. For a cosigner document it also assumes the
  cosigner holds the witness key and applies this document. Networks come
  from the node context, exactly as exported, else the built-in networks
  only; the same mapping compiles the document, so a custom network's routes
  resolve.
- **test** re-runs the workspace's saved cases: tries kept with the answer
  expected, so an edit that changes a decision you already made is caught
  before the document is installed. They live in `.appolicy/cases.json` in the
  workspace directory (the default is the current directory), which is never
  read as a policy document. Each case names a document by its path in the
  workspace, the transaction, and the outcome (`reject`, `review`, `approve`
  or `default`, the words try prints) with its rule:

  ```json
  {
    "format": "aplane.policy-cases.v1",
    "cases": [
      {
        "name": "600 ALGO top-up to ops needs review",
        "document": "treasury.json",
        "txn": {"network": "mainnet", "sender": "TREAS...", "receiver": "OPS...", "amount": 600000000},
        "expect": {"outcome": "review", "rule_id": "transfer_policy:treasury-to-ops:review_above"}
      }
    ]
  }
  ```

  The transaction takes try's fields (`network`, default `testnet`; `sender`;
  `receiver`; `amount`; `asset`; `fee`, default 1000; `close_to`;
  `clawback_from`; `rekey_to`; `rekey_target_held`). A review or approval
  matches its deciding rule; a rejection matches its first violation's rule,
  or any rejection when `rule_id` is omitted. test exits 0 when every case
  passes, 1 when one fails, and 2 when the file is bad or a case cannot run
  (its document is missing or invalid). It writes nothing.
- **explain** describes a valid document. Amounts are shown in base units and,
  where the asset's decimals are known, in display units: from the node's
  ASA set in the export, else from the built-in asset table.

This `appolicy` is not the retired binary of the same name: it edits and
checks files only, and never contacts a node or opens a store. The retired
flags (`-online`, `-check`, `-yaml`, `-sha256`, `-save`) are refused with a
pointer to `apadmin policy`.

#### Commands of the retired policy binary

The earlier `appolicy` edited a node's policy. Its command shapes map to
`apadmin` as follows:

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

There is no wrapper or automatic online-to-rescue fallback. A former command
line that names a file now opens that file in the editor described above,
which writes nothing until you save.

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
key file) without requiring sidecars, reports a document that has no sidecar
yet, and warns about files for keys the node does not hold. A document whose
sidecar is missing or no longer matches was placed by hand, so it is checked
like a submitted one: an unknown network or an asset outside the ASA set
fails the check. A document whose sidecar still verifies was accepted before
and is only warned about. `apstore policy sign` refuses the same documents,
then writes fresh sidecars for every stored document. `apstore policy verify`
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
| `rekeys` | signer | yes | How the signer treats a txn with a non-zero `RekeyTo`: `reject_all_rekeys` rejects it; `reject_foreign_rekey` rejects it unless this node holds the target or the target is on the signing account's own [rekey-to list](USER_KEYTYPES.md#rekey-to-lists) (the shipped default); `allow_rekeys` rejects nothing. This setting only rejects: a rekey it lets through still meets the rekey warning, review rules and operator approval, and User Auto-Approve can approve it. A rejection outranks all of those. The signer's own rotation rekeys are never rejected. |
| `reject_rekey` | cosigner | yes | Reject every txn with non-zero `RekeyTo` this cosigner is asked to sign. With `false`, a rekey still fails unless `rekey_policy` allows the edge. A bounded account's listed rekey never asks the cosigner, so this doesn't stop it. |
| `reject_close_remainder` | both | yes | Reject payment txns with non-zero `CloseRemainderTo`. |
| `reject_asset_close` | both | yes | Reject ASA transfer txns with non-zero `AssetCloseTo`. |
| `reject_clawback` | both | yes | Reject ASA clawback txns using `AssetSender`. |
| `always_review_warnings` | signer | yes | Require operator review for warning-level findings unless User Auto-Approve is on. |
| `auto_approve_self_noop_transfer` | signer | yes | Auto-approve exact low-risk 0-amount self-transfer shapes. |
| `max_fee_microalgos` | both | yes | Reject txns whose fee exceeds this microAlgo ceiling; `"0"` means no cap. |
| `transaction_types` | both | yes | Map from transaction type (`pay`, `axfer`, `acfg`, `afrz`, `appl`, `keyreg`, `stpf`, `hb`) or `*` to `allow`, `review`, or `reject`; `*` covers every type not named and is required in a signer document. A cosigner document may `allow` only `pay` and `axfer` and may not use `review`; its `*` can only be `reject`, so it may be left out. |
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

For cosigner rekey authorization, set `"reject_rekey": true` to refuse every
rekey the cosigner is asked to sign. To authorize a controlled rekey, set
`"reject_rekey": false` and add `rekey_policy.allowed` entries:

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

`rekey_policy` applies to every cosigned rekey of a cosigned account, on a
plain or bounded host: a `spending_key` rekey on a cosigned account, or a target
off the list under `plus_cosigned`.
A listed rekey takes the spending key alone and never asks the cosigner, so on
an account with a [rekey-to list](USER_KEYTYPES.md#rekey-to-lists)
`"reject_rekey": true` doesn't stop a rekey to a listed address, and
`rekey_policy` picks only the targets of cosigned rekeys. The list is the
owner's standing statement, fixed in the account's program. A Corridor account
takes only listed rekeys, so it never asks the cosigner about one. To stop
listed rekeys, set the signer document's `rekeys` to `reject_all_rekeys`.

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
  "rekeys": "reject_foreign_rekey",
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
- `always_review_warnings` requires an operator prompt when User Auto-Approve
  is off and warning analysis finds a rekey, an ALGO or
  ASA close-out, a clawback, an application delete, clear-state, or update, an
  asset reconfigure, destroy, freeze, or unfreeze, or a fee above 1 ALGO. A
  rotating account's own rotation, the rekey to the next stage the signer
  derives itself, is not a finding.
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
prompts when User Auto-Approve is off; with it on, review is satisfied automatically. Keep `*` in the map; it is
required.

A `keyreg` verdict, `allow` included, covers online and offline registrations
only. The signer refuses a nonparticipating `keyreg` itself, whatever the
policy says: it marks the account as unable to participate, permanently.

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
  transfer from this key is a route miss and is rejected.
- A route matches by the transaction's **sender**, but the document is
  chosen by the **key that signs**. A key that signs for its own address
  needs routes naming that address, a set holding it, or `*`. After a
  rekey the two differ: if account A is rekeyed to this key, this file
  governs A's transactions, and its routes must name A, not the key. On a
  cosigner node the document belongs to a Witness Key ID and its `sources`
  are cosigned account addresses; see
  [Cosigner Documents](USER_TRANSFER_ROUTING.md#cosigner-documents).
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
  "rekeys": "reject_foreign_rekey",
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
  "rekeys": "reject_foreign_rekey",
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
  "rekeys": "reject_foreign_rekey",
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
allow only `pay` and `axfer` (every type it does not name is rejected, so
`"*": "reject"` may be left out), and a finite fee cap keeps a permitted
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

1. While writing, run `appolicy check FILE` and `appolicy explain FILE`, or
   edit the file with `appolicy FILE`; they need no node. Then run `apadmin policy check FILE` (or `apadmin policy
   rescue check FILE` while the daemon is stopped), which also checks the
   file against the node's keys, and read its warnings.
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
| Edited policy has no effect | The file was checked but not applied, or a document repaired in a stopped store has not been loaded by a successful signer start, reload, or unlock. |
| A change to the default has no effect on one key | The key has a policy of its own; `apadmin policy status` shows it as `own policy`. Edit that file, or `remove` it so the key follows the default. |
| Signer refuses to load policy | A sidecar is missing or does not match its document, a document does not decode, or the generation has no `default.json`. |
| `apply` fails with `policy_snapshot_changed` | Something the review saw changed before the apply committed: another apply, an ASA set change, or a network mapping change. Check the current state with `apadmin policy status` and apply again to review the node as it is now. |
| `check` rejects a file with "missing required field" | Key files and defaults are complete documents; start from `apadmin policy template --key K` rather than a fragment. |
| `check` rejects a file with "is not accepted in a cosigner document" | The file carries a signer-only field (`rekeys`, `always_review_warnings`, `auto_approve_self_noop_transfer`, the `*_on_no_route` family, `review_above`, or a `review` type verdict). |
| `export --key K` fails with `policy_document_not_found` | The key has no policy of its own; it follows the default, which `export` without `--key` returns. |
| `check`, `diff` or `apply` fails with `policy_export_stale` | The files come from an export the node has moved on from: its policy, ASA set or network map changed since. Export again with `export --all` into a new directory and copy your edited files into it, or run `diff --no-node-context FILE` to review against the live node and `apply --no-node-context FILE` when the diff shows only your edits (in the TUI, load a copy from outside the export). See [Exporting the whole policy](#exporting-the-whole-policy). |
| `appolicy` refuses `--signer-data` | appolicy no longer reads a signer's data directory. Export with `apadmin policy export --all DIR` and open the files in `DIR`. |
| A cosigner key rejects every request | It has no file and follows the deny-all default; give it one with `apadmin policy template --key <WitnessKeyID>`, edited and applied. |
| A request is rejected with `transaction_type:<type>` | The governing document's `transaction_types` rejects that type, directly or through `*`. |
| A transfer is rejected unexpectedly | `"on_no_route": "reject"`, a blocked destination, close/clawback denial, or a stricter matching route threshold. |
| A route does not match an ASA | ASA IDs are network-local; check the transaction network and any `asset_sets` mapping. |
| A route in a key file never matches | Its `sources` do not name the transaction's sender. The file governs what its key signs, but routes match the sender: the key's own address when it signs for itself, the original account's address when that account is rekeyed to the key, or a cosigned account address on a cosigner node. |

For implementation-level details, see [ARCH_POLICY.md](ARCH_POLICY.md). For
network token rules, see [ARCH_NETWORKS.md](ARCH_NETWORKS.md).
