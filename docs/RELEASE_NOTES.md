# Release Notes

Entries are newest first and include pre-release development history. Older
token, setup-file, and protocol-v5 entries describe behavior superseded by the
enrolled-key model and current admin protocol v8.0; they are not current setup
instructions. See [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) for current contracts.
Entries below that name `request-enrollment` describe the enrollment command
before it was renamed `enroll`.

## The signer refuses request fields it does not know

- Every signer endpoint that reads a request body refuses a field its request
  type does not declare, at any depth, with a 400 naming it: `request has
  unknown field "<name>"`. Such a field used to be dropped, so a misspelled
  hint did nothing and said nothing. So did the retired `lsig_size` written in
  any case but lowercase. Data after the JSON value is refused too. apshell
  and the SDKs send only declared fields. A caller that adds its own keys to a
  request object passed to the SDKs now gets the 400. A body whose read
  fails, a timeout or a body cut short, gets a 400 saying `failed to read
  request body`, before or after the value.
- A passthrough entry on `/sign` or `/plan` whose signed transaction carries
  no signature is refused, as `/sign/assemble` already refused one. The signer
  adds nothing to a passthrough and returns it as signed. On all three
  endpoints, a multisig none of whose subsigs is signed counts as no
  signature, whether it signs the transaction or delegates a LogicSig: it can
  never meet its threshold. `/sign/assemble` used to accept one. An escrow
  LogicSig, a program with no delegation, still counts.
- A LogicSig runtime argument that declares neither `byte_length` nor
  `max_size` was planned as 0 bytes, so a large one got too few dummies and
  the network refused the group. The signer now plans it at the size the
  request sends. It measures the hex without decoding it, so a secret value
  such as an HTLC preimage is not copied. If such an argument is required and
  the request leaves it out, `/plan`, `/sign` and `/sign/component` refuse
  the request with 400 (`missing required arg: <name>`): a plan made without
  the value would be short of dummies when `/sign` receives it. No template is
  refused for leaving the size out.
- A bounded account's derived arguments, the recipient proof and the rekey-to
  list proof, go in the slot that has their name. Assembly used to rely on the
  declarations and the slots being in the same order, which held only because
  generation writes them that way.
- `keyset_revision` in `/status` starts at a random value in each signer
  process instead of 0. A restarted signer reported the same low revisions
  again, so a client that had cached the key list under one of them could keep
  using a stale list. Clients compare it for equality, as before.
- ARCH_SIGNING.md now says that a single transaction carrying its own group ID
  can go through `/sign` and `/plan` only, and that the signer checks the
  assembly receipt, the chain does not.

## Resource dummies are counted at their real opcode cost

- The dummy transactions the signer adds to pool LogicSig budget were counted
  at an opcode cost of 1. Their program runs three opcodes, so it costs 3. A
  group whose declared LogicSig costs came within 2 per dummy of a 20,000
  boundary was planned one dummy short, and the network rejected it: one
  LogicSig declaring 39,999 got one dummy, though the group can then cost
  40,002, over two transactions' 40,000. It now gets two.
- The signer's planner, apshell's fee reserve, its cosigned and plugin dummy
  declarations, and the plain host's resource check and fee-limit warning at
  generation all count 3, as do the Go, Python and TypeScript SDKs' cosigned
  dummy declarations. No wire field changed.

## apshell refuses input it used to ignore or guess at

More places where what was sent could differ from what was typed, all in
apshell and its JavaScript API:

- **Unknown trailing words on a command are refused.** `send`, `sweep`,
  `optin`, `optout`, `close` and `keyreg` ignored a word they did not take, so
  `sweep algo to main leaving=1` dropped the reserve and swept the whole
  balance, and `send ... fee 2000` used the default fee. A fee given twice is
  refused too, on these and on `app call` and `app deploy`. A `to` with no
  address after it on `optout` is refused; it used to be dropped.
- **A command line may end with `# a comment`.** The documented examples do;
  they worked only because the trailing words were ignored. A `#` standing
  alone, followed by a space or the end of the line, now starts a comment. A
  word that begins with `#`, such as `#42`, is still an argument.
- **`note <text>` is gone; write `note=<text>`.** The spaced form took the next
  word as the note, whatever it was.
- **A rekey or close to the zero address is refused.** The network reads the
  zero address in that field as no rekey or close at all, so the transaction
  did nothing and was reported as done. The same holds for closing out an
  asset.
- **`keyreg <account> offline eligible=true` is refused.** It paid the 2 ALGO
  incentive fee on a registration that cannot be eligible. `eligible=` takes
  `true` or `false` only; `eligible=yes` was read as false.
- **Pasting more than one participation key is refused**, including part of
  one, or only its round lines, followed by all of another. The fields of two
  keys could be mixed.
- **`arg:` is refused on an atomic `send` to or from a set**: that path does
  not carry LogicSig arguments, and they were left out silently. An app call's companion
  payment (`--pay`) now carries the call's LogicSig arguments.
- **JavaScript numbers are not coerced.** An amount, fee or ID must be a
  number, a `BigInt` or a plain decimal string. `null`, `undefined`, `''`,
  `true`, `'0x10'` and `'1e6'` were read as 0, 0, 0, 1, 16 and 1000000; each
  is now an error, as is a whole number past `Number.MAX_SAFE_INTEGER`. The
  same forms are accepted inside option objects. `algo()` takes a number
  only: `algo(null)` was 0 ALGO and `algo('1e6')` a million.
- **JavaScript options are checked.** An option of the wrong type, such as
  `{wait: 'false'}` or `{note: 123}`, is an error; it was read as not given.
  So is an option a function does not read, such as `{Fee: 0}`,
  `{nowait: true}` or `{lsigArgs: ...}` on `send()`; each was ignored.
- **`setSimulate()`, `setWriteMode()` and `setVerbose()` take `true` or
  `false` only.** `setSimulate(undefined)` switched simulation off, and
  `setSimulate('false')` switched it on.
- **JavaScript account lists must hold only strings.** Another kind of entry
  was dropped, moving every entry after it.
- **`undefined` and `null` are refused where a name is expected.** They were
  read as the aliases "undefined" and "null". `NaN`, `Infinity` and fractions
  are refused there too. A plugin still receives a boolean or a `BigInt` as
  its text.
- **JavaScript `sweep()` is now the `sweep` command.** It closed the account,
  sending everything and resetting the account; the command of the same name
  sends the balance less what is to be left and keeps the account open. It
  now does that: `sweep(from, to, {asset, leaving, fee, wait})`, with `from`
  one account or a list, returning each account's outcome. To close an
  account from a script, call `close()`.
- **An ALGO `sweep` given no `leaving` leaves each account its minimum
  balance.** The default was 0, which builds a transaction the network
  refuses: an open account cannot send its minimum balance. The command and
  `sweep()` both do this. `leaving 0` is still taken as written, and an ASA
  sweep still leaves nothing by default.
- **`rekey`, `unrekey` and `close` say what they are about to do before the
  transaction is signed.** The lines, including the warning that this system
  cannot sign for a rekey target, were printed with the result, after the
  account had been rekeyed or closed. There is no new prompt.
- The MCP tool description said every amount is in human units. `fee=`,
  `pay=` and all JavaScript amounts are in microAlgos or base units, and it
  now says so.

## One description of a transaction, for the signer and for apshell

- apshell's review of a plugin-built group and the signer's approval prompt
  each had their own code for describing a transaction, and the two disagreed
  in places. Both now use one describer and one set of warning rules, so they
  say the same thing about the same bytes. The plugin review reads like the
  signer's prompt, followed by every finding the signer would warn about, each
  marked `!!`. That now includes a ClearState, an asset freeze and a fee above
  1 ALGO, which the plugin review did not flag. It names the network from the
  transaction's genesis hash, and says a rekey keeps control when the target
  is a key the connected signer holds.
- Two warnings are new for the signer as well: a key registration that marks
  the account nonparticipating (which the signer refuses to sign in any case),
  and one that carries only one of the vote and selection keys. Under
  `always_review_warnings` the second now forces a review.
- When no network name is known for a transaction's chain, the description
  shows the genesis hash.
- A key registration that goes online shows its participation keys in full,
  in base64, the form `goal account partkeyinfo` prints them in, so they can
  be compared. The signer's prompt showed the first 8 bytes of each, in hex.
  A key that is absent is shown as `(none)`.
- A transaction's lease is shown when it has one.
- A transaction type the describer does not know is shown with a line saying
  its fields are not shown.

## App calls keep the apps you list, as you list them

- `app call`, `app call raw` and the JS `appCall()` / `appCallRaw()` used to
  tidy the foreign-apps list: repeats were dropped and the called app was
  removed. A program that reads the list by position (`txna Applications N`)
  then found its apps moved.
- The list is now sent exactly as given: order, repeats, and the called app.
- An app needed only by a box reference is still added for you, at the end,
  and only when the list doesn't already have it.
- A box written without an app ID always points at position 0, whether or
  not the called app is listed.
- Repeats and the called app now use reference slots, so a call that listed
  them near the network's limit can be rejected by the node. `app=0`, which
  used to be dropped, is refused.

## The signer refuses request bytes that aren't canonical

- `/sign` and `/plan` decoded a request's transaction bytes leniently: the `TX`
  prefix was optional, and trailing data, a repeated field and a wrong-length
  address were accepted. The signer then reviewed and signed its own
  re-encoding, which could differ from the bytes the client sent, so the
  client's transaction ID no longer matched.
- Sign-mode and foreign bytes must now be `TX`-prefixed and canonical, as
  every other signer endpoint already required. Anything else is a 400.
- A passthrough entry's signed bytes must be canonical too. They are returned
  as given, so they have to be exactly what was decoded and reviewed.
- apshell holds a plugin's signed slots to the same rule, so a plugin that
  signs is told before the group reaches the signer. The Algorand SDKs'
  encoders already produce canonical bytes; a hand-rolled encoder that writes
  an explicit empty field or unsorted keys is now refused.
- Every signer endpoint answers undecodable transaction bytes with the same
  fixed text. The codec's own wording, which quotes bytes from the request,
  goes only to the signer's console, escaped.
- apshell and the SDKs have always sent this form.

## Reviews show more of what a transaction does

- **ABI method label.** The signer never held the app's contract, so the method
  name on an app call was always the client's claim, tied to the call by a
  4-byte selector. The review now says so, `Method (the client's label, not
  verified)`, and shows the selector. The label is shown only when the first
  argument is exactly those four bytes; when a label is offered that doesn't
  match, the review says so without showing it. The heading no longer adds
  `[ABI]` on the client's word.
- **Access list.** An app call that names its resources in the newer access
  list (`al`) showed no accounts, apps, assets or boxes at all. Every entry is
  now listed, and `RejectVersion` is shown when set.
- **Plugin group review** (apshell). The review of a plugin-built group showed
  a payment's amount and receiver and little else. It now shows what each
  transaction type does, lists every account, app, asset, box and access
  entry an app call names, and marks every rekey, close, clawback, app update
  or delete, and asset reconfigure or destroy, whatever the type. A plugin-signed slot is not
  reviewed at the signer, so this can be the only review it gets.

## apshell reads transaction input as it is written

Five places where apshell built a transaction from input read differently from
how it was typed:

- **ABI numbers.** An `app call` argument for a `uintN`, `byte` or `ufixedNxM`
  type must be plain decimal, and a `bool` exactly `true` or `false`. Before,
  `0100` was read as octal 64, `0x10` and `1_000` were accepted, and `null`
  became zero or false.
- **JS `appCall()` arguments** are converted by their ABI type. Before, a
  `Uint8Array` or number array for a `byte[]` argument was sent as the text
  `[1 2 3]`, and `null` as the text `<nil>`. `null` and `undefined` are now
  refused.
- **Byte values** (`arg-raw=`, LogicSig `arg:`, box names, and the same
  strings in the JS API) accept `int:`,
  `str:` and `addr:`, and refuse a bare value that contains a colon. Before,
  `int:5` was sent as five text bytes. Literal text with a colon is written
  `text:key:value`.
- **Transaction files** (`sign <file>`, JS `sign()`). Several msgpack
  transactions written one after another are all read; before, only the first
  was signed. Leftover bytes, a non-canonical msgpack transaction, a JSON key
  named twice, a `null`, an empty transaction, and any key beside `txn` in a
  `{"txn": [...]}` file are refused.
- **`keyreg online`** requires `keydilution`, `votefirst` and `votelast`.
  The old defaults (10000, and rounds 0 to 3000000) need not match the
  participation key, and a mismatched registration goes through but can't
  vote. Pasting `goal account partkeyinfo` output still supplies it. The JS
  `keyreg()` requires the same options.

## The review of a mixed cosigned group no longer calls the signer's own accounts foreign

- A mixed cosigned group is signed in several requests, and each shows the whole
  group. A position signed in another request used to be headed `[FOREIGN - not
  signing]`, even when its account was this signer's. It is now headed `[THIS SIGNER
  HOLDS THIS ACCOUNT'S KEY - not signed in this request]`.
- A listed rekey on such a position used to warn "YOU WILL LOSE CONTROL OF THIS
  ACCOUNT". The warning now names it as a handover to an address on the account's
  rekey-to list, as the request that signs it does.
- The group line counts the positions whose key the signer holds apart from the
  foreign ones.
- The signer recognises a position from its own records, by the sender, not from
  the client. What a request signs, and what its policy judges, is unchanged, and a
  rekey still forces review.
- Where a `/sign/component` request names one of the signer's keys as the authorizer
  of another sender, the review says the request named it and that it isn't checked
  against the chain. It keeps the unlisted-rekey warning.
- Not covered: on `/sign`, a position whose sender was rekeyed to an account this
  signer holds still shows as foreign.

## Generation: a held cosigner key is allowed, a rotating rekey target is refused

- Lifted: an account's cosigner public key may now be a key this signer holds as an
  account's key. Generation used to refuse it with "bounded cosigner public key
  collides with signer-managed key".
- It is safe because the two roles sign different messages: a cosigner signs the hash
  of a message that begins `APLANE_COSIGNER_V1`, an account key signs a transaction ID,
  the transaction itself or an assembly receipt, and no account key signs bytes a caller
  chooses. See [ARCH_COSIGNED.md](ARCH_COSIGNED.md#role-separation).
- The product itself never produces this case. A cosigner key is generated on a
  cosigner node from a random seed and can't be imported from a mnemonic, and a node is
  a signer or a cosigner, not both. The warning fires only when key material was copied
  by hand.
- What it costs is independence, so generation warns: "The cosigner is a key this
  signer holds. It is the key of `<address>`, so the cosigner isn't independent of this
  signer: whoever controls this signer's keys can give both signatures." The warning is
  in the apadmin review, in `prepare_generate_result.warnings`, and in the
  `/admin/generate` response's `warnings`, which apshell prints.
- Kept: an account's own spending key can't be its cosigner.
- New refusal: generation refuses a rekey-to list that names a rotating account this
  signer holds, with `rekey_to: cannot rekey to <address>: it is a rotating account,
  ...`. The signer never signs that rekey, so the entry was a way out that didn't
  exist. It catches only accounts this signer holds, only the rotating account's own
  address (not its later stage addresses), and it runs only at generation: an account
  already stored with such a list still loads. This reverses, for this one case, the
  earlier entry that a rekey-to list may name any address.
- apadmin's review keeps to one warning line. One warning shows its first sentence.
  Several show "Warning: N things to read before generating. See details.", and the
  details list each in full.
- New: `generate_result` carries `warnings`, and apadmin's generated-account screen
  names each by its first sentence, or counts them when there are more than two. `w`
  there shows them in full. Generation reads the signer's keys again, so a warning can
  be there that the review didn't have.
- New: the JavaScript `generateKey()` returns the signer's `warnings`, an array that is
  empty when there are none.

## The signer refuses a few transactions the network never accepts

- New: before policy or approval, the signer refuses a transaction whose `LastValid`
  is before its `FirstValid`, whose validity window is longer than the network's
  maximum transaction life, or whose note is longer than the network's absolute
  maximum. It answers `400` and names the transaction.
- Why: a caller that supplies transaction bytes bypasses an SDK constructor's checks,
  and the mistake used to surface only at submission, after an approval and a
  signature. This was a wasted approval, not a safety problem: the network refuses
  these transactions regardless.
- The limits come from the pinned consensus parameters (`MaxTxnLife` and
  `MaxAbsoluteTxnNoteBytes`). A note above `MaxTxnNoteBytes`, where the surcharge
  starts, and within the absolute maximum is valid and pays that surcharge, as before.
- A cosigner node makes the same check before it gives a witness signature.
- It is not full validation. Other malformed transactions are still refused only by
  the network.

## Templates can't declare LogicSig arguments the network refuses

- New: installing a template is refused when it declares more than 255 LogicSig
  arguments or a single argument over 4,096 bytes (`byte_length` or `max_size` on a
  runtime argument).
  Algorand refuses such a LogicSig whatever its group looks like, so a key made from
  that template could never have signed a transaction.
- A composed template's count includes its base's signature arguments. A bounded
  template's whole layout counts: signatures, proofs, runtime arguments and the
  cosigner's signature. Both are refused when the template is installed.
- A runtime argument value over 4,096 bytes is refused at signing too, which covers an
  argument that declares no size.
- When each check runs: at install for a template, at key generation for a bounded
  account's argument layout, and at signing for a supplied argument value.
- Nothing is re-checked at load. A template already installed, or a key already
  stored, that is past a limit still loads, so a reload never fails over these limits.
  No key can be generated from such a bounded template, and signing still refuses an
  argument value over 4,096 bytes.
- A bounded template is now checked against its template-level contract at install.
  Two mistakes that used to surface only at key generation are refused at install too:
  a parameter with the reserved `bounded_` prefix, and a `rekey_to` parameter that
  doesn't match the framework's own. A template already installed with either mistake
  still loads, and key generation refuses it as before.
- No bundled template or built-in key type is affected. The largest argument any of
  them carries is 2,928 bytes, and none carries more than five.

## A bounded account's fee limit is configurable

- Removed: the fixed cap of 10,000 microAlgos on a bounded account's `max_fee`, in
  templates (`bounded.max_fee`) and in stored metadata validation. `max_fee` is still
  required on `bounded2`, and any value from 0 to 2^53 - 1 is valid (the largest every
  client reads exactly as a JSON number). A `plain1` account still
  has no fee ceiling.
- New: the plain hosts take an optional bounds parameter `max_fee`, and a boundary file
  an optional field `max_fee` (a whole number of microAlgos, written as a number or a
  string; it needs `spend`). Absent means 10,000, and `max_fee: 10000` resolves to the
  same contract, shape fingerprint and boundary digest as leaving it out.
- Another ceiling is the same shape compiled with that value: the same shape
  descriptor, its own shape fingerprint and boundary digest. The grammar fingerprint
  is unchanged and still covers the 147 shapes at the default ceiling.
- The presets (Allowlist, Locked Allowlist, Corridor) fill in 10,000, and a sample
  boundary file written from a preset says `max_fee: 10000`. apadmin's Custom bounds
  form has a Fee Limit field, and apshell's boundary preview prints the fee limit.
- A ceiling below what a path costs is no longer refused at generation ("path needs a
  fee of N, above the account's ceiling"). The apadmin review warns instead, through
  the new `prepare_generate_result.warnings`, so a sponsored-only account such as
  `max_fee: 0` can be created. The `/admin/generate` response carries the same
  `warnings`, which apshell prints. The warning is a lower bound, computed before the
  program exists. A path that doesn't fit one transaction's resource limits is still
  refused.
- Unchanged at signing: the planner never raises a bounded slot above its `max_fee`,
  and planning fails if no other signer-controlled transaction in the group can take
  the charge. Why: the cap was a protective default, not a real budget. The presets
  are the safe defaults, and other choices are advised on, not refused.

## Bounded accounts no longer have a timelock

- Removed: the bounded Layer-3 policies `timelock`, `fixed_allowlist_timelock` and
  `merkle_allowlist_timelock`, the `unlock_round` bounds parameter and boundary-file
  field of the plain hosts, and the Timelock preset in apadmin. The presets are now
  Allowlist, Locked Allowlist and Corridor, and each plain host offers 147 bounded
  shapes.
- Why: the timelock only delayed spends. A rekey never reached it, so under most rekey
  settings the account could leave the lock early.
- For a time condition, write the check in author TEAL in a custom template (for
  example `txn FirstValid` compared with a round). The review reports it as a custom
  policy, not as a timelock.
- A vault, if one is added, will be its own key type.
- It was removed before any release, so there is nothing to migrate.

## A cosigner policy can be as open as you make it

- A cosigner document's `transaction_types` may allow any type, `"*"` included. It
  used to accept `allow` only for `pay` and `axfer`. Routes still govern those two;
  any other allowed type is signed on its type verdict alone.
- `rekey_policy` accepts `"*"` as a sender or a target, and `"self"` as a target (a
  rekey back to the account's own address). `"self"` as a sender is refused, since a
  sender is always itself; use `"*"`.
- A route may set `allow_close` with a `"*"` destination, on both node roles.
- `appolicy check` and `apadmin policy apply` print an advisory for each of these wide
  choices, saying what it means. Nothing coherent is refused.
- No policy allows a `keyreg` with nonparticipation; the node refuses it before policy.

## Cosigned groups charge the right account

- In a group with a cosigned account, the signer's own non-cosigned positions are now
  planned as its own, not as another party's. The authorization charge follows the same
  payer order as an ordinary `/sign`: a native Falcon position takes it, ahead of any
  LogicSig account. It used to land on the cosigned account, and a bounded account with
  a tight fee ceiling could fail to plan a group that signs on the ordinary path.
- Those positions are sized from the signer's records, on the path each one takes. The
  client no longer sends a worst-case size for them, which could add a dummy
  transaction the group didn't need.
- `/sign/component` contextual positions take `auth_address` and `lsig_args` for a
  position the signer holds. All three SDKs send them.
- apshell refuses a cosigned group that has a position the signer doesn't hold, before
  planning. Such a group could never finish: it used to fail at the follow-up `/sign`,
  after the operator had approved it.

## A nonparticipating keyreg is refused

- apsigner refuses a `keyreg` with nonparticipation at any position it signs, with 403,
  before any policy runs: on the signer role (`/sign`, bounded components, rotating
  sign) and on a cosigner (`/sign/component`). Going nonparticipating marks the account
  as unable to participate, permanently, so no policy can allow it; a `keyreg` `allow`
  covers online and offline registrations only. Passthrough and foreign positions are
  not judged.
- The SDKs no longer build one: the Go `Nonparticipation` field, the TypeScript
  `nonParticipation` option and the Python `nonpart` keyword are gone. SDK keyreg
  prep takes an explicit `online` or `offline` mode, as apshell's `keyreg` does. An
  online keyreg needs the state proof key, and it can ask for incentive eligibility,
  which adds the 2 ALGO fee unless the account is already eligible.
- A signer-invariant refusal is audited as `signer_invariant:` on both node roles. On
  the signer role, a rekey to a rotating account used to be audited as
  `policy_engine_rejected:`.
- Refusing a rekey to a rotating account now says why: its address is a one-time stage
  key, so an account rekeyed to it would be stuck on that stage and every signature
  would reuse that key. Refusing a rekey to an account that is itself rekeyed drops its
  `policy rejection:` prefix, since no policy is involved.

## An alias can't redirect an address

- An address always resolves as itself. Before, an alias named like a real address took
  precedence over it, so `addAlias('<treasury>', '<other>')` from a script or an agent
  redirected every later send, close, rekey or app call to `<treasury>`.
- apshell's `alias` command and JS `addAlias()` refuse a name that is itself an
  Algorand address, in either case.
- An address-named alias already in the client cache is ignored, with a warning naming
  the address it pointed to, when the cache loads, and the next save drops it.

## Approval prompts escape client and chain text

- An approval prompt shows an asset's name, unit and URL, a transaction's genesis ID and
  type, an ABI method label and the request's auth address with every non-printing
  character escaped (`\x1b`, `\r`, `\n`, `\u202e`). Before, a client or an asset's issuer
  could put terminal control sequences in them that cleared apapprover's screen or wrote
  over lines already shown, so the operator approved something other than what was
  signed. The signer escapes the prompt where it sends it, and apadmin and apapprover
  escape it again where they receive it. The daemon's console copy is escaped too.
- `app_call_info.method` must be printable ASCII, as every ABI method signature is.
  `/sign`, `/plan`, `/sign/component` and `/sign/rotating/sign` refuse anything else
  with 400.
- ASA set unit names, and the asset names a policy preview shows, replace format
  characters such as U+202E with `?`, as they already did control characters.

## Bounds are an overlay of the plain hosts

This release is install-fresh only.

- The general bounded key type `aplane.falcon1024-b.v1` is gone, with `lsig/boundedaccount`.
  Its bounds (transfer kinds, a recipient list, a timelock, or limits only, under the
  10,000 microAlgo fee ceiling) are now an overlay of the plain hosts
  `aplane.falcon1024.v1` and `aplane.ed25519.v1`, beside the cosigner and the rekey-to
  list. A request with any bounds parameter (`spend_effects`, `recipients`,
  `recipient_scope`, `unlock_round`, `list_encoding`) is a `bounded2` account; with
  overlay parameters only it is `plain1`; with none, the plain program. The contracts,
  the durable record, the wire and the signing paths are unchanged.
- The grammar is every combination the contracts allow: 294 `bounded2` shapes per base
  (six policies, seven overlay arrangements, seven transfer subsets) beside the seven
  `plain1` arrangements. The general type's grammar limits are lifted: a refused rekey, a
  timelock with a spending-key or plus-cosigned rekey, and a refused account that can't
  send what it holds are accounts like any other. `plus_cosigned` still needs a
  cosigner.
- Ed25519 takes every bound and overlay, `bounded2` with a cosigner included: generation
  admission, the template rules and the signer's completed workflows admit it, as phase 5
  did for `plain1`. Its spending key is classical, which the review says. Template
  validation now asks the generation support policy whether a base takes a cosigner,
  instead of naming the Falcon base.
- `aplane.falcon1024.v1` is enabled by default, as the general type was, so it is no
  longer in the KeyType Library and can't be enabled or disabled there; `apadmin keytype
  enable aplane.falcon1024.v1` reports that it is not library-visible. `aplane.ed25519.v1`
  stays opt-in. `require_contained` and `require_cosigner` restrict new plain host
  accounts.
- Both plain hosts report `boundary_schema` `aplane.boundary.v1`. One grammar fingerprint
  per base covers every arrangement and shape, and the boundary digest is
  `APLANE_HOST_BOUNDARY_V1` under schema `aplane.boundary.v1`; the plain host's own
  `aplane.plain-host.v1` name is gone.
- Boundary files apply to the plain type they are used with (`generate
  aplane.falcon1024.v1 --boundary rules.yaml`, apadmin's Load boundary file). A file may
  leave out `spend`: it then describes an overlays-only `plain1` account and can't name
  recipients, a scope, an encoding or an unlock round, and apshell's summary says it has
  no bounds. `rekey: {authority: refused}` is accepted.
- apadmin's Generate on a plain type opens the preset screen: **No bounds**, the presets,
  **Custom bounds** (every bounds field in the overlay form, without a file) and **Load
  boundary file**. It lists titles, with the selected row's description, so every row
  fits 80x24. A bounded form's rekey control offers "No, never" too, and Custom bounds
  leaves the recipient scope and list encoding unset until chosen. The review names an
  Ed25519 account's classical spending key with bounds too, and says a timelock can be
  left by any rekey path it has. The Corridor v1 profile is the Corridor preset of
  `aplane.falcon1024.v1`.
- A parameter given with an empty value is refused rather than read as absent, so an
  empty unlock round, transfer list or cosigner can't make a weaker account than the
  request named; leave a parameter out to leave it unset. The bounded shapes are built on first
  use, so a process that never selects one, such as a client, doesn't build them at
  start.
- The O4 agreement harness runs every shape of both bases and every arrangement (about
  600 programs) against its corpus. The general type's names are on `test/arch`'s
  retired list.

## Choosing overlays

This release is install-fresh only.

- apadmin's Generate form for a plain host or `aplane.falcon1024-b.v1` shows the overlay
  choices: **Require a cosigner (Falcon-1024)**, optional unless a preset needs it and
  cleared with Backspace; **Add rekey-to addresses**; and **Allow rekeys** (No, never, or
  Yes, by the spending key, with the cosigner when there is one) or, with a list,
  **Rekey-to option** (Only these addresses, or, with a cosigner, These, plus others
  with the cosigner). On the general type the preset's bounds come first as one group;
  the preset fills in the overlay choices and the operator can change them. Each type is
  offered every setting it declares, and every field fits 80x24: a list field such as
  recipients or rekey-to addresses no longer pushes a parameter form into the panel
  scroller at that size.
- apadmin's review details say which kind of protection the rekey setting is, and on a
  post-quantum account name each held classical target and ask the operator to confirm
  that the other listed targets are post-quantum. They say a listed key is an exit in a
  mesh. These are statements, not refusals.
- "Guarded" is now "cosigned" everywhere it named a cosigned account: the client package
  `internal/engine/guarded` is `internal/engine/cosigned`, `docs/ARCH_GUARDED.md` is
  `docs/ARCH_COSIGNED.md` (the MCP docs tool names it `ARCH_COSIGNED`), apshell's
  `[GUARDED]` progress lines read `[COSIGNED]`, and apadmin's "Generate Guarded Account"
  reads "Generate Cosigned Account". The SDKs rename their public API with no aliases:
  `SignPreparedGuardedGroup` and `SimulatePreparedGuardedGroup` become
  `SignPreparedCosignedGroup` and `SimulatePreparedCosignedGroup` (Python
  `sign_prepared_cosigned_group`, TypeScript `signPreparedCosignedGroup`, and their
  simulate twins), and every `Guarded*` type becomes `Cosigned*`. No wire value changes:
  the flow label stays `cosigned1`. The old name is on `test/arch`'s retired list.
- apshell's `generate` takes its own options as flags: `--boundary <file>` and
  `--result <file>` (or `--flag=file`) replace `boundary=` and `result=`. Every
  `param=value` now goes to the signer, so a template's own `boundary` or `result`
  parameter reaches it, and only `--boundary` reads the signer's key types, once. Any
  other `--` argument is refused. `--result` works for every key type.
- The generation setting `boundary_require_cosigner` is now `require_cosigner`, beside
  `require_contained`, in the product runtime config and the admin settings, since both
  govern the plain hosts too; apadmin shows them as "Require contained accounts" and
  "Require cosigned accounts". A config that sets an old name fails to load.
- apshell's boundary summary names the key type, its result names the rekey setting and
  any rekey-to list, and `generate`'s help names the plain hosts' parameters.

## Plain hosts replace the dedicated cosigned account

This release is install-fresh only.

- `aplane.falcon1024.v1` and `aplane.ed25519.v1` are now plain hosts: LogicSig
  accounts on the new `plain1` contract, which has no host rules. Every transaction
  that doesn't rekey is a spend, of any type, closes and clawback included, and there
  is no fee ceiling. A rekey still passes only as a pure rekey, on the paths the rekey
  setting gives. Both types move from internal-only to the library, opt-in: enable one
  before generating.
- A plain host takes the general type's request vocabulary: `cosigner`,
  `rekey_authority` and `rekey_to`. It has seven arrangements per base: `refused`,
  `spending_key` and `only_these`, each with or without a cosigner, and
  `plus_cosigned`, which needs one. With no parameters it is the plain program, the
  composition base every bounded account names and the program of restored plain
  keys, and it can now be created as an account too. Each arrangement has a
  fingerprint, each base a grammar fingerprint, and each request a boundary digest.
- A cosigned plain host signs through `cosigned1`, and its cosigner's policy is the
  only restriction on its spends besides the spending key. One without a cosigner signs
  through ordinary `/sign` (`bounded1`). The cosigned flow completes Ed25519 spending
  keys on `plain1`; `bounded2` stays Falcon-only. The Ed25519 plain host is classical.
- apadmin's review says a plain host has no fee limit or transfer list, that the
  cosigner's policy decides what it signs, that a refused rekey still leaves closes,
  without a cosigner that the spending key alone decides, and on Ed25519 that the
  spending key is classical. Every arrangement fits 80x24. Account labels read "Plain
  host". apshell creates one through the generic `generate`.
- The dedicated cosigned account type `aplane.falcon1024-cosigner1024.v1` is gone, with
  `lsig/falcon1024_guarded` and the `cosigner1` flow: the `user` component kind and
  role (role byte `0x01` is retired and never reused), the user component's approval
  gate, the `guarded` assembly target kind with its user signature and runtime-argument
  fields, and the client's `cosigner1` route and "cannot mix" check. `cosigner1` is now
  an unknown flow, so a leftover account fails closed, as a rekey target too. The string
  `cosigner1` stays as the cosigner overlay's contract label. A cosigned plain host
  replaces the dedicated type.
- `bounded_authorization.contract` is `bounded2` or `plain1`, and `max_fee` is optional
  in the durable record, the wire and the admin protocol: required on `bounded2`,
  absent on `plain1`. `/keys` reports `spend_effects: []` on a plain host. The client
  caches each account's contract beside its fee ceiling, and refuses an account whose
  contract is missing or unknown, or a bounded host without its ceiling, before any
  request. `txeffects.ClassifyFor` refuses an unknown contract instead of treating it
  as bounded.
- Key types gain `boundary_schema`, the boundary file grammar a per-key type's requests
  take: `aplane.boundary.v1` on the general type, absent on a plain host.
  `per_key_contract` no longer implies the boundary workflow: apadmin opens the boundary
  presets, and apshell accepts `boundary=`, only when `boundary_schema` is set.
- `docs/PLAIN_EFFECT_CLASSIFICATIONS.json` is `plain1`'s independent judgment of the
  protocol surface, compared with the plain manifest by the inventory tests. The
  classifier sends a plain host's transaction without `RekeyTo` to the spend path by a
  new rule, `open_spend`. `bounded2`'s canonical encoding and golden vectors are
  unchanged; `plain1`'s profile has no fee field. Templates can't declare `plain1`.
- Mnemonic import is native-only: the LogicSig mnemonic provider hook is gone, and every
  LogicSig type refuses import.
- Product restrictions are lifted, so users get the configuration they ask for; a
  warning layer comes later. Durable validation and the composer no longer refuse a
  refused account without `pay`, or one that opts into assets without `axfer`, and they
  accept a timelock with a spending-key rekey, so expert templates may declare either.
  A rekey-to list may name any address, including the account's own cosigner's or a
  rotating account's. The general type keeps its 147 shapes until bounds become an
  overlay; its refusals of a bare refused rekey and of a timelock with a spending-key
  rekey now read as grammar limits and point to expert templates.
- Contract fixtures: `keys_response_guarded.json` becomes `keys_response_plain_host.json`
  (a `plain1` account without `max_fee`), the mixed assembly request's guarded target
  becomes a listed rekey, and the per-key keytypes fixture carries `boundary_schema`.
  The admin protocol stays at 8.0, which is still unreleased.
- `guarded_assembly.tla` retires with its companions. A8 is now
  `A8_PassthroughTxidBound` in `bounded_cosigner.tla`, and the surviving properties move
  to its section of `FORMAL_TRACEABILITY.md`.
- The O4 harness covers all seven plain arrangements on both bases, 161 shapes over the
  same corpus. LocalNet tests cover every plain arrangement on chain, plain hosts
  through the signer, and a bounded mesh: native members rekeyed to allowlist programs
  that name each other. The Docker four-node smoke takes a cosigned plain host through
  its real cosigner node via apshell and all three SDKs (Go as a host-built static
  binary, TypeScript from a locally packed tarball, and Python), closes it out, and
  checks that its spend fails once the cosigner key is deleted.
- The SDKs follow: `max_fee` is optional and checked only on `bounded2`, key types carry
  `boundary_schema`, and the `cosigner1` flow and the explicit-group API
  (`SignGuardedGroup`, `sign_guarded_group`, `signGuardedGroup` and their simulate
  twins) are removed; the prepared cosigned helpers remain.

## Cosigned bounded accounts can be rekeyed

This release is install-fresh only.

- A bounded account with a cosigner can now take rekeys. `aplane.falcon1024-b.v1`
  offers five rekey arrangements, each with all seven spend subsets: the spending
  key; only these; the spending key with a cosigner, a cosigned rekey that needs the
  spending key and the cosigner, whose `rekey_policy` picks the targets; only these
  with a cosigner, where a listed rekey takes the spending key alone and the cosigner
  is not asked; and the new plus cosigned, which needs a cosigner: a listed target
  takes the spending key alone, and any other target the spending key and the
  cosigner. A timelock takes only `only_these`, with or without a cosigner, because a
  cosigned rekey would leave the lock early too.
- `rekey_authority=refused` is no longer offered, with or without a cosigner, so
  every account has a way out besides its transfers. The request is refused with a
  pointer to `only_these`. The general type has 147 shapes: 70 allowlists, 42
  timelocks and 35 limits-only.
- Requests take `rekey_authority=plus_cosigned` with `rekey_to`, which needs
  `cosigner`, and `rekey_authority=spending_key` with a cosigner. Boundary files take
  `rekey: {authority: plus_cosigned, to: [...]}`. `rekey.authority` accepts
  `spending_key`, `only_these` and `plus_cosigned`; `refused` is refused.
- Corridor is now a cosigner plus only these, and asks for its rekey-to list: "A
  Merkle list and a cosigner on every spend. It can be rekeyed only to an address on
  its rekey-to list, with the spending key alone." A Corridor account whose cosigner
  is gone can no longer spend, but its listed key can still take it over.
- Plus cosigned is stored as `rekey: spending_key` plus `rekey_list`, only these as
  `rekey: refused` plus `rekey_list`. A cosigner's `required_on` is `[spend]`, or
  `[spend, spending_rekey]` when the account takes a spending-key rekey, and the
  cosigner slot is required on exactly those paths and forbidden on `listed_rekey`.
  Templates can declare `bounded.rekey: plus_cosigned`, which needs a cosigner, and
  must write `required_on: [spend, spending_rekey]` beside a spending-key rekey.
  `rekey: refused`, with or without a cosigner, stays available to templates under
  the rule that it keep a transfer.
- The cosigner check is now one subroutine that the spend path and a cosigned rekey
  both call, so the cosigner key compiles once, and every cosigned program changes
  with it, templates' included. The cosigned shapes are new and the grammar
  fingerprint has changed, so a review prepared before the upgrade is refused as
  changed; prepare it again. Shapes without a cosigner keep their programs. Under
  plus cosigned a non-empty list proof commits a rekey to the listed branch, which
  never falls through to the cosigner. Golden vector 3 in `ARCH_BOUNDED_DSA.md` now
  uses the plus cosigned shape.
- `require_contained` still accepts only refused or only these accounts with
  a recipient list. A spending-key account with a cosigner, and a plus cosigned one,
  are only as strong as their two online keys.
- The cosigned flow is now `cosigned1`, replacing `bounded-cosigner1`, so a client
  that knows only the old flow refuses a cosigned key instead of asking the cosigner
  to sign a listed rekey. It carries spends, cosigned rekeys and listed rekeys. Each
  bounded-base component in the `/sign/component` response names its `path`
  (`spend`, `spending_rekey` or `listed_rekey`). The client asks the cosigner for
  every target but a listed rekey, sends no cosigner request when no target needs
  one, and budgets a cosigned position in a mixed group on its component's path.
- `cosigner_signature` is optional on a `bounded-cosigner` assembly target and still
  required on a `guarded` one. `/sign/assemble` classifies the transaction again
  against stored metadata, through the planner's function, requires the cosigner
  signature on `spend` and `spending_rekey`, and refuses one on `listed_rekey`. A
  wrong mark can stall a request, never weaken it. Plain `/sign` still refuses every
  cosigned account with `bounded_cosigner_required`.
- The cosigner node is unchanged. A cosigned rekey reaches it as any rekey does, and
  `reject_rekey`, the `rekey_policy` edge and the pure shape decide. A listed rekey
  never reaches it, so on an account with a rekey-to list `reject_rekey: true` no
  longer stops every rekey: a rekey to a listed address goes through. The signer's
  `rekeys: reject_all_rekeys` still rejects it.
- apadmin's review reads "Spending key and cosigner" for a cosigned rekey and "These
  N, spending key alone; others need the cosigner" for plus cosigned. Account labels
  say "cosigned rekey" and "rekey to listed, or cosigned". apshell's summary names the
  cosigned arrangements and says the cosigner is not asked for a listed address.
  `prepare_generate_result.bounded.rekey_list` is also set for plus cosigned. The admin
  protocol stays at 8.0, which is still unreleased.
- The SDKs follow: they route `cosigned1`, read the component `path`, skip the
  cosigner on a listed rekey, and assemble without its signature.
- `bounded_cosigner.tla` now models spends, cosigned rekeys and listed rekeys, and
  BS2 covers the listed rekey.

## Rekey-to lists and the signer's rekey setting

This release is install-fresh only.

- Signer policy documents replace the boolean `reject_foreign_rekey` with one setting,
  `rekeys`, which takes `reject_all_rekeys`, `reject_foreign_rekey` (the default, as before)
  or `allow_rekeys`. It only rejects: a rekey it lets through still meets the rekey warning,
  review rules and operator approval, and User Auto-Approve can approve it, as today.
  `allow_rekeys` turns the rejection off. The signer's own rotation rekeys are never
  rejected, so a rotating account keeps spending under `reject_all_rekeys`. A document with
  `reject_foreign_rekey` is refused; write `"rekeys": "reject_foreign_rekey"`. Cosigner
  documents are unchanged.
- Bounded accounts without a cosigner can have a rekey-to list ("only these addresses"):
  `rekey_authority=only_these` with `rekey_to`, 1 to 16 distinct nonzero addresses. The
  spending key alone can then rekey the account only to a listed address, and the program
  refuses every other rekey. The list compiles to a salted Merkle root that reveals nothing
  about its entries. The signer keeps the entries in the key file and derives the salts from
  the spending key, so a backup of the key carries everything, and `/keys` never shows the
  entries.
- A listed address can take the account over whenever the spending key chooses. List keys
  you hold apart from the spending key. For a post-quantum account, list a native
  `falcon1024` account: an Ed25519 key puts the account on a classical key after a handover.
  Generation refuses an entry that could never act on the account: one of this signer's
  rotating accounts, or the address of an imported cosigner reference.
- `refused` without a cosigner is no longer offered: use `only_these`. Corridor stays
  `refused` with a cosigner, because a cosigned account can't have a list yet. The Locked
  Allowlist and Timelock presets are now `only_these` and ask for the rekey-to addresses;
  Allowlist is unchanged. On a timelock a listed rekey is a way around the lock: no rule
  holds a rekey back until the unlock round, so the lock holds only while the holders of the
  listed keys cooperate. apadmin's review and apshell's summary say so.
- Boundary files take `rekey: {authority: only_these, to: [...]}`. `rekey.to` needs
  `only_these`, and `only_these` needs `rekey.to`. An `only_these` account with a recipient
  list counts as contained for `require_contained`.
- The general type has 81 shapes: 34 allowlists, 30 timelocks and 17 limits-only. Every
  shape fingerprint, boundary digest and bounded template fingerprint has changed, because
  every bounded profile now encodes a list marker and a `listed_rekey` rule for each argument
  slot. The spending-key and cosigned shapes keep their programs. A review prepared before
  the upgrade is refused as changed; prepare it again.
- Templates can declare `bounded.rekey: only_these`. The framework adds the `rekey_to`
  parameter and a 160-byte list-proof argument after any Merkle proof, so a runtime argument
  moves one slot later. The rule that a `refused` template must allow `pay`, and `axfer` with
  `asset_opt_in`, now applies only without a list.
- A rekey on an "only these" account takes the new `listed_rekey` path through ordinary
  `/sign`, and the signer builds the list proof. A target that isn't on the list is refused
  before anything is signed, with the new error code `bounded_rekey_target_not_listed` (HTTP
  400). Every listed rekey needs review (`bounded_rekey_requires_review`), which User
  Auto-Approve satisfies and the self no-op rule never does. Under `reject_foreign_rekey` a
  target on the signing account's own list counts as declared; `reject_all_rekeys` still
  rejects it. The approval says the transaction hands the account to an address on its
  rekey-to list and, when this signer doesn't hold that address, that the account leaves
  this signer's custody.
- `/keys` and `/keytypes` carry `bounded_authorization.rekey_list` (`contract` `rekey_list1`,
  `depth`, and in `/keys` the account's `root`). Resource profiles gain a `listed_rekey`
  cell, which clients from this release require, and argument layouts a `listed_rekey` rule.
  Account labels say "rekey to listed only".
- apadmin's `prepare_generate_result.bounded` gains `rekey_list`. The admin protocol stays at
  8.0, which is still unreleased.
- The SDKs follow: the `listed_rekey` resource path and path-mask field, the `rekey_list`
  record, path selection for a rekey on an "only these" account, and the new error code.

## Bounded accounts move to the bounded2 contract

This release is install-fresh only.

- The bounded contract is now `bounded2`. An account states one rekey setting,
  `refused` or `spending_key`, in place of bounded1's `admin_operations` with a
  `policy_gate`. `/keys`, `/keytypes` and apadmin's `prepare_generate_result` carry
  `rekey` instead of `admin_operations`, and no longer publish an `admin_rekey` path in
  resource profiles or argument layouts. Signing flow names stay `bounded1` and
  `bounded-cosigner1`.
- No account rule gates a rekey any more: the program checks the spending signature and
  the fee ceiling, then accepts or refuses a rekey before any recipient, timelock or
  cosigner rule. So a timelock now refuses rekeys, in the general type and in templates.
  The Timelock preset can never be rekeyed.
- Templates declare `rekey: refused` or `rekey: spending_key` in their `bounded` block.
  `admin_operations` and `policy_gate` are refused, and a runtime argument can only be
  required on spend. A template with `rekey: refused` must also allow `pay`, and `axfer`
  if it allows `asset_opt_in`: such an account can neither close nor be rekeyed, so it
  would otherwise trap what it holds.
- The general type has 57 shapes. Every program, fingerprint and boundary digest has
  changed.
- New limits-only accounts: a boundary file (or request) with `recipient_scope: any` makes
  an account with no recipient list and no timelock, so only its transfer kinds and fee
  ceiling apply. It must be asked for: a missing list is still an error. `any` can't be
  combined with `recipients`, `encoding` or `unlock_round`. Its stored Layer 3 policy is
  `none`, which templates can't declare, and it is never contained. There is no preset
  for it.
- The last retired templates (`aplane.falcon1024-allowlist.v1`, `.v2` and
  `aplane.falcon1024-timelock.v1`) are deleted, and so is `library/retired`.
- The signer decides a bounded transaction's path from the account's declared contract
  and names the rule it applied. Refusals name the contract, for example "bounded2
  account permanently disables rekey".
- The review rule `bounded_admin_operation_requires_review` is now
  `bounded_rekey_requires_review`.
- The SDKs follow: `rekey` replaces `admin_operations`, and the `admin_rekey` resource
  path and path-mask field are gone.
- The admin protocol is now 8.0, which folds in the unreleased 7.4 changes. A 7.x
  apadmin would read an account with no `admin_operations` as having no rekey path, so
  it is refused at authentication instead.

## The contract-admin key is gone

This release is install-fresh only.

- `aprekey` is removed, along with the `.adm` admin key and its `.adm.json` public
  reference. Nothing in APlane reads them any more; a `.adm` file in a key store is just an
  unexpected file.
- The signer no longer serves `POST /sign/bounded-admin`. The `bounded_admin_required` and
  `bounded_admin_target_rejected` error codes are gone, and so are `admin_key_id` and
  `program_binding` in `/keys` and `/keytypes`. The admin rekey target rule went with them.
- A bounded1 template can no longer declare an `admin_key` rekey or a
  `bounded_admin_public_key` parameter. Its rekey is by the spending key, or there is none.
- The retired templates `aplane.falcon1024-allowlist-lock.v1` and `aplane.corridor.v1` are
  deleted. Use the Locked Allowlist and Corridor presets of `aplane.falcon1024-b.v1`, which
  refuse rekeys. The other three retired templates are unchanged.
- apadmin's Generate form no longer has a Contract Admin Reference field, and its review
  no longer shows a contract admin. apshell's `generate` result drops `admin_key_id`.
- apshell's `rekey` and `unrekey` refuse an argument they don't take. They used to ignore
  one, so `rekey alice to bob using ...` would have become a plain spending-key rekey once
  the old `using` guard was gone.
- A witness key is a cosigner key now; it has no admin role.
- The SDKs drop their bounded-admin request and response types, the client call, and the
  two error codes.
- The admin protocol stays at 7.4. It also removes `admin_key_id` from
  `prepare_generate_result`.

## General bounded accounts no longer use an admin key

This release is install-fresh only.

- `aplane.falcon1024-b.v1` offers two rekey authorities: `spending_key`, and the new
  `refused`, which gives the account no rekey path. `admin_key` and
  `bounded_admin_public_key` are refused, and a boundary file no longer takes
  `rekey.admin_key`.
- The Locked Allowlist and Corridor presets now refuse rekeys. Their accounts can never
  be rekeyed, where the retired templates allowed an `aprekey` ceremony.
- A cosigner needs `refused`.
- An account that refuses rekeys can neither close nor be rekeyed, so it must be able to
  transfer what it holds: its transfer kinds must include `pay`, and `asset_opt_in` needs
  `axfer`. It keeps its minimum balance forever.
- The type now has 56 shapes instead of 96. Spending-key shapes compile to the same
  programs with the same fingerprints and boundary digests. A review prepared before the
  upgrade is refused as changed; prepare it again.
- `boundary_require_admin_key` is now `require_contained`, shown in apadmin as
  "Require contained accounts". A contained account refuses rekeys and has a recipient
  list, so a timelock with no list does not qualify. Fees are capped per transaction, not
  in total, so containment does not stop a stolen key from burning the balance on fees. The runtime config is read strictly,
  so a config that still sets `boundary_require_admin_key` fails to load. The admin
  protocol is now 7.4.
- Expert templates and `aprekey` are unchanged in this release.

## apadmin can list and prune the deleted archive

- `apadmin archive list` and `apadmin archive prune --confirm <deleted/path>...` now run.
  The daemon and client code existed, but apadmin's command table didn't route `archive`,
  so a store at the deleted-archive limit (4,096 entries or 256 MiB) had no supported way
  to free space. `archive list` unlocks a locked signer first; the daemon never served it
  to a read-only session.
- `apadmin generations discard --confirm <generation-id>...` now runs too. apadmin
  rejected it before connecting.

## Admin and cosigner files have separate names

This release is install-fresh only. Stores don't carry over in place, and the old
names below are no longer read.

- `aprekey generate` now writes `<WitnessKeyID>.adm` for the encrypted admin key and
  `<WitnessKeyID>.adm.json` for its public reference. `.wit` and `.wit.json` are gone,
  and `aprekey` refuses them.
- Cosigner private keys stay `.cos`. Their store sidecars are now `.cos.json`, and
  apadmin suggests `cosigner-<id>.cos.json` for exports instead of
  `.aplane-cosigner.json`.
- apadmin's Contract Admin Reference field and a boundary file's `rekey.admin_key`
  accept only `.adm.json`, so both refuse a cosigner reference by name. A name doesn't
  prove custody: check the key with `aprekey verify` and compare the ID.
- apadmin's cosigner import browser now lists `.cos.json` files by default. Press `a`
  to list everything. `cosigner import` refuses a `.adm.json` file, and `cosigner export`
  refuses to write one.
- A boundary file must be a regular file of at most 8 MiB, and its `rekey.admin_key` a
  regular file of at most 16 KiB. A symbolic link is refused for both.
- `aprekey generate --out` refuses a directory inside a signer store, where the new
  file would stop the signer at its next reload. It also prints the two paths it wrote.
- A relative `rekey.admin_key` now follows symbolic links the way the system does. A path
  with `..` through a link could previously read a different file.
- Only filenames change. Witness Key IDs, schemas, encryption, and signing authority
  are the same.
- **Keep your existing admin keys.** A `.wit` file behind a deployed bounded account is
  still that account's admin authority. Rename `<id>.wit` to `<id>.adm` and
  `<id>.wit.json` to `<id>.adm.json` in every copy, including cold storage.
- Move cosigner and signer keys with a normal backup, then restore into the new store.
  Restore writes the new sidecars.

## Clients choose bounded flows from the signer's inventory

- apadmin and apshell now pick the preset and boundary-file flows from the signer's
  `per_key_contract` field, not the key type's name. Nothing changes for current key types.
- If apadmin hasn't received the signer's key types, choosing a type to generate shows an
  error and reloads them. It no longer opens the form from its compiled list.
- `generate ... boundary=` or `result=` now reads the signer's key types first. If that fails,
  or the signer doesn't report the type, apshell stops and sends no generation request. A
  `generate` with neither option doesn't need the lookup.
- apadmin's template library now says bounded presets are under Generate.

## Bounded generation refuses workflows a base cannot complete

- New accounts are refused when their base can't complete a declared workflow. An
  `authorization: admin_key` rekey or a cosigner on a non-Falcon base is refused at generation,
  because the admin ceremony and bounded cosigner flow need a Falcon-1024 spending key. Such an
  account could previously be created with an external-admin rekey that could never complete.
- Installed templates and existing accounts are unaffected. Fingerprints don't change, the
  template stays listed, and the store keeps unlocking and committing.
- Template import is unchanged, so the refusal appears when generating an account.

## Five templates leave the default library

- `aplane.falcon1024-allowlist.v1`, `aplane.falcon1024-allowlist.v2`,
  `aplane.falcon1024-allowlist-lock.v1`, `aplane.corridor.v1`, and
  `aplane.falcon1024-timelock.v1` moved to `library/retired/`. New accounts should use the
  matching preset of `aplane.falcon1024-b.v1`.
- Existing accounts are unaffected. Fingerprints and addresses do not change, schema v2 stays
  supported, and installed templates keep working and stay listed. The store is not touched.
- The installer copies the files to `<APSIGNER_DATA>/library/retired/` so an operator can
  repair an account; a re-import matches the installed copy. It does not delete older copies
  from `library/templates/`, so an upgraded signer keeps listing them.
- apadmin's KeyType Library can now view the stored YAML of an installed template that has
  no library file.
- A later release deletes these templates and `library/retired/`; see
  [Bounded accounts move to the bounded2 contract](#bounded-accounts-move-to-the-bounded2-contract).

## Bounded templates can use framework timelock policies

- A schema-v2 template can now set `bounded.layer3.policy` to `timelock`,
  `fixed_allowlist_timelock`, or `merkle_allowlist_timelock`, with a new
  `unlock_round_parameter`. Each requires `FirstValid >= unlock_round`, and the combined
  policies then apply the matching recipient check. They reject `teal`.
- A rekey with `policy_gate: none` and every admin-key rekey skip the timelock, so they
  can move the account before the unlock round.
- Such accounts record the policy name as their `layer3_policy`. Binaries from before
  this change reject those key files.
- `aprekey` program validation now accepts Layer 3 that reads `txn FirstValid`, which also
  lets an existing custom timelock with an admin key complete a ceremony.

## Bounded accounts can have a timelock

- `aplane.falcon1024-b.v1` accepts `unlock_round`, alone or with a recipient list, and apadmin
  has a Timelock preset. A spending-key rekey waits for the round. An admin rekey does
  not, so it stays available for recovery.
- Existing bounded accounts and their fingerprints are unchanged.

## Admin protocol 7.3 adds review values for the general bounded key type

- `prepare_generate_result` adds `review_fingerprint` and `boundary_digest`. Admin
  settings add `boundary_require_admin_key` and `boundary_require_cosigner`, both writable. Key types add `per_key_contract`.
  `apadmin` now prepares every parameterized request before generating it. Key details
  add `policy_label`. `generate_key` accepts an optional
  `expected_boundary_digest`. A prepared request now sends `review_fingerprint` as
  `expected_fingerprint`; for existing key types it equals `fingerprint`.
- `aplane.falcon1024-b.v1` is new and enabled by default on every signer, on fresh installs and
  upgrades alike. It lets an operator choose an account's recipient rules at generation
  instead of importing a template for each. See
  [USER_KEYTYPES.md](USER_KEYTYPES.md#bounded-accounts).

## Admin protocol 7.2 can prepare a key generation request

- The new local-IPC `prepare_generate_key` message reports what a request would create:
  its resolved parameters, bounded contract, and external authority IDs. It creates
  nothing, and later generation repeats every check.
- `generate_key` accepts an optional `expected_fingerprint`, and rejects the request if
  the definition changed after review. apadmin does not use either yet.

## Bounded templates can add a custom rule to a framework allowlist

- A schema-v2 template can now declare `bounded.layer3` with `fixed_allowlist` or
  `merkle_allowlist` and also supply `teal`. The allowlist runs first, then the TEAL, and
  both must pass, so a custom rule no longer has to reimplement the recipient check.
- Such accounts record `fixed_allowlist_custom` or `merkle_allowlist_custom` as their
  `layer3_policy`. Binaries from before this change reject those key files.
- A framework-policy template with no `teal` now rejects `bounded.runtime_args`, since
  nothing would read them. Existing keys are not affected.

## Plain LogicSig providers are internal-only

- Plain `aplane.falcon1024.v1` and `aplane.ed25519.v1` are internal-only:
  absent from the KeyType Library and creation discovery, with standalone
  enablement, generation and mnemonic import rejected even for old enabled
  records. Use native `falcon1024` and `ed25519` for ordinary accounts.
- Their providers remain registered for composed templates and existing-key
  signing and encrypted restore. Existing accounts remain visible and eligible
  as contract-admin rekey targets; create a native account if a new target is
  needed. No account or enablement record is rewritten.
- This implements the previously announced removal of plain LogicSig mnemonic
  import. Mnemonic import, export, and recovery apply only to native accounts. See
  [mnemonic backup and recovery](ARCH_KEYTYPES.md#mnemonic-backup-and-recovery).

## apadmin lists fit the 80-column minimum

- Enrolled Clients keeps the whole fingerprint and the `connected` flag on each row. Label,
  key type, source address, and request time for the selected row now appear below the list.
- The restore preview keeps its `present`, `hint`, and `+policy` flags whole; the address and
  key type shorten instead.
- The policy preset picker wraps each summary, so the whole text and the
  `(fill in placeholders)` note stay visible.
- The Policies list uses short statuses. The selected row's full status and its document's
  size, SHA-256, and applied time appear below the list.
- KeyType Library, Cosigner References, and Choose Cosigner rows now line up in fixed columns.
- The restore preview keeps its RESTORE button on screen at 80×24, showing fewer keys at a
  time if it has to. Its size and SHA-256 are now on separate lines, and the selected and
  total counts share one.
- Status messages and the policy review prompt now wrap instead of running off the screen.
- The Policies list now scrolls with the selection, so a long list no longer hides its last
  rows, the selected row's details, or the result of an apply.

## HTLC is ALGO-only and pays out once

- `aplane.htlc.v1` no longer handles ASAs, and `allowed_optin_assets` is gone. Same-chain
  swaps use atomic groups; the HTLC is for swaps across chains.
- Claim and refund must now close the account. A repeatable partial payment would have
  let anyone burn the balance in fees once the preimage was public or the timeout had
  passed. The opt-in path allowed the same without either.
- `recipient` and `refund_address` can no longer be the zero address, and the program
  requires a nonzero close target. A zero `CloseRemainderTo` means no close-out, so a
  zero destination let either path repeat and burn the balance in fees. Generic and
  composed templates can set `nonzero: true` on an `address` parameter.
- A claim must now expire before `timeout_round`. Checking only `FirstValid` let a
  backdated claim land up to about 1,000 rounds after the timeout, so the two windows
  overlapped. A default 1,000-round claim must now start that far before the timeout.
- The fee is now capped at 10,000 microAlgos rather than fixed at 1,000, so a higher
  network minimum can't strand funds.
- The preimage can now be 1 to 64 bytes rather than exactly 32, so the typed phrase
  `apadmin` offers at creation can actually be claimed. Generic templates can set
  `max_size` on a variable-length runtime argument.

## Rekey-locked allowlist renamed and its limits removed

- `aplane.falcon1024-allowlist-alock.v1` is now
  `aplane.falcon1024-allowlist-lock.v1`, with no alias for the old name.
- It no longer takes `asset_ids`, `max_payment_amount` or `max_asset_amount`; it
  takes `recipients` and the contract-admin key. One program is valid on every network, so a listed asset ID
  could mean a different asset on each chain, and one base-unit cap meant very
  different amounts for assets with different decimals. Set per-network asset and
  amount limits in signer policy.
- Composed templates can no longer set the matching `bounded.layer3` fields.

## Rotating signatures stop at lock

- A lock during rotating signing could neither stop the signature nor wait for the
  seed to be cleared. Locking now cancels the request and waits for the seed to be
  cleared. The signer refuses to release a signature if it locked, the request was
  cancelled or the key was removed. Slow SLH-DSA signing already checked this;
  WOTS, XMSS and WOTS+C did not.
- A leaf-family spend could reuse a one-time leaf, with unused leaves left and nothing
  reported, if a delayed reset of the release memory landed after the spend passed its
  restore check. The spend now fails with an error and can be retried.
- A restore interrupted by a lock, cancellation, recovery or refused key use no
  longer lets spends through with releases missing. Unrestored accounts stay held
  for another restore attempt in the current session. Ordinary restore failures
  still open the wait and can leave leaf history missing.

## Rotating WOTS key type removed

- `aplane.rotating-triple-wots.v1` is gone. `aplane.rotating-triple-wotsc.v1` is its
  intended replacement: a smaller signature, a lower constant cost, one transaction fewer, and
  64 one-time leaves per stage instead of one. With intact history and unused
  leaves, a rebuilt transaction takes a fresh leaf; an identical retry keeps its
  recorded leaf. Exhaustion or missing history can still cause reuse, and missing
  history can also prevent a reuse warning.
- WOTS+C isn't frozen, and a change would derive different accounts from the same
  seed. XMSS and SLH-DSA are the frozen rotating key types.
- There's no migration. A store with this key type enabled, or holding one of its
  key files, goes into recovery when it loads, even if it holds no WOTS keys.
- This release is new-install only: the installer's minimum supported upgrade
  version is v0.49.0, so an earlier install, or a development build before
  v0.49.0, needs a fresh install root.

## Rotating WOTS+C key type

- New library key type `aplane.rotating-triple-wotsc.v1`: a rotating account whose
  stages require Falcon-1024, Ed25519 and a signature from a tree of 64 WOTS+C keys.
  A spend needs 3 transactions and a 628-byte hash signature, the smallest of the
  rotating types. Enable it, then generate an account as for the others.
- WOTS+C isn't a standard, and the key type isn't frozen. See
  [KEYTYPE_ROTATING_TRIPLE_HYBRID.md](KEYTYPE_ROTATING_TRIPLE_HYBRID.md#12-wotsc-variant).

## Lost signer notifications are shown

- If apadmin, apconsole's signer pane, or apapprover can't keep up with the
  signer, notifications are dropped, and an approval request can be among them.
  The TUIs now show the number lost in the status bar for the rest of the
  session, including across reconnects, and apapprover prints a warning.

## `endpoints public-key` prints the client's SSH public key

- `endpoints public-key [<alias>]` prints the OpenSSH public key line and
  fingerprint of an endpoint's SSH identity, for an operator to import. It reads
  the existing key, so it works at any time and never creates one.

## apconsole shows cache warnings

- apconsole used to discard every cache warning, including the one reporting
  that a cache may have been tampered with. They now appear in the shell pane,
  whether raised during startup or later in the session.
- Cache messages go to stderr, not stdout, so they no longer mix with `--script`
  results. The routine message on first use now appears only at `loglevel info`.

## Diagnostics have one control: `loglevel`

- `loglevel [error|warn|info|debug]` sets which diagnostics appear in `apshell`
  and in the apconsole shell pane. The default is `warn`.
- Use `loglevel info` to show plugin output. It no longer appears by default, so
  plugins don't write over command results, and `apshell --mcp` still logs it to
  stderr. The sandbox startup line appears at `info` too.
- If a plugin fails while its output is hidden, its last 20 lines are shown as
  warnings above the error, so a crash keeps its reason.
- Plugin output in apconsole used to be discarded. It now appears in the shell
  pane at `loglevel info`.
- Plugin output is reported a line at a time under a fixed `[plugin name stderr]`
  prefix, and terminal control characters in it, including in the plugin's name,
  are shown as escapes.
- `verbose` is unchanged: it controls signing detail only.
- SSH connection loss and key revocation are now warnings, on stderr in `apshell`
  and in the shell pane in apconsole, which used to discard them.
- A newly generated SSH key is announced with its fingerprint, in apconsole too.
  `endpoints public-key` prints the key itself, which replaces the copy that was
  printed once at generation.

## Builds move to a pinned Go 1.27 toolchain

- Releases are built with Go 1.27.3, pinned by the `toolchain` line in
  `go.mod`. Building from source needs Go 1.27 or later, and the macOS
  binaries now need macOS 13 or later.
- `golang.org/x/crypto` moves to v0.58.0 and `golang.org/x/text` to v0.43.0,
  and the Go update picks up standard library fixes. These clear the known
  advisories reachable from the shipped binaries, most of them in the SSH
  transport.
- Release builds now run from `v*` tags only, every workflow action is pinned
  to a commit, and signing needs approval through a protected environment.
- The Go SDK needs Go 1.26 or later from aplanesdk v0.48.1.
- Answering a client enrollment request from the popup now reports the
  outcome in the status bar with a shortened fingerprint, so it fits at 80
  columns, and a success no longer carries a `Warning:` label.

## apadmin needs an 80×24 window; apconsole's split layout is rebuilt

- apadmin lays out for a window of at least 80×24 and every screen fits at
  that size. In a smaller window it shows only a "Window too small" screen,
  which says when an approval request is waiting, and ignores every key but
  `ctrl+c`, so no key acts on a screen you cannot see.
- apconsole's split view now puts apadmin in a left column exactly 80
  columns wide inside its border, with the daemon pane under it at its
  compact height, and gives the shell the rest of the width at full height.
  Split view starts at 133×39 (82 columns wide on a cosigner node); in a
  smaller terminal apconsole shows one pane at a time, where apadmin's pane
  needs a terminal of at least 82×30.
- An apsigner apconsole did not start (an attached socket, systemd attach
  mode, or `--no-start-daemon`) gets no daemon pane, and split view then
  starts at 30 rows; the title bar still shows the daemon's status. A failed
  start keeps the pane, which says why.
- Function keys are fixed: F1 is apadmin, F2 the shell, F3 the daemon, and a
  key whose pane is absent does nothing. On cosigner nodes the daemon moves
  from F2 to F3.
- The client key import, cosigner key import and export, and backup import
  forms are compacted to fit; the cosigner export buttons now sit side by
  side.

## Only the native key types are enabled by default; new installs only

- This release is new-install only: the installer's minimum supported upgrade
  version is v0.48.0, so an earlier install needs a fresh install root and
  fresh `apclient`/`apsigner` data directories.
- Signer nodes now enable only the protocol-native key types, `ed25519` and
  `falcon1024`, by default. The LogicSig Falcon key type
  `aplane.falcon1024.v1` is library-visible like every other LogicSig key
  type, and new stores install no templates (the
  `aplane.falcon1024-allowlist.v1` template is no longer installed by
  default). Cosigner nodes keep `aplane.witness-falcon1024.v1` enabled.
- Enable any other key type from the apadmin KeyType Library or with
  `apadmin keytype enable <key_type>`; import templates with
  `apadmin template import`. Generating or importing a key type the node has
  not enabled now names that step instead of reporting an invalid key type.
- The quickstarts now generate a native `falcon1024` key.

## Signer fee charges no longer consume a client's extra fee

- The signer used to count every fee already in a group toward the charges
  its own authorization adds: native Falcon contributions, opcode-budget
  dummy base fees and priced LogicSig program bytes. An app call's extra fee
  reserved for inner transactions was therefore spent on those charges, and
  the group failed on chain once its inner transactions ran out of fee
  credit. A Mithras deposit from a native Falcon key failed this way. The
  signer now adds its charge on top of the client's fees and never spends a
  client surplus. See [Fee Ownership](FEE_HANDLING.md#fee-ownership).
- A client that already included the signer's charge in its own fees now
  pays it twice. Build transactions with ordinary suggested fees and let the
  signer add its charge.
- A group whose only signer-controlled slots are bounded keys, and whose
  surplus previously covered the charge, is refused at planning when the
  bounded `max_fee` leaves too little room for it.
- Send a single transaction's original draft to `/sign`, not the transaction
  `/plan` returned: a single transaction has no group ID, so planning the
  planned transaction again adds the charge again. Multi-transaction `/plan`
  output is unaffected, because its group ID makes `/sign` check it without
  raising it.

## Enrollment command renamed `enroll`

- apshell's `request-enrollment` command is now `enroll`, with the same flags
  (`--endpoint`, `--label`). The old name is gone; it is an unknown command.
- The SSH username a client uses to request enrollment is now `enroll`
  (it was `request-enrollment`); the session's exec command and the queued
  request's ID already used `enroll`. This is a wire change: an older
  apshell or SDK cannot enroll with an upgraded signer, and the reverse.
  Upgrade the signer, apshell and the SDKs together. Already enrolled keys
  are unaffected; they connect as before.

## Rotating SLH-DSA triple accounts and signing hardening

- New rotating key type `aplane.rotating-triple-slhdsa.v1`: Falcon-1024,
  SLH-DSA and Ed25519 per stage, with a fresh SLH-DSA key for every stage.
  The SLH-DSA leg is the SLH-DSA-SHA2-128s construction of FIPS 205 with its
  hypertree shortened to two layers of height 11 (h = 22), which is not a
  FIPS 205 parameter set: a stage key normally signs one spend, so the
  shorter tree is enough, and it cuts the signature to 4,400 bytes and a
  spend to six transactions (six minimum fees). Like the other rotating
  types it is opt-in through the key type library. Independent security
  review and production qualification are pending; see
  [SLHDSA_EVALUATION.md](SLHDSA_EVALUATION.md).
- SLH-DSA is stateless, so this type tracks no leaves: retries and restored
  copies exhaust nothing, and signing the same transaction again gives the
  same signature. Its security margin is stated for at most 2^16 distinct
  messages per stage key, which the signer does not count or enforce.
  Deriving a stage takes about 100 ms, so lookahead is capped at two stages
  and a restore rebuilds its address cache at roughly two to three stages
  per second.
- Rotating prepare builds the group with the same resource solver, fee
  allocator and group construction as `/sign` and `/plan`, replacing a
  private copy. Single spends produce the same groups as before.
- `/sign/rotating/prepare` now requires a canonically encoded transaction,
  as `/sign/rotating/sign` already did; encodings that do not re-encode to
  the same bytes, such as trailing data, are refused.
- The approval binding, which refuses to sign anything other than what was
  approved, now also covers each request's LogicSig arguments and a rotating
  spend's stages and target address, on every signing path.
- `/sign/rotating/sign` accepts optional `app_call_info`, and apshell sends
  it, so the approval prompt for a rotating application call names its ABI
  method as `/sign` does.

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
