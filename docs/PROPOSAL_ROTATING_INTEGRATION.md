# Proposal: Rotating Signing Integration

Own-account groups for rotating accounts, built on the ordinary signing
machinery: one normalized request path, shared planning, fee allocation,
approval and execution, with a rotating coordinator that keeps the release
protocol its own.

Status: implemented 2026-10-28 on branch `work/rotating-integration`; see
section 13 for where the implementation departs from this text. Written
2026-10-25 as "rotating spends grouped with the signer's own transactions",
after the group-boundary design note landed in
[KEYTYPE_ROTATING_TRIPLE_HYBRID.md](KEYTYPE_ROTATING_TRIPLE_HYBRID.md)
section 10.1. Revised 2026-10-28 through three design reviews; section 12
lists what each changed and why. Where an earlier revision and this text
disagree, this text is authoritative.

## 1. Problem

A rotating spend is today the only user transaction in its atomic group. That
rule excludes two different things:

1. Another party's transaction in the group.
2. A transaction from one of the user's own ordinary accounts, held by the
   same signer.

Section 10.1 gives a safety reason for (1): a counterparty would decide
whether a released rotation lands, and the remedy is a same-stage re-release.
That reason does not apply to (2) in the same form. Both signatures come from
this signer, so nobody can withhold one. The own-account exclusion exists
because one rule was simpler to state and build, not because it protects
anything beyond a small validation-surface property.

This proposal lifts (2) and keeps (1).

Concrete cases it opens:

- The user's hot account pays a fee or bond leg while the rotating account
  makes the main application call.
- A plugin-composed group where the padding `gas` calls come from an ordinary
  account and the rotating account supplies the one call that must come from
  it (Reti `withdraw` and `claim` after a plugin change; not `deposit`).
- Funding and acting in one atomic step: hot account pays into the vault,
  vault pays out, both or neither.

What it does not open: two transactions from the rotating account itself in
one group. That is multi-stage release (section 10.1, deferred item 2) and
is out of scope here, though section 7 below keeps room for it.

## 2. Design in one paragraph

Rotating prepare and sign accept a group in the ordinary `/sign` slot
grammar instead of a bare transaction. The group must contain exactly one
transaction from a rotating account, and every other slot must be a sign slot
whose effective signing key is a non-rotating, non-witness, non-guarded,
non-bounded key this signer holds. No passthrough slots, no foreign slots.
The signer normalizes the request into one internal representation, sets
the rotation fields on the rotating slot, solves resource dummies and fees
for the whole group with the ordinary planner's rules, and returns the
canonical group. Rotating sign rebuilds the group from the presented user
slots and compares it, evaluates policy and approval once against the group
as presented, checks the approval binding, signs the owned slots in memory
with the ordinary signing path, then runs the rotating release path under
the account lock, and returns everything or nothing. The stage program, the
stage addresses, the release gates, release memory and the audit entry for
the rotation are untouched.

The restriction to held keys removes one hazard, external signature
dependency: no one outside this signer can withhold a signature the group
needs. It does not remove execution dependencies on outside state, which a
standalone rotating application call already has. Section 6 states the
guarantee at that width.

## 3. Wire contract (`rotating1`)

Nothing has shipped, so these are v1-freeze decisions.

### 3.1 Prepare request

`RotatingPrepareRequest` gains a group form that reuses the ordinary slot
grammar:

```
account:        the rotating account
txn_bytes_hex:  (existing) one bare transaction; the single-slot form
requests:       (new) []SignRequest in group order: txn_bytes_hex, optional
                auth_address, optional lsig_args
```

Exactly one of `txn_bytes_hex` and `requests` is set. In the group form:

- Every slot is unsigned and ungrouped (no group ID). Exactly one slot's
  sender is the rotating account; that slot carries no `auth_address`, no
  `lsig_args` and no `rekey_to`. The signer sets its rotation target; a
  supplied target is refused, never replaced.
- Every other slot is a sign slot. `auth_address` names the signing key for
  a rekeyed sender exactly as on `/sign`; `lsig_args` supplies runtime
  arguments for a generic LogicSig exactly as on `/sign`.
- `auth_address` omitted on an owned slot means "the sender's own key". This
  differs from ordinary `/sign`, where `SignRequest.Mode` classifies bytes
  without `auth_address` as a foreign slot. The rotating endpoints resolve
  the omission to the sender before any ordinary classification runs
  (4.1); the meaning of an omitted `auth_address` on `/sign` is unchanged.
- `signed_txn_hex`, `lsig_resources` and a foreign-only `pq_scheme` are
  refused explicitly, naming the slot. Reusing the `SignRequest` struct
  does not exclude passthrough and foreign by construction; the rotating
  admission does.
- Every owned slot's validity window must equal the rotating slot's window
  (4.4). The signer refuses a mismatch; it never rewrites a window.

Reusing `SignRequest` is what makes rekeyed owned accounts and generic
LogicSigs expressible; bare transaction bytes could carry neither. The
single-slot form is the group form with one entry and stays supported.

### 3.2 Prepare response

`RotatingPrepareResponse` carries the canonical group and describes it:

```
account:        the rotating account
transactions:   the final unsigned group, TX-prefixed hex
rotations:      [{index, stage, target, rekey_to}], one entry per rotating
                slot; one entry today
owned_indexes:  positions of the slots the signer will sign with ordinary
                keys
mutations:      the existing MutationReport
```

The scalar `stage`, `target` and `rekey_to` fields are replaced by the
`rotations` list in both forms. A one-element list costs the single-slot
form nothing and means multi-stage changes no field shape later. This is
a freeze decision, not a compatibility break, but it is a client-visible
change with the migration consequences in section 10.

Dummy placement is canonical and the client checks it: the returned group is
the user's slots in presented order, followed by the dummies. So
`rotations[i].index` and every `owned_indexes` entry are below the user
slot count, every position at or above it is a dummy, and the client
verifies both.

### 3.3 Sign request and response

`RotatingSignRequest` carries the prepared user slots in the same
`requests` shape as prepare, each `txn_bytes_hex` being the prepared bytes
(rotation fields, fee and group ID set), with the same `auth_address` and
`lsig_args` the client sent to prepare:

```
account:   the rotating account
requests:  []SignRequest, the prepared user slots in group order
```

The dummies are not resent. The group ID in each presented slot commits to
the ordered complete group including the dummies the signer will rebuild,
under the existing hash assumptions, so omitting them loses nothing. The
slot metadata has to travel with the sign request because the signer needs
it at signing time and remembers nothing from prepare; and the group ID
binds transactions only, so `auth_address` and `lsig_args` receive the
normal eligibility, resource, policy and signing checks at sign time.

The legacy `transactions` form, the whole old group with its dummies, stays
accepted. Its adapter validates the full old group exactly as today, the
canonical dummy suffix included, and only then normalizes it to a
one-element `requests` list. Taking element zero and ignoring the rest would
weaken the old validation. Exactly one of the two forms is present; request
ID validation and cancellation apply to both.

The signer's validation sequence on the new form:

1. Decode each presented user transaction canonically, rejecting trailing or
   non-canonical data, keeping its presented bytes and group ID.
   `canonical.DecodeGroupHex` expects a complete group and cannot be called
   on the user-slot prefix, whose group IDs commit to omitted dummies; its
   per-transaction canonical decoding is extracted and reused, and
   completeness is validated after reconstruction. Ordinary full-group
   validation is not weakened to accept prefixes.
2. Admit the slots and their authorization context (4.1). Validate the
   presented rotating target against the derived next stage; a wrong target
   is refused, not replaced.
3. Rebuild the complete canonical group with the shared builder on working
   copies, clearing group IDs where the group ID computation requires it.
4. Compare every rebuilt user slot's bytes with the presented bytes, and the
   presented group ID with the group ID of the complete rebuilt group,
   dummies included. Enforce the group-size limit.
5. Approve, sign and return exactly that complete group. The client compares
   every returned transaction, dummies included, with the group it
   simulated.

A group ID comparison is not a substitute for comparing every user slot's
bytes; both are done.

`RotatingSignResponse` becomes:

```
signed:     aligned with the group, every slot filled
rotations:  [{index, stage, target, txid}], one entry per rotating slot
group_id:   the group ID
```

replacing the scalar `stage`, `target` and `txid`.

Ordinary `/sign` and `/plan` keep refusing any group containing a rotating
sender with `rotating_signing_required`. That refusal is what forces clients
onto the endpoint pair with the release gates, and it stays.

## 4. Signer changes

The rotating coordinator stays in
`internal/signerapp/signing/rotating_flow.go`. The shared steps it calls
are extracted from the ordinary workflow in `service.go`, `execution.go`,
`planner_runtime.go`, `native_pq_fee.go` and `approval.go` (4.5), so this
change touches more than the rotating file.

### 4.1 Normalization and admission

Before any ordinary classification runs, the rotating endpoints normalize
the request into one internal representation:

1. Decode the transactions and apply the endpoint's wire restrictions:
   exactly one rotating sender, no `signed_txn_hex`, `lsig_resources` or
   foreign-only `pq_scheme`, and no `auth_address` or `lsig_args` on the
   rotating slot. `rekey_to` is phase-specific, below.
2. Resolve an omitted `auth_address` on an owned slot to the slot's sender,
   so that no slot can be classified as foreign.
3. Represent the rotating slot with the rotating account as its policy and
   signing selector and an explicit rotating role.

Admission then applies to every slot. One internal workflow does not mean
prepare and sign have identical wire preconditions; `rekey_to` differs by
phase, exactly as the current flow distinguishes them:

| Slot | Prepare | Sign |
|---|---|---|
| Rotating slot | `rekey_to` must be zero; the signer derives and sets the target | `rekey_to` must be present and equal the derived next stage of the signing stage; the stage must be live under the account lock before signing; a wrong or missing target is refused, never replaced |
| Owned slot | `rekey_to` must be zero | `rekey_to` must be zero |

In one sentence: reject `rekey_to` on every owned slot; on prepare also
reject a supplied rotating target; on sign require and verify the prepared
rotating target. The normalized legacy sign form obeys the same sign-time
rule.

- The rotating slot: `validateRotatingSpend` as today, plus the phase rule
  above.
- Each owned slot, judged on its effective signing key (the resolved
  `auth_address`), not on its sender: the key must be held; its key type
  must not be rotating (`rejectRotatingKeyType`, applied to owned slots
  only, since it would refuse the designated rotating slot); it must pass
  `cosignerSignRejectMessage`, which refuses witness and guarded key types;
  and its credential metadata must carry no bounded authorization
  (`boundedmeta.Metadata`), checked explicitly because ordinary sign plans
  bounded accounts rather than refusing them and that planning cannot nest
  inside this flow. Same genesis hash as the rotating slot. Window equal to
  the rotating slot's. A sender that is not held is fine when its
  `auth_address` is.
- `rejectRekeyToRotating` applies to every slot.

A slot that fails admission is refused with `bad_request` naming the slot.

### 4.2 Prepare (`PrepareRotatingWithContext`)

1. Normalize and admit (4.1).
2. Find the live stage and set `rekey_to` on the rotating slot, as today.
3. Replace `buildRotatingGroup`'s fixed `TransactionCount: 1` with the real
   slot count and the full list of LogicSig usages, the rotating profile's
   usage being one entry. The ordinary planner's solver (`lsigresource.Solve`)
   already computes dummies for mixed groups, so dummies become net of the
   owned slots' pooled budget and gross of their own LogicSig demands.
4. Fees. There is no fee independence between slots: an owned LogicSig slot
   adds argument bytes and opcode cost, which can raise the dummy count, and
   native Falcon authorization and LogicSig program bytes carry their own
   surcharges. What the rebuild needs is determinism. The allocation is
   exactly the ordinary planner's, `authorizationBudgets` and
   `applyGroupFees`, called as `/sign` calls them: every slot's budget, and
   every LogicSig slot, the rotating one included, as a preferred target,
   with the allocator's own priority and pooling rules deciding who pays
   the dummy deficit. No rotating exception, not even "the rotating slot
   pays the dummies", which would be one more rule with two
   implementations. The contract therefore permits cross-subsidy in both
   directions: an owned native-Falcon slot may pay part of the dummy
   deficit, and the rotating slot may cover another slot's surcharge.
   Policy evaluates the final fee on each account, and the client sees
   every change in `mutations.fees_modified` and in the simulated group.
   `TXN_FEE_SPLITTING.md` gains a sentence saying rotating groups follow
   its rules unchanged.
5. Return the canonical group with `rotations` and `owned_indexes`.

Determinism is a property of the internal canonical builder: given the
extracted user slots with finalized fees, it reproduces the same group byte
for byte, which is what the sign-time rebuild relies on. The HTTP prepare
endpoint itself refuses grouped transactions and supplied rotation targets,
so it does not literally accept its own output; idempotence is tested on
the builder, not the endpoint.

### 4.3 Sign (`SignRotatingWithContext`)

The five rules in the file header change as follows.

- Rules 1 to 4 (stage proven, target is next stage, timing, target can sign
  later) are unchanged. They are about the rotating slot and the account.
- Rule 5 (group exact) becomes the validation sequence of 3.3: rebuilding
  the complete group from the presented user slots reproduces their bytes
  and their group ID. This is the same check as today with more inputs. It
  proves the group is one the signer would build from these slots; it does
  not and cannot prove the slots are the ones prepare saw, because sign
  remembers nothing from prepare. A client may change an owned slot's
  content between prepare and sign exactly as it may change the rotating
  spend today, and policy and approval evaluate what is presented.
  Preserving the client's intent is the client's job (section 5), as
  `ARCH_SIGNING.md` already states for the rotating slot.

Then, in this order, under one execution lease:

1. Policy and approval once, through `approveGroupWithPlanContext`, with
   the owned slots as ordinary sign slots carrying their per-key policy and
   the rotating slot carrying its `rotatingPlanItem`. The approval
   description names the rotation at its actual index
   (`BuildApprovalDescription` currently attaches it to slot zero and must
   use `rotations[0].index`) and lists the owned slots as ordinary sign
   does. A policy rejection on any owned slot ends the request here, with
   no rotating signature made.
2. The approval binding check (`checkApprovalBinding`) for the whole group,
   before any key is used. Today it runs immediately before rotating
   signing; with an earlier ordinary-signing phase it must run before that
   phase, and the late check before rotating signing stays as well.
3. Owned signatures, in memory, through the ordinary signing path's
   per-slot execution. A key that fails to load or sign ends the request
   here. The ordinary executor's failure audit entry for that slot is kept
   as a diagnostic; what the design guarantees is that no rotating
   signature has been generated and no release accounting has happened.
4. The rotating path under the account lock, unchanged: fresh chain read,
   rules 1 and 3, the open test, the stage signature, local verification,
   the post-sign chain recheck for stateless families.
5. Release accounting for the rotation (audit entry, release memory), then
   the ordinary audit entries for the owned slots, then the response.

What these guarantees are and are not:

- A failure or cancellation in steps 1 to 3 leaves no rotating signature
  generated and no release accounting; the owned signatures existed only in
  memory and are discarded. A retry is a fresh request with nothing to
  reconcile; for leaf families no leaf was consumed.
- A failure inside step 4 can occur after the rotating signature has been
  generated, for example at the post-sign chain recheck. Generation,
  release accounting and delivery are three different events. Today's
  flow already distinguishes them: a signature generated and then refused
  is wiped and never recorded. That holds unchanged.
- Once step 5 has started, a transport failure can still prevent the
  client from receiving the response. The release history is kept
  conservatively in that case, as today; the ordering change prevents an
  owned-key failure from landing after release accounting, it does not
  guarantee delivery.

The lock region is the same as today's.

### 4.4 Validity windows

The rotating slot's window is capped at 100 rounds and must satisfy the
timing rule at sign time. A group confirms or fails as a whole, so an owned
slot with a different window gains nothing. The rule is therefore: every
owned slot's window equals the rotating slot's, checked at admission and
refused otherwise. The signer never rewrites a window, so `MutationReport`
needs no window field and the client's check (section 5) stays simple. The
client's window construction and refresh (`freshenRotatingValidity`, which
today operates on one transaction) is extended to keep every user slot
aligned through initial construction and retries, followed by a fresh
simulation.

### 4.5 Shape of the implementation

One request path. The single-slot form is normalized into a one-element
`requests` list at the API boundary, with its full-group validation done
first (3.3), and takes the same admission, planning, approval, signing and
response construction as the group form; a test proves both forms yield
identical canonical bytes. A separate single-slot workflow would keep the
duplication this change exists to remove.

Shared internals, distinct release protocol. The ordinary workflow in
`service.go` combines approval, execution and audit behind
`SignGroupWithContext`, and its executor rejects rotating key types. The
refactor exposes the steps beneath that entrypoint, slot admission,
resource solving, fees, canonical group construction, approval binding and
ordinary-slot execution, so the rotating coordinator can call them on a
plan that contains one rotating slot. Rotation keeps what is its own: stage
derivation, the next-stage rekey, the account lock, the fresh chain checks,
timing, the open test, leaf selection and release accounting. Ordinary
`/sign` stays unable to reach a rotating key, and rotation does not become
a key-provider callback inside the ordinary executor. The endpoint pair
stays because the release gates live there; what must not exist is a rule
with two implementations.

## 5. Client changes

- `internal/engine/rotating.go`: `rotatingSender` stops refusing groups.
  It reports a rotating group when exactly one sender is rotating and
  refuses more than one with a message pointing at multi-stage being
  unsupported. Eligibility of the other slots is judged on the effective
  signing authority, resolved through the ordinary client authorization
  path, not on the sender: account A rekeyed to held key B needs no local
  credential for A. The rotating account itself is still identified by
  sender.
- `internal/engine/transaction.go`: route the whole group to
  `SignAndSubmitRotating` instead of `txns[0]`, building the owned slots'
  `SignRequest` entries with the same `auth_address` and `lsig_args` the
  ordinary path would send.
- `internal/clientsign/rotating.go`: `SignAndSubmitRotating` takes a group.
  `ValidatePreparedRotatingGroup` reads `rotations` and `owned_indexes`
  instead of the scalar fields it reads today and checks: the user slots
  are at the leading positions in the order sent; the rotating slot differs
  from what was sent only in `rekey_to`, fee and group ID; each owned slot
  differs only in fee and group ID; the remaining positions are canonical
  dummies; and every fee change is listed in `mutations.fees_modified`. The
  client then simulates the exact group before sign, which now covers the
  owned slots, and sends the prepared user slots back as `requests` with
  their `auth_address` and `lsig_args` (3.3). This validation is where
  intent preservation lives, since the signer's rebuild cannot provide it
  (4.3). `validateSignedRotatingGroup` compares every returned transaction,
  dummies included, with the group it simulated.
- apshell: the "must be sent alone" error disappears. Plugin intents whose
  group has one rotating sender and otherwise held authorities route
  through the rotating path without the plugin knowing.
- SDK: the Go, TypeScript and Python SDKs mirror the client checks and the
  `rotations` list. Contract fixtures gain a group-form prepare request and
  both responses.

## 6. Safety analysis

What is preserved:

- Every rotating signature is released only while the stage is live, under
  the lock, after the open test, into a group the client has already
  simulated. Unchanged.
- No signature the group needs can be withheld by anyone outside this
  signer. The counterparty race of section 10.1, in which another party
  decides whether a released rotation lands by choosing whether to sign,
  does not arise.
- Operator approval sees the whole group once, with per-key policy on every
  owned slot, which is the existing mixed-group behaviour.
- No signature leaves the process unless every slot signed.

What changes, stated at its real width:

- The signer accepts bytes it did not derive (the owned slots). The
  widening is the same one ordinary `/sign` already accepts for every group
  it signs, so it adds no new class of input to the signer, only to this
  endpoint pair.
- Owned slots are not immutable between prepare and sign. The rebuild
  check accepts any owned-slot content the signer would plan the same way;
  policy and approval evaluate the presented content; the client's
  validation preserves intent. This is today's contract for the rotating
  slot, extended.
- Execution can still depend on outside parties. An owned application call
  can fail on state someone else changed; an owned asset transfer can fail
  on a freeze. Simulation before sign catches what is visible at that
  moment. A failure between simulate and commit leaves the stage live with
  its signature public, the same outcome as a window expiry today, with the
  same alert and the same same-stage re-release remedy. The difference from
  the excluded case is that no outside party holds a signature the group
  needs; it is not that no outside party can affect the outcome. A
  standalone rotating application call carries the same execution
  exposure today.
- Fees are a deterministic function of the whole group under the ordinary
  allocator, with cross-subsidy in both directions (4.2). An owned slot can
  pay part of the rotating slot's dummy deficit and the rotating slot can
  cover an owned slot's surcharge. Policy evaluates each account's final
  fee, and the client sees every change in `fees_modified` and in the
  simulated group before anything is approved. The user-facing mixed-group
  doc says this in a sentence.

Exclusions worth a test each: an owned slot that rekeys its sender to the
rotating account (`rejectRekeyToRotating`); an owned slot whose effective
signing key is a witness or guarded type (`cosignerSignRejectMessage`); an
owned slot whose credential carries bounded-authorization metadata, which
ordinary sign would plan rather than refuse; an owned slot sent from a
stage address, which the held-key rule refuses since stage addresses are
never held keys.

## 7. Room for multi-stage later

Multi-stage release is not designed here, but the grammar should not
foreclose it:

- The rule "exactly one rotating slot" is the only admission rule to
  relax. Keep it as a single check with a single error.
- `rotations` is a list in both responses from the start, and nothing else
  in the wire shape is scalar per rotation.
- Nothing in the compare step or the approval rendering assumes the
  rotating slot is at position 0. It is wherever the client put it among
  the user slots.

The hard parts of multi-stage (stage chaining, budget per spend, release
memory for several stages, audit) are additive to this shape.

## 8. Tests

Unit, signer (`rotating_flow_test.go` and the shared-step tests):

- Group-form prepare with one and several owned slots; dummy count net of
  members for every rotating scheme.
- Fee allocation parity with the shared allocator: native-Falcon priority,
  existing pooled overpayment, several LogicSig targets, an owned LogicSig
  slot raising the dummy count. Which slot pays the deficit is whatever the
  ordinary allocator decides; a fixture arranged so the rotating slot pays
  is valid, but "the rotating slot's fee rises" is not a universal
  invariant and is not asserted as one.
- Normalization: omitted `auth_address` resolved to the sender; both
  request forms present, neither present; `signed_txn_hex`,
  `lsig_resources` and foreign-only `pq_scheme` refused; a supplied
  rotating target refused rather than replaced.
- Admission: refusal of a second rotating sender, an unheld effective key,
  a witness or guarded key, a bounded credential, a window mismatch;
  `rejectRotatingKeyType` on owned slots only.
- Rekey rules by phase: prepare rejects a caller-supplied rotating target;
  sign accepts the valid prepared target; sign rejects a missing or wrong
  target, and a stage that moved follows the existing stage-change
  refusal; both endpoints reject `rekey_to` on owned slots; the normalized
  legacy sign form obeys the sign-time rule.
- Rebuild: determinism of the internal builder on extracted user slots with
  finalized fees; the user-only sign request with changed, missing,
  reordered or extra slots, inconsistent group IDs, and non-canonical
  encodings; the legacy form with a modified or extra dummy refused; both
  forms yielding identical canonical bytes.
- A changed owned slot passing the rebuild and receiving fresh policy
  evaluation; a policy rejection on an owned slot producing no rotating
  signature; a mutation of authorization or transaction after approval
  refused by the binding check before any key is used.
- A rotating slot at a nonzero index, including the approval description.
- An owned key that fails to load leaving no rotating signature, no release
  record and, for leaf families, no consumed leaf; cancellation between
  owned signing and the rotating path releasing nothing.

Unit, client: `ValidatePreparedRotatingGroup` on the group form, including
a signer response that reorders a slot, alters an owned slot beyond fee and
group ID, or omits a fee change from `fees_modified`; routing where the
owned sender is not held and its `auth_address` is; window alignment held
through construction and refresh.

Integration (`rotating_txntypes_test.go` or a sibling), every scheme:

- Hot account payment plus rotating app call in one group through apshell;
  authorizer moves to a fresh stage and the hot account's balance moved.
- A rekeyed owned account whose sender has no local credential, signing
  through `auth_address`; a generic LogicSig owned slot with required
  runtime arguments.
- An owned slot that fails simulation leaving the authorizer unchanged.
- Mandatory, failure after release: prepare and simulate a valid group;
  sign it and hold the complete signed group; change chain state so an
  owned slot now fails, for instance flip a test application's acceptance
  flag, and wait for that change to confirm; submit the held group and
  verify rejection; verify the rotating authorizer is unchanged, the
  rejected group applied no effects and the signer retains its release
  record; verify the expired-release warning after the window and the
  same-stage rotate-only recovery. Controlled sequencing, not a timing
  race. This is a different guarantee from the owned-key failure before
  rotating signing, which must show no release at all; both are acceptance
  criteria.

Contract fixtures: group-form prepare request, both responses with the
`rotations` list, every scheme.

## 9. Docs

- `docs/KEYTYPE_ROTATING_TRIPLE_HYBRID.md` section 10: group shape row
  becomes "one rotating spend, any number of this signer's non-rotating,
  non-bounded transactions, plus dummies". Section 10.1: the own-account
  exclusion is lifted; the other-party exclusion and its reason stay,
  restated as "no external signature dependency"; deferred item 1 is
  rewritten to describe passthrough and foreign admission only.
- `docs/ARCH_SIGNING.md` rotating section: the group form, the `rotations`
  list, the rebuild contract stated honestly, the signing order and the
  audit guarantees of 4.3.
- `docs/TXN_FEE_SPLITTING.md`: rotating groups follow its rules unchanged.
- `docs/TXN_MIXED_GROUPS.md`: rotating accounts can join a group whose
  other members this signer signs; cross-subsidy of fees.
- `docs/USER_KEYTYPES.md`: the restrictions list and the "single-transaction
  use" paragraph are rewritten around "one transaction from the rotating
  account per group".

## 10. Estimate and sequencing

Signer normalization, admission, prepare, fees, sign ordering and the
shared-step extraction, about four days. Client and apshell including the
validation rules and window alignment, two days. SDK mirrors and fixtures
for the `rotations` change, one to two days. Tests and docs, two to three
days. About two and a half weeks for one person, none of it touching the
stage program.

Sequencing has to respect the response change. Replacing the scalar
`stage`, `target` and `rekey_to` fields breaks the current client, whose
`ValidatePreparedRotatingGroup` reads them, so the signer cannot land first
with existing clients unaffected. Either land the signer, the first-party
client and the SDK decoders together, or have the signer emit both the
scalar fields and the `rotations` list for a short migration and drop the
scalars once every first-party consumer reads the list. The old request
syntax stays accepted throughout, which is a separate matter from the
response contract. The change is client-visible; it is not observable only
through tests.

## 11. Decisions taken and questions open

Taken:

- `rotations` as a list in both responses, replacing the scalar fields,
  with the migration sequencing of section 10.
- Owned slots carry `auth_address` and `lsig_args` through the ordinary
  `SignRequest` shape on both prepare and sign; an omitted `auth_address`
  means the sender's own key on these endpoints only; rekeyed owned
  accounts and generic LogicSigs are supported, passthrough and foreign are
  refused explicitly.
- Eligibility is judged on the effective signing key, on both signer and
  client.
- Dummies follow the user slots; positions are validated by the client;
  sign resends the user slots only, every user slot's bytes are compared
  and the group ID of the complete rebuilt group binds the dummies.
- Windows are checked equal, never rewritten, and kept aligned by the
  client through refresh.
- Fees follow the ordinary planner exactly, every LogicSig slot a target,
  cross-subsidy permitted; no rotating exception and no independence claim.
- One normalized request path and shared internals under a rotating
  coordinator (4.5); the failure-after-release and failure-before-release
  integration tests are acceptance criteria (8).

Still open:

- Should owned slots be allowed to reference the rotating account as a
  foreign account in an app call? Nothing in the stage design objects; it is
  an ordinary app-call resource. Default yes.
- Should a bounded credential be admitted later through its own planning,
  rather than refused? Out of scope here; the refusal is explicit so the
  question is visible.

## 12. Revision notes

First review (2026-10-28):

1. The claim that owned slots cannot change between prepare and sign is
   withdrawn (4.3, 6).
2. The safety guarantee is narrowed to "no external signature dependency"
   (2, 6).
3. Fee independence is withdrawn. The first revision's replacement, the
   rotating slot as sole dummy-fee target, was itself a rotating exception
   and is superseded by 4.2 as it now stands.
4. Bounded credentials are excluded by an explicit metadata check (4.1).
5. Signing order is reversed: owned signatures in memory first (4.3).
6. Window alignment by mutation is replaced by an equality check (4.4).
7. The wire decisions are settled (3, 11); the estimate is raised.

Second review (2026-10-28):

8. The sign request carries the slot metadata (3.3); the first revision
   would have lost `auth_address` and `lsig_args` at signing time.
9. The fee rule is the ordinary allocator with every LogicSig slot as a
   target and cross-subsidy permitted (4.2, 6); the stale "every slot pays
   its own" claim and the stale test expectation are removed.
10. One normalized request path and shared internals (4.5).
11. The failure-after-release integration test is specified and made an
    acceptance criterion (8).
12. Normalization before ordinary classification: an omitted `auth_address`
    would otherwise classify a slot as foreign under `SignRequest.Mode`;
    passthrough and foreign fields are refused explicitly;
    `rejectRotatingKeyType` applies to owned slots only, since it would
    refuse the rotating slot (3.1, 4.1).
13. Client eligibility is judged on the effective signing authority, not
    the sender; a rekeyed sender need not be held (5, 8).
14. Response migration: the scalar fields are read by the current client,
    so signer and consumers land together or the signer emits both shapes
    for a migration (10).
15. Audit, cancellation and delivery guarantees are qualified: the ordinary
    executor's failure audit entry stays; generation, release accounting
    and delivery are distinguished; the binding check runs before the
    owned-signing phase; one execution lease spans both phases (4.3).
16. The sign-time validation sequence is explicit: canonical per-slot
    decoding reused from the group decoder, every user slot's bytes
    compared, the group ID checked against the complete rebuilt group, the
    legacy form validated in full before normalization (3.3).
17. Determinism is stated as a property of the internal builder, not of
    the HTTP endpoint on its own output (4.2); the approval description
    must render the rotation at its actual index (4.3, 7); section 4's
    ownership statement names the shared files (4).

Third review (2026-10-28):

18. The `rekey_to` admission rule is split by phase. The previous text
    refused `rekey_to` on every slot in the shared admission, which would
    have refused every valid sign request, since sign receives the
    prepared rotating target. Prepare refuses a supplied target; sign
    requires and verifies it; owned slots never carry one (4.1, 8).

## 13. Implementation notes, 2026-10-28

The implementation follows this text, with these choices made where the text
left one open or the code required one:

- **Response migration.** Section 10's second option is taken: both
  responses carry the `rotations` list and the scalar `stage`, `target`,
  `rekey_to` and `txid` fields, which repeat its single entry. The SDKs live
  in a separate repository and cannot change in the same review, so the
  scalars stay until they read the list; the first-party client already
  requires the list and checks the scalars agree with it. Contract fixtures
  gain the list and four group-form fixtures.
- **Shared steps.** The group builder is `Planner.finalizeGroup`, extracted
  from `PlanGroup`, which `/sign`, `/plan` and both rotating endpoints call.
  Owned slots are signed by `Executor.SignOwnedSlots`, which shares
  `signPlannedSlot` with `ExecuteGroupSigning`. Approval and the approval
  binding were already shared. Admission is the rotating coordinator's own
  (`normalizeRotatingSlots` in `rotating_group.go`), because ordinary
  classification would read an omitted `auth_address` as a foreign slot and
  the ordinary key check refuses the rotating slot; it reuses the ordinary
  key-type rejections for owned slots.
- **Approval binding.** The approval digest now also covers every slot's
  LogicSig arguments and, for a rotating group, the rotating slot's index,
  stage, target stage and target address. The arguments are signing inputs
  an owned generic LogicSig consumes, and the rotation is what the prompt
  describes, so both are bound like the bytes. The change applies to every
  flow that uses the binding, not only rotating groups.
- **Canonical decoding.** `canonical.DecodeTXPrefixed` is the exported
  per-transaction decoder; both rotating endpoints decode every slot
  strictly, including the single-transaction prepare form, which previously
  accepted any decodable encoding.
- **Not in this repository.** The Go, TypeScript and Python SDK mirrors
  (section 5) belong to `aplane-algo/aplanesdk` and are not part of this
  change; the contract fixtures they consume are.

