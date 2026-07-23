# APLANE CORRIDORS

**Technical Whitepaper**

*Version 0.4 — Draft*

> Status: This whitepaper is design framing, not the shipped product contract.
> See [ARCH_CORRIDOR.md](ARCH_CORRIDOR.md), [ARCH_SENTRY.md](ARCH_SENTRY.md),
> [USER_KEYTYPES.md](USER_KEYTYPES.md), and
> [KEYTYPE_CAPABILITIES.md](KEYTYPE_CAPABILITIES.md) for current behavior and
> supported key types.

---

## Abstract

APlane Corridors is a constrained asset transfer architecture built on the
Algorand blockchain. It provides provably enforced, auditable, and
non-bypassable financial flow controls without requiring the use of stateful 
smart contracts or smart-contract app state.

At the heart of a corridor account is a Logic Signature - a small, 
fixed program that the ledger itself evaluates on every transaction, enforcing 
Falcon-authorized transfers through two mechanisms.

First, the program defines the account's **corridor**. A corridor is a
permitted transfer path from the account to one or more fixed destinations, compiled
into the account's Logic Signature. Each account has exactly one corridor —
one origin, one or more exits. LogicSigs are small fixed TEAL programs that the Algorand
Virtual Machine uses for authorization. 

Except for protocol fees and issuer-controlled clawback behavior on
clawback-enabled assets, an account's corridor destinations are the only routes
account-controlled value may travel. Transfers outside them are impossible, even
if the account's Falcon key is stolen.

Second, an account's corridor may be gated by a separate sentry. A sentry is 
a second signer that maintains its own policy and key material. For those
transfers, the program requires both the account holder's authorization and
a per-transaction sentry approval issued under deterministic policy. The holder 
initiates transfer; the sentry permits or denies. 

APlane makes sentry signing invisible to the end user in its transaction handling, but there 
is nothing proprietary about the technique and only standard Algorand primitives
are used. 

Policy is divided into two layers with different volatility profiles:

- **Structural policy — where corridors exist.** Compiled into the account's 
  LogicSig: the holder's Falcon key, the corridor destination definitions, 
  the embedded sentry key, and the governance rekey path. Corridors change 
  only by construction — a Falcon-authorized governance rekey under dedicated 
  governance keys, separate from both spending and sentry authorities — with the 
  account address stable across all versions.
- **Operational policy — when gates open.** Gate policy rules held on separate
  sentry nodes, evaluated fail-closed per transaction and enforced on-chain
  through a required sentry signature. Gate rules change by an authenticated policy
  edit, with no on-chain transaction.

Optionally, a "sentry" signer may also be used to provide a second signature for
additional transaction approval. This approval process runs off-chain, so while
it can be based on transaction / group details, it can also be based on off-chain
state as well - eg., anything a process can look up via HTTP. 

Like the destination address of a corridor, the use of a specific pre-determined sentry key
is cryptographically enforced, similar to the concept of multisig.


The network graph — the corridor map — is the emergent union of per-account
corridors. There is no central router, registry, or privileged
network-level component. Value moves only along cryptographically enforced
paths. Every structural signer change is publicly visible on-chain, and the
corresponding corridor program is verifiable from the operator-published
configuration and template version.

This document describes the account primitive, the authorization model, the
corridor and gate layers, topology governance, the security model, and the
v1 scope. It is grounded in the APlane signing infrastructure, whose
guarded-signing subsystem provides the production implementation of the
gate layer. A glossary mapping the corridor vocabulary onto production
terminology appears in the appendix.

## 1. Design Principles

1. **All account-controlled spend authority is Falcon-authorized.** Except for
   protocol fees and issuer-controlled clawback behavior on clawback-enabled
   assets, every transaction moving value from an account carries a
   Falcon-1024 signature, bound to the transaction ID, from the account's spend
   key. There is no anonymous satisfaction of a predicate: knowing an account's
   program confers no spending ability.
2. **All on-chain enforcement is stateless.** Corridors and gates are
   enforced exclusively by account programs evaluating transaction facts,
   group context, and supplied signatures. No smart-contract app state.
   Operational gate-rule documents live off-chain at the guard, never on the
   ledger.
3. **Corridors change only by construction; the address never changes.** An
   account's corridor changes only through its compiled governance rekey
   path, authorized by a separate administrative Falcon key. The account
   address is stable across all versions; the on-chain rekey history records
   effective signer changes, while the complete construction record pairs that
   history with the operator-published program configuration and template
   version.
4. **Gates are attested, not state-resident.** Operational rules — movement
   authorization, per-sender constraints, compliance gating — are evaluated
   off-chain by the guard under deterministic, fail-closed gate rules, and
   enforced on-chain by requiring the guard's signature alongside the
   holder's. Gates are shut by default.

Design discipline: *if a proposed feature pushes corridor or gate
enforcement from the account's program to any shared or central component, it
should be deferred. The defining property of this system is local
enforcement at the account level.*

## 2. The Account Primitive

### 2.1 Definition

An **account**, as the term is used throughout this document, is an
Algorand account whose effective signer is a corridor
program: a small, stateless program that the ledger evaluates on every
transaction, composing three predicates — Falcon holder authorization, the
corridor, and (for guarded accounts) the gate requirement — plus a
governance rekey branch for corridor construction. Each account has exactly
one corridor: one origin (the account itself) and one or more destinations.
Where this document uses the plural "corridors," it means corridors across
accounts.

Two formation patterns produce such an account, with identical enforcement
semantics:

- **Contract account.** The account address is derived from the
  program itself, so the address commits to the exact program; the account's
  corridor is permanent unless the program contains a governance branch.
- **Rekeyed account (governed).** A standard account is rekeyed so that the
  corridor program becomes its effective signer. The address is independent
  of the program, so corridor construction replaces the program under a
  stable address. This is the recommended formation for any account whose
  corridor is expected to evolve, and it uses APlane's existing
  guarded-authorizer support.

### 2.2 Keys and guard variants

Every account's spend key is Falcon-1024. The guard key is either Ed25519 or
Falcon-1024; the latter makes the account fully post-quantum. The guard is
chosen at generation time: its public key is embedded in the account's program
and recorded alongside the holder's key material. Endpoint routing
thereafter is mechanical and confers no authority. The ungated profile —
a corridor and Falcon authorization only, with no gate predicate — is
APlane's existing post-quantum allowlist account family.

### 2.3 Configuration

Everything an account enforces is compiled into its program at generation (or
at a subsequent construction):

- the holder's Falcon public key — WHO initiates;
- the corridor: the list of permitted destination addresses — WHERE
  value may go;
- close semantics: account close-out fields must be zero or name a corridor
  destination;
- the guard's public key, if any — the gate requirement; absent means an
  ungated corridor;
- the governance public key, if any — construction authority; absent means
  the corridor is permanent;
- optional structural bounds: a per-transaction amount cap, a hard validity
  window, and a fee cap;
- an optional escape hatch: a recovery corridor, with or without an
  activation round (§7.3).

### 2.4 Account profiles

The configuration composes into the standard account profiles:

| Profile | Configuration |
|---|---|
| Immutable leaf | literal corridor, ungated, no governance key |
| Governed account | corridor + governance key |
| Guarded governed account | corridor + gate + governance key |

## 3. Authorization Model

### 3.1 Holder authorization (the holder initiates)

Every spend from an account requires a Falcon-1024 signature from the holder's
spend key over a message bound to the transaction's canonical ID. Binding
to the transaction ID makes the signature valid for exactly one transaction
in exactly one atomic group (the ID commits to the group), eliminating
replay and group-substitution by construction.

Keyless contract accounts are explicitly rejected as a design basis: an
account program with no signature predicate can be spent by anyone who
knows its (public) program. The guarantee this system makes instead is
stronger in practice: *a spend key exists, its holder can travel only the
account's corridor, and key compromise is bounded to corridor destinations*
(§7.1).

### 3.2 Gate attestation (the guard admits)

For guarded accounts, the program additionally requires the guard's
signature, bound to the same transaction ID but role-separated from the
holder's: a holder signature can never open a gate, and a guard signature
can never initiate a spend. The guard signs — opens the gate — only after
its deterministic policy evaluation authorizes the decoded transaction
facts (§5). Gate decisions are scoped to transaction facts; binding gate
approvals to particular requesting identities (per-authorizer delegation)
is out of scope for v1.

### 3.3 Construction authorization (the rekey path)

The program branches on the transaction's rekey field before any transfer
logic. A transaction that does not rekey takes the transfer path: corridor
evaluation (§4) and, for guarded accounts, the gate (§3.2). A transaction
that rekeys takes the construction path: it must be a zero-amount
self-payment with all close fields zero, carrying a Falcon signature from
the governance key. Accounts compiled without a governance key reject all
rekeys unconditionally — their corridors are permanent.

Design decision: corridor construction is authorized by a **plain Falcon
signature from the governance key, independent of the gate subsystem**.
Construction is never routed through transfer-gate rules, so topology
governance has no liveness dependency on the transfer guard. Guards gate
traffic; they do not supervise construction. Deployments that want
two-party construction control should make the governance key an M-of-N
arrangement at the key-management layer (or a second guarded account acting
as construction signer) rather than overloading the transfer guard.

The governance key MUST be distinct from the spend key, SHOULD be M-of-N,
and SHOULD be cold. Rationale in §7.2: construction authority is the one
power that can construct corridors.

## 4. Structural Policy: Corridors

### 4.1 Transfer hygiene

Transfer-path transactions are restricted to payments and asset transfers.
Close-out fields must be zero or name a corridor destination — a close to a
corridor destination is a sanctioned sweep through an existing corridor,
which keeps a decommissioning path open without creating a drain (the sweep
can travel no path a transfer couldn't). Clawback-style transfers initiated by
the account are rejected, fees are bounded by the compiled fee cap, and a
zero-amount self-transfer is permitted without corridor evaluation so an account
can opt in to approved Algorand assets. For clawback-enabled assets, the asset
issuer's clawback authority remains outside the holder account's LogicSig and
must be disabled or governed by an equivalent corridor/control model where the
strongest corridor guarantees are required.

### 4.2 Corridor evaluation

The corridor's destinations are compiled into the program as literal
addresses, compared directly against the transaction's receiver. The same
evaluation applies to receivers and to non-zero close-out targets.
Everything outside the corridor is wall: unreachable by the holder, the
guard, both in collusion, or any third party.

### 4.3 Optional structural bounds

The amount cap and validity window evaluate per transaction. Timed release
is expressed as an account knob (a validity floor on a purpose-configured account
or escrow leaf — a corridor that opens at a date), not as a distinct
account type.

## 5. Operational Policy: Gates

### 5.1 Verdict model — gates are shut by default

Sentry nodes evaluate their gate rules with deterministic, fail-closed
semantics: matching allow policy opens the gate (signs); deny rules leave
it shut; unmatched requests leave it shut; manual review and operator
default are not valid outcomes — a guard cannot be talked through a gate.
Transactions that cannot be represented as supported transfer movements
leave the gate shut. Gate-rule documents are tamper-evident and edited only
through supported, audited tooling.

### 5.2 What gate rules express

Movement authorization by sender, receiver, asset, and amount; deny rules;
network scoping; and per-guard-key overrides — approved classes, active
assets, and compliance gating expressed as gate rules rather than as
on-chain state anywhere. Updating gate rules is an authenticated policy edit
on the sentry node; it takes effect on the next signing request with no on-chain
transaction and no effect on any account's program. Gate rules can narrow
which traffic passes through a corridor; they can never authorize travel
where no corridor exists.

### 5.3 V1 trust domain

In v1, the signer and sentry are assumed to be operated by the same
organization, using separate node roles, data roots, keys, and policy
documents. The sentry is therefore an internal control and policy-enforcement
point, not third-party attestation. It still provides key separation and
fail-closed gate enforcement: the sentry key cannot spend, and the holder key
alone cannot pass guarded traffic. It does not protect against a fully
compromised or malicious operator that can command both roles.


## 6. Topology and Governance

### 6.1 The corridor map

The network graph is the union of per-account corridors: a directed edge
A→B exists iff B is a destination of A's corridor. The corridor map is not stored anywhere — no adjacency state, registry, or
route table. Multi-hop paths exist only where consecutive operators have
constructed consecutive corridors, and an intermediary's forwarding leg
requires that intermediary's Falcon signature — intermediaries are
operational signers, not passive infrastructure.

### 6.2 Constructing the corridor

Adding or removing corridor destinations at an account = construction rekey
to a LogicSig differing in its destination set. Properties:

- the account address is unchanged; no peer or counterparty updates anything;
- the rekey transaction is on-chain, so the sequence of effective signer
  changes is publicly auditable; the program/configuration history is complete
  when paired with the operator-published LogicSig configuration and template
  version;
- a transaction authorized under the previous program and not yet confirmed
  becomes invalid at the rekey — construction is atomic at a round boundary,
  with no shared-state race;
- the correspondence between published configuration and deployed program
  is verifiable per §6.4.

### 6.3 Atomic multi-hop

Any set of legs can be bound into one Algorand atomic group with no
application involved. A two-hop transfer A→B→C groups A's leg (A's holder
signature + A's gate if guarded) with B's leg (B's holder signature + B's
gate if guarded); the group succeeds or fails as a unit, so B never holds
funds between hops. Grouping is a delivery-guarantee option, not a security
requirement: with Falcon authorization on every account, an intermediary's
float cannot be moved by anyone but its key holder, and never outside its
corridors. APlane's guarded orchestration assembles such groups, collecting
holder and guard signatures per guarded position; mixed guarded/ungated
groups are supported by the same flow.

### 6.4 Verifiability

Counterparties and auditors must be able to confirm that an address
enforces the corridor it claims. Compilation of the corridor program is
deterministic for given configuration values; the template source and
version are published; and each account's operator publishes the configuration
needed to reproduce its program and confirm that the program is the
account's effective signer.

## 7. Security Model

### 7.1 Non-bypass guarantee

Except for protocol fees and issuer-controlled clawback behavior on
clawback-enabled assets, no account-controlled value leaves an account except
through a transaction that (a) carries a valid Falcon signature from the
account's spend key bound to that exact transaction — the holder initiated it;
(b) travels the corridor — the receiver, including any close target, is in the
compiled destination set; and (c) for guarded accounts, passes an open gate — a
valid sentry signature issued under fail-closed gate rules. The corridor
program is the sole effective signer for account-authorized movement; there is
no state to corrupt, no upgrade hook, and no administrative override of the
transfer path. The construction path can change the account's future corridor
but cannot move value beyond protocol fees (zero-amount self-payment only):
construction authority constructs corridors; it does not travel them.

### 7.2 Blast radius

| Compromise / failure | Worst case | Bound |
|---|---|---|
| Spend (holder Falcon) key | Attacker initiates transfers | Corridor destinations only; on guarded accounts every transfer still needs an open gate, so rule-violating traffic is stopped at the gate — except an always-available escape hatch, which the holder key can use without a gate but only to push value to the fixed recovery corridor (§7.3) |
| Guard (sentry) key | Attacker opens gates | **Opens gates, cannot construct corridors**: no spend occurs without the holder signature, and holder–guard collusion is still confined to the corridor |
| Gate-rule tampering | Improper gate openings | Same bound as guard-key compromise; rule files are tamper-evident and edits are audited |
| Governance key | Attacker rekeys the account to an arbitrary program | **Total for that account — this is the one power that constructs corridors.** Hence cold, M-of-N, distinct from the spend key, and absent entirely on immutable accounts |
| Guard unavailability | Every gate that guard controls is shut (fail closed) | Availability loss only, never integrity loss; bounded by the escape hatch where present — a timed hatch unlocks after its activation round, an always-available hatch is open throughout (§7.3) |
| Account operator coercion | Operator signs transfers under duress | The corridor and gate rules still bound destinations and facts |

The asymmetry between the spend key (travels corridors) and the governance
key (constructs them) is the central operational fact of the model and
drives the key-separation requirement.

### 7.3 Escape hatch (optional)

An account may include a recovery corridor: a transfer path requiring the
holder signature but **no gate**, restricted to a recovery corridor
(typically a single treasury or successor address). The hatch bounds the
worst case of permanent guard loss — value can always reach a safe address
even if the guard is gone — without widening where account-controlled value
may travel: the recovery corridor is itself an allowlist of one or a few
fixed destinations.

The hatch comes in two variants, chosen at construction:

- **Timed (dead-man switch).** The hatch is gated by an activation round
  and stays shut until then, preserving shut-by-default gates before
  activation. Operational pattern: periodically rekey the account to push
  the activation round forward; a healthy governance process never lets the
  hatch unlock. This is the right posture when the gate should hold value in
  place until guard loss is confirmed.
- **Always-available.** The hatch carries no activation round and is open
  from day one: the holder can move value to the recovery corridor at any
  time without a gate. This trades the timed variant's before-activation
  gate coverage for a standing, gate-free lane to a safe address — a panic
  button that no guard outage can disable. Because the recovery corridor is
  a fixed safe destination, a compromised spend key can use this lane only
  to push value into that destination, never to an attacker-chosen address;
  the cost is that the guard can no longer hold value away from the recovery
  corridor (see §7.2).

The recovery corridor may be realized as a dedicated gate-free destination
compiled into the account, or as a separate hatch side account — an ungated
allowlist whose sole destination is the recovery address — that the account
lists as a corridor destination. Accounts for which frozen-on-guard-loss is
the desired posture simply omit the hatch.

### 7.4 Monitoring

Production deployments monitor: gate rejections and gate openings (from the
sentry's signed audit log), construction rekeys on every account (an on-chain
watch), spend attempts rejected at the signer, balances below operating
reserve, and escape-hatch activity — activation proximity for timed hatches,
and any use of an always-available hatch. Transactions failing
program evaluation are rejected at submission and never appear on-chain;
rejection monitoring is therefore signing-infrastructure logging, not chain
scanning.


## Appendix: Glossary — The Corridor Model

Production terminology (sentry, guarded account, component signature,
sentry-domain policy) remains canonical and unchanged. The corridor
vocabulary is the system's explanatory layer; each term maps exactly onto
one architectural element, and this document uses both consistently.

| Term | Maps to | Definition |
|---|---|---|
| Corridor | The account's structural allowlist | The permitted transfer path compiled into an account's program: one origin (the account), one or more destinations. Each account has exactly one corridor; account-controlled value can move only through it, except for protocol fees and issuer-controlled clawback behavior on clawback-enabled assets. |
| Destination | An allowlist entry | A single address in an account's corridor. Each destination is one directed edge A→B of the corridor map. |
| Wall | Absence of a destination | Any address not among the corridor's destinations. Impassable by every party, including all key holders. |
| Construction | Governance rekey | Adding, removing, or reconfiguring corridor destinations by rekeying to a successor program. Deliberate, key-ceremonied, on-chain. |
| Guard | Sentry | A separate sentry-role node holding a component key and deterministic gate policy. In v1, this is an internal control point operated by the same organization as the sending accounts, not third-party attestation. |
| Guarded account | Guarded account (production term) | An account whose program requires both the holder's signature and the guard's co-signature. Two-party: the holder initiates, the guard admits, neither acts alone. |
| Gate | The sentry's per-transaction admission decision | Opened only by a sentry signature issued under matching allow policy. Shut by default: denied or unmatched transactions, unsupported shapes, and unreachable or locked sentries all leave the gate shut. |
| Gated corridor | An attested corridor | The corridor of a guarded account: structurally constructed AND per-transaction gated. |
| Ungated corridor | A non-attested corridor | The corridor of an ungated account: structurally constructed, no guard posted. Used where structural bounds alone are the intended control. |
| Gate rules | The sentry's policy document | The deterministic, fail-closed policy under which the guard opens gates. |
| Corridor map | The network graph | The emergent union of every account's corridor. Not stored anywhere. |
| Escape hatch | Recovery path | An optional gate-free path restricted to a recovery corridor. Either timed — unlocks only after an activation round — or always-available, open from day one. Realizable as a compiled destination or a hatch side account (§7.3). |

Two sentences carry the security model and recur throughout:

1. **A compromised guard can open gates; it cannot construct corridors.**
   Sentry compromise never expands where value can flow (§7.2).
2. **The holder initiates; the guard admits.** Neither the spend key nor the
   sentry key alone moves value from a guarded account (§3).

The substrate needs no metaphor — the ledger is Algorand, the signing
infrastructure is APlane — and everything the system adds on top is named
by the corridor model above. Spending accounts are simply **accounts** —
the nodes of the corridor map, with corridor destinations as its edges — and
the metaphor is not extended past the load it usefully carries.

---

*— End of Document —*
