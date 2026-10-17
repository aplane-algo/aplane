# Key Type Design Model

This guide describes the dimensions used to understand and design APlane key
types. It is a conceptual map for developers and LLMs, not a declaration that
every combination is implemented or safe to compose.

Read this first when asking what kind of key type to build. Then use
[ARCH_KEYTYPES.md](ARCH_KEYTYPES.md) for architecture and resolution rules,
[DEV_KEYTYPES.md](DEV_KEYTYPES.md) for implementation, and
[AGENTS_KEYTYPES.md](AGENTS_KEYTYPES.md) for the agent checklist. Exact contracts
remain authoritative in [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md),
[ARCH_GUARDED.md](ARCH_GUARDED.md), and [ARCH_SIGNING.md](ARCH_SIGNING.md).

## Describe an account along separate dimensions

A key type is a versioned definition that fixes a particular combination of
behavior. Its name is an identifier, not a substitute for that definition.

| Dimension | Question | Choices or examples |
|---|---|---|
| Account authorization mechanism | What does the chain verify? | Native signature, DSA LogicSig, generic TEAL-only LogicSig |
| Authority lifecycle | How does the account's authorizer evolve? | No mandatory rotation; mandatory per-spend stage rotation |
| Spending constraints | Which transactions may it authorize? | Signature-only, bounded profile, custom or dedicated program |
| Additional spending authority | Who else must participate in spending? | None; external cosigner |
| Administrative authority | Who may authorize each administrative operation? | Operation forbidden; spending key; spending key plus external admin |
| Signature construction | Which cryptographic proofs are required? | Falcon, Ed25519, WOTS, multiple algorithms required together |
| Network binding | What binds authorization to a network? | Transaction binding; additional network binding in key/stage derivation |

These dimensions organize design questions. They are not independent switches
in a general-purpose key type composer. An implementation must define which
combinations its contract permits.

**Nonrotating** here means no mandatory per-spend rotation. It does not mean
that an account can never rekey. Conversely, current rotating accounts keep a
fixed account address while each accepted spend transfers authority to the
predetermined next stage.

**Non-bounded** means outside the specific `bounded1` framework contract. It
does not mean unrestricted: custom and dedicated programs can constrain
transactions. Existing rotating programs impose rotation, validity, and
transaction-shape restrictions without being bounded1 profiles.

**Cosigned** means another authority participates, with a separate custody and
authorization role. Falcon plus Ed25519 signatures derived by the same signer
are a multi-algorithm construction, not an external cosigner.

**Admin-keyed** means a distinct external key participates in a named
administrative operation. In current bounded1, it co-authorizes pure rekey
with the spending key; it cannot independently spend or recover a lost spending
key. The `apadmin` management client is not this cryptographic authority.

## A sixteen-cell capability map

For DSA LogicSig accounts, four booleans make a useful overview:

`rotating × bounded × cosigned × external-admin-keyed`

The table has eight rows and two admin columns, covering sixteen conceptual
cells. Native accounts and generic TEAL-only LogicSigs are outside its scope.
“Bounded” refers to the implemented bounded1 contract; a future rotating bounded
contract would need its own explicit definition.

| Rotating | Bounded | Cosigned | No external admin key | External admin key |
|---|---|---|---|---|
| No | No | No | **Implemented:** plain Falcon and Ed25519 LogicSigs | **Design required:** no current combined contract identified |
| No | No | Yes | **Implemented:** dedicated Falcon/Falcon guarded account | **Design required:** no current combined contract identified |
| No | Yes | No | **Implemented:** bounded allowlist and timelock profiles | **Implemented:** `aplane.falcon1024-allowlist-alock.v1` |
| No | Yes | Yes | **Supported profile shape:** bounded cosigner spend gate with no admin operations | **Implemented:** `aplane.corridor.v1` |
| Yes | No | No | **Implemented:** the three rotating hybrid types | **Design required:** current rotating contracts have no external-admin path |
| Yes | No | Yes | **Design required:** rotating plus external cosigner | **Design required:** rotating plus cosigner plus external admin |
| Yes | Yes | No | **Design required:** rotating plus bounded policy | **Design required:** rotating bounded policy plus external admin |
| Yes | Yes | Yes | **Design required:** rotating bounded policy plus cosigner | **Design required:** all four capabilities |

“Implemented” identifies an existing type, not arbitrary combinations of
algorithms and policies. “Supported profile shape” describes an option allowed
by the existing contract, not a separately shipped template; a concrete profile
still requires validation and tests. “Design required” makes no claim that the
combination is compatible merely because each capability exists separately.

The no-admin column does not answer whether rekey is allowed. For example,
the bundled Falcon allowlist v1 permits spending-key-authorized rekey, whereas
a cosigner-enabled bounded1 profile cannot permit that bypass. Such a profile
must omit rekey or use the external-admin path.

## Authority belongs to operations

A boolean says that an authority exists. The complete contract must say what
that authority can do and which other signatures remain necessary.

| Operation | Required design decision |
|---|---|
| Ordinary spending | Spending signature construction, additional cosigner, policy and effect restrictions |
| Mandatory stage transition | Which next authorizer is permitted and how its usability is established |
| Administrative rekey or exit | Whether permitted; which authorities approve; permitted target and transaction form |
| Policy or cosigner replacement | Whether a defined transition allows it; whether it requires a new authorizing program |
| Recovery | What survives loss of each key, unavailable cosigners, cache loss, and restore |

For Corridor, ordinary spending requires the spending key and the cosigner,
subject to the bounded spending policy. Pure administrative rekey instead
requires the spending key and external contract admin, under the frozen admin
normal form; the spend cosigner and Layer-3 spending policy do not gate that
path. This is intentional separation of authority, not a general admin override.

Current bounded1 exposes only rekey as an admin operation. It has no general
policy-editing or witness-replacement API. Rekey can change the authorizing
program, but that is different from mutating an existing program's policy.

Current rotating contracts permit only the predetermined next-stage transition.
They have no arbitrary exit or external-admin recovery path. Combining rotation
with administrative rekey must explicitly reconcile those restrictions; it
cannot inherit both contracts unchanged.

## Keep concepts separate from contract names

| Layer | Examples | Meaning |
|---|---|---|
| Capability | Rotation, constrained spending, cosigning, administrative co-authorization | What behavior is desired |
| Authorization contract | `bounded1`; a particular frozen rotating stage program | On-chain rules and associated durable semantics |
| Concrete key type | `aplane.corridor.v1`, `aplane.rotating-triple-hybrid.v1` | One versioned account definition |
| Signing flow | Empty ordinary flow, `bounded1`, `cosigner1`, `bounded-cosigner1`, `rotating1` | Client/server choreography advertised by inventory |
| Implementation | Composer, provider, rotating stage operations, codec, registries | Code that realizes the contracts |

Matching words across layers do not make them interchangeable. A `bounded1`
contract with a cosigner advertises `bounded-cosigner1`. Adding rotation to a
cosigned account requires an explicitly defined choreography; clients must not
infer it from the key type's name or combine two flow labels themselves.

Use **rotating-bounded** for the proposed combination of rotation and a bounded
spending envelope, and **rotating-cosigned** for rotation with an additional
spending authority. In current APlane terminology, “guarded” usually refers to
cosigner participation; “rotating-guarded” does not identify a distinct policy
dimension without further definition.

## Signature construction and custody are additional choices

Multiple required algorithms can strengthen one authority without creating
multiple authorities. The rotating triple hybrid requires Falcon, WOTS, and
Ed25519 signatures, but its stage keys are derived under one signer-held seed.
An external cosigner adds a different custody and approval boundary.

A rotating-cosigned design must state whether the witness is fixed or rotates,
whether its schedule is synchronized with the spending stages, and who can
replace it. An admin-keyed design must separately state the admin's lifecycle
and permitted operations. None of these choices follows from “rotating: yes.”

Cosigner and contract-admin witnesses currently share a key form, but use
different custody containers and message domains. Sharing a cryptographic
algorithm does not make the roles interchangeable. Do not enroll the same
witness keypair in both roles.

## Design record for a new combination

Before writing code, complete this record and identify the authoritative
contract for every answer:

1. **Identity and scope:** new key type and version; authorization mechanism;
   existing contracts reused and contracts that must be introduced or changed.
2. **Operation authority:** permitted effects and transitions, required
   signatures per path, policy gates, forbidden operations, and recovery limits.
3. **Cryptography and custody:** algorithms, signature combination, key
   derivation domains, authority separation, witness enrollment and lifecycle.
4. **Bindings:** account, network, stage, transaction/group, next authorizer,
   and relevant policy commitments authenticated by each signature.
5. **Durable authority:** credential schema and validation; what is persisted
   versus derived; which files are reconstructible caches. Ordinary provider
   LogicSigs persist bytecode; current rotating keys derive stage programs.
6. **Choreography:** inventory flow, endpoints, preparation, approval,
   component verification, assembly, and submission. Define retry, expiry,
   partial-signing, concurrent-transition, and restore behavior.
7. **Resources and compatibility:** argument slots and bounds, program size,
   opcode ceilings, fees, canonical encodings, and version boundaries.
8. **Evidence:** positive and negative vectors, cross-account/network/stage
   replay rejection, forbidden-transition tests, next-stage opening tests,
   recovery cases, and maximum-resource checks as applicable.

Classify the result as an existing supported profile, a new implementation of
an established contract, or a new protocol design. An LLM should identify
unresolved contract decisions explicitly rather than silently borrow semantics
from two implementations that were never specified to compose.

The current rotating operations interface returns a complete locally signed
stage authorization. The cosigner flow separately collects and verifies
external components. Reusing their primitives is useful, but their combination
needs a defined integration boundary before it becomes a routine new-type task.
