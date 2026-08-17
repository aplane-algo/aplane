# Corridor v1 Architecture

## Status

`aplane.corridor.v1` is the first bundled profile that composes optional sentry
authorization into `bounded1`. It is an optional schema-v2 template source at
`library/templates/aplane.corridor.v1.yaml`; it is not a compiled provider,
authorization-contract identifier, key category, or special transaction
classifier.

The dimensions are independent:

| Dimension | Corridor v1 value |
|---|---|
| Full key type | `aplane.corridor.v1` |
| Account form | DSA LogicSig |
| Base signing primitive | `aplane.falcon1024.v1` |
| Authorization contract | `bounded1` |
| Layer-3 policy | framework-owned `merkle_allowlist` |
| Spend auxiliary authority | `sentry1`, Falcon witness, required on spend |
| Rekey auxiliary authority | distinct offline Falcon contract-admin witness |
| Advertised signing flow | `bounded-sentry1` |

Changing one dimension does not reinterpret the others. In particular,
`bounded1` is the on-chain envelope and durable metadata vocabulary, while
`bounded-sentry1` is the client/server choreography used to obtain a complete
spend signature.

### V1 compatibility ratification

This schema-v2 bounded template is the first supported
`aplane.corridor.v1`. Earlier development catalog entries used a compiled
guarded provider with different TEAL, address derivation, and choreography;
they were pre-release artifacts and do not define a durable Corridor
compatibility contract. No account generated from that provider is supported
as a production Corridor account. Developer or LocalNet instances must be
discarded or decommissioned and recreated from this template. The key type,
canonical program, metadata, and `bounded-sentry1` flow documented here become
the Corridor v1 compatibility baseline.

The complete sentry-bearing profile encoding, behavior parameters, Merkle
root/proof, argument masks, program binding, and admin transcript are frozen
together in
[bounded1 Golden vector 2](ARCH_BOUNDED_DSA.md#golden-vector-2-corridor).

## Accepted Transactions

Every accepted path requires the Falcon spending signature and
`Fee <= 10,000` microAlgos. Spend paths admit only:

- pure payments;
- pure asset transfers; and
- asset opt-ins.

A non-self `Receiver` or `AssetReceiver` must have a valid 512-byte proof
against the fixed-depth Merkle root compiled from the durable `recipients`
parameter. Self receivers bypass proof verification. Every spend also requires
the enrolled sentry's Falcon signature over the `APLANE_SENTRY_V1` sentry-role
TxID message.

Root construction, recipient canonicalization, duplicate rejection, padding,
node hashing, and proof order are frozen by the
[bounded1 Merkle allowlist compatibility contract](ARCH_BOUNDED_DSA.md#merkle-allowlist-compatibility-contract).

Corridor rejects close remainder, asset close, clawback, hybrid rekey+spend,
unsupported transaction types, missing or malformed proofs, missing sentry
authorization, and arguments supplied from the wrong source.

The only administrative operation is the bounded pure-rekey normal form. It
requires the spending signature plus the distinct external contract-admin
signature. It does not require or permit a sentry signature or Merkle proof.
The admin witness is therefore a rekey co-authorizer, not an independent
spending-key recovery key.

## Custody and Generation

Generation resolves three distinct Falcon keypairs:

1. the signer-held spending key;
2. the sentry-node `.sen` witness selected by `sentry` or supplied as
   `sentry_public_key`; and
3. the offline `.wit` contract-admin witness represented by
   `bounded_admin_public_key`.

Visible collisions reject. The generated `.key` stores the resolved public
parameters, bytecode, and complete signing-metadata version 2
`bounded_authorization` object. Existing keys therefore remain signable if the
installed product template is later disabled or removed.

The repository YAML is an install source only. Fresh signer identities do not
enable Corridor by default; operators import and enable it through the normal
KeyType Library workflow before generation.

The custody consequences are asymmetric:

- a stolen spending key cannot rekey the account without the admin witness;
- the spending key plus the admin witness can rekey away from an unavailable
  or compromised sentry or replace the current Corridor program;
- the admin witness cannot recover an account after the spending key is lost.

Operators must therefore back up the spending key and admin witness as distinct
required authorities rather than treating the admin witness as a substitute
for spending-key recovery.

## Spend Choreography

The frozen online flow is:

```text
client -> user signer  POST /sign/bounded-component
client -> sentry node  POST /sign/component (role: sentry)
client -> user signer  POST /sign/bounded-assemble
client -> algod         submit or simulate exact signed group
```

The first call finalizes group bytes and fees, applies user-signer policy and
operator approval, and releases the base signature args plus a spending-key
assembly receipt. First-party clients contact the sentry only after that
release. The sentry endpoint does not verify a prior base component, so this
order is client choreography for audit quality, efficiency, and predictable
operator UX rather than a sentry-enforced security property. Final assembly
verifies the base signature, receipt, sentry signature, durable metadata,
source/path masks, derived Merkle proof, frozen TxID, LogicSig address, and
authorizer binding.

Ordinary `/sign` rejects Corridor spends. First-party clients reject groups
mixing `sentry1` and `bounded-sentry1` targets because they do not implement a
combined assembly workflow; this is not a signer-side whole-group prohibition.
Contract-admin rekey uses `/sign/bounded-admin` plus `aprekey` and never
contacts the sentry.

The sentry component is transaction-scoped: it binds the sentry role and TxID,
not the Corridor account, authorizer, or program binding. Final assembly and
the LogicSig perform those account/program checks. Reusing one sentry key
across Corridor accounts therefore creates a shared transaction-policy domain;
per-authorizer sentry policy would require a new component-message and LogicSig
version. See [ARCH_SENTRY.md](ARCH_SENTRY.md#component-message).

## Close and Decommission

Corridor v1 has no direct close path. Decommissioning is deliberately a
two-step governance action:

1. use the bounded contract-admin ceremony to pure-rekey the account to a
   successor authorizer; then
2. use that successor authorizer to close the ALGO account or asset positions.

Step 1 requires both the existing spending key and the contract-admin witness.
It can escape a failed sentry or current policy, but it cannot recover a lost
spending key.

`CloseRemainderTo`, `AssetCloseTo`, and `AssetSender` remain zero on every
transaction authorized by Corridor itself.

## Compiler and Resource Budget

Corridor stores one resource profile over its final compiler-auto-salted
bytecode. The spend, spending-key rekey, and contract-admin rekey paths each
publish their own maximum argument bytes and reviewed opcode ceiling. Under
v42, argument/opcode capacity determines the minimum group size; bytecode above
the final group's free program pool contributes to the aggregate fee instead
of manufacturing extra dummies.

The pinned one-recipient compiler cell is approximately 5.9 KB of final
bytecode. Its worst-case spend and admin argument layouts remain distinct and
are derived from durable bounded metadata. The planner evaluates the selected
path, adds only required resource dummies, applies the v42 program surcharge,
and rejects the finalized transaction if its fee exceeds the compiled 10,000
microAlgo ceiling. Compiler golden values are toolchain-pinned; the stored
final bytecode is authoritative.

For shared definitions, see [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md),
[ARCH_SENTRY.md](ARCH_SENTRY.md), [ARCH_KEYTYPE_AXES.md](ARCH_KEYTYPE_AXES.md),
[ARCH_HTTP_API.md](ARCH_HTTP_API.md), and the machine-checked choreography in
[FORMAL_TLA_BOUNDED_SENTRY_MODEL.md](FORMAL_TLA_BOUNDED_SENTRY_MODEL.md).
