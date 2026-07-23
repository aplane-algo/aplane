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

Corridor rejects close remainder, asset close, clawback, hybrid rekey+spend,
unsupported transaction types, missing or malformed proofs, missing sentry
authorization, and arguments supplied from the wrong source.

The only administrative operation is the bounded pure-rekey normal form. It
requires the spending signature plus the distinct external contract-admin
signature. It does not require or permit a sentry signature or Merkle proof.

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
identity-local template is later disabled or removed.

The repository YAML is an install source only. Fresh signer identities do not
enable Corridor by default; operators import and enable it through the normal
KeyType Library workflow before generation.

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
assembly receipt. Only then may the client contact the sentry. Final assembly
verifies the base signature, receipt, sentry signature, durable metadata,
source/path masks, derived Merkle proof, frozen TxID, LogicSig address, and
authorizer binding.

Ordinary `/sign` rejects Corridor spends, and the client rejects groups mixing
`sentry1` and `bounded-sentry1` targets. Contract-admin rekey uses
`/sign/bounded-admin` plus `aprekey` and never contacts the sentry.

## Close and Decommission

Corridor v1 has no direct close path. Decommissioning is deliberately a
two-step governance action:

1. use the bounded contract-admin ceremony to pure-rekey the account to a
   successor authorizer; then
2. use that successor authorizer to close the ALGO account or asset positions.

`CloseRemainderTo`, `AssetCloseTo`, and `AssetSender` remain zero on every
transaction authorized by Corridor itself.

## Compiler and Fee Budget

The pinned single-recipient compiler cell is:

| Bytecode | Spend LogicSig | Admin-rekey LogicSig | Required pooled group |
|---:|---:|---:|---:|
| 5,940 bytes | 9,012 bytes | 8,500 bytes | 10 transactions |

At the current 1,000 microAlgo minimum fee, the target fee is the compiled
10,000 microAlgo ceiling. A network with a higher minimum fee is rejected by
planning for this profile.

For shared definitions, see [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md),
[ARCH_SENTRY.md](ARCH_SENTRY.md), [ARCH_KEYTYPE_AXES.md](ARCH_KEYTYPE_AXES.md),
[ARCH_HTTP_API.md](ARCH_HTTP_API.md), and the machine-checked choreography in
[FORMAL_TLA_BOUNDED_SENTRY_MODEL.md](FORMAL_TLA_BOUNDED_SENTRY_MODEL.md).
