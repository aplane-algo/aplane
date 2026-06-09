# Formal Signing Authority Model

> Status: precise English model, not machine-checked.
> This document formalizes the current sign-time authority semantics for
> existing key files, especially LogicSig keys.
> Invariant status (implemented / intended / deferred / etc.) is tracked in
> [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).

## Sources

Normative inputs:

- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md): key-file, v1 signing-metadata,
  off-curve, template reload, backup/restore, and signing-authority contracts.
- [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md): durable authority map for key files,
  templates, policy, and runtime indexes.
- [ARCH_SPEC.md](ARCH_SPEC.md): signer startup, key scan, runtime index, and
  architectural invariants.
- [ARCH_LSIG_PROVIDER.md](ARCH_LSIG_PROVIDER.md): LogicSig provider and
  off-curve salting architecture.
- [FORMAL_TXN_PLANNING_MODEL.md](FORMAL_TXN_PLANNING_MODEL.md): sign-mode slots
  that must resolve to signer-managed signing authority.

## Scope

This model covers how an existing key file authorizes signing behavior after it
has been created, imported, restored, or loaded by `apsigner`.

Guarded account keys and sentry keys are existing key files, but
their request path is not ordinary `/sign`: direct signing rejects those key
types and the component-signing plus assembly workflow is modeled separately in
[FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md).

It does not model:

- the cryptographic correctness of Ed25519, Falcon, ECDSA, or TEAL opcodes,
- full template generation semantics,
- algod TEAL compilation,
- mnemonic generation,
- storage encryption details,
- operator approval policy.

## Notation

Pseudo-formal snippets in this document are relational pseudocode. `Reject(...)`
means no successful load/sign/restore result exists for that input.

## Abstract Objects

### Key File

`KeyFile` is an encrypted `.key` payload that becomes observable only after the
identity master key decrypts it. The model observes:

- key type,
- key category,
- native key material for native keys,
- LogicSig bytecode for LogicSig keys,
- `signing_metadata_version`,
- `salt_counter`,
- `signing_args`,
- `base_key_type`,
- optional `template_fingerprint`,
- creation parameters and provenance data.

The encrypted envelope and KDF are outside this model except for the assumption
that decryption succeeds only with the identity master key.

### Signing Authority Record

`SigningAuthority(key)` is the durable sign-time authority extracted from a
valid key file.

For native keys:

```text
SigningAuthority = stored native key material + key_type
```

For generic LogicSig keys:

```text
SigningAuthority = stored LogicSig bytecode + stored signing_args
                   + stored salt_counter
```

For DSA-backed LogicSig keys:

```text
SigningAuthority = stored LogicSig bytecode + stored signing_args
                   + stored salt_counter + stored base_key_type
                   + stored private signing material
```

The signer-side base cryptographic provider identified by `base_key_type` must
be available when a DSA-backed LogicSig needs a cryptographic signature. The
composed template/provider that originally generated the key type is not
required to reconstruct already-stored LogicSig bytecode or runtime arguments.

### Template Definition

`TemplateDefinition` is source material for generation, discovery, inventory,
library installation, and provenance checks. It is not sign-time authority for
an existing key file.

`template_fingerprint` is provenance metadata. A mismatch may be reported by
inventory surfaces, but it does not change the signability or signing behavior
of an otherwise valid existing key.

### Runtime Key Index

`RuntimeKeyIndex` is the in-memory projection created by scanning valid key
files after unlock or reload. It maps addresses to key metadata needed by
planning and signing. Concretely it exposes:

- `Resolve(address) -> KeyFile | NotFound` - maps an address to the durable
  key file that authorizes signing for it,
- `KeyType(address) -> key_type | NotFound` - the stored key type used by
  signing dispatch and fail-closed signability checks,
- `LSigSize(address) -> bytes | NotFound` - LogicSig budget contribution for
  planning.

The runtime index is a cache of valid key-file authority. It is not an
independent source of durable signing authority.

Canonical filename binding is a store invariant, not a selection
preference. A scan accepts a key file for address `X` only when the file is
named `X.key` and the decrypted payload derives address `X`. A misnamed
file is skipped as invalid key-file authority; it does not install an entry
in the runtime index and it does not compete with the canonical file for the
same address. See S13 below.

The model intentionally chooses skip-and-warn for misnamed files rather than
strictly failing the entire reload. Canonical filename binding removes the
selection ambiguity by construction: only `X.key` can load as authority for
address `X`. A noncanonical artifact is diagnostic evidence of operator or
tooling error, but it does not make the canonical file ambiguous.

Address-collision rejection remains a defensive fallback for impossible or
buggy states in which two accepted key files resolve to the same address. If
that fallback is ever hit, reload fails closed and invalidates any
previously-published snapshot rather than selecting a winner.

Recovery is operator-driven: rename a valid misnamed file to its canonical
address filename, or remove it if it is only an artifact, then trigger a
reload.

### Auth Address Binding

A sign-mode entry supplies an `auth_address`. The signer must obtain the
key used to authorize that slot through `RuntimeKeyIndex.Resolve(auth_address)`.
The transaction sender is not the binding handle: rekeyed accounts have a
sender different from their authorizing key, and the planner already routes
through `auth_address` for that reason.

## Load and Scan Rules

### Payload Parsing

1. Key payload parsing has one compatibility boundary.
2. Cosmetic aliases such as `parameters`/`params` and
   `lsig_bytecode`/`bytecode_hex` normalize to one semantic field.
3. If both aliases are present with conflicting values, the key payload rejects
   instead of selecting one by precedence.

### LogicSig v1 Metadata

Every signable LogicSig key must be a v1 signing-metadata key:

```text
signing_metadata_version >= 1
```

LogicSig keys missing `signing_metadata_version` reject when signing or restore
would otherwise depend on missing durable signing metadata.

### Stored Bytecode and Args

For LogicSig signing:

1. Stored bytecode is the bytecode to assemble into the LogicSig.
2. Stored `signing_args` defines runtime argument order.
3. Missing and empty `signing_args` are equivalent and mean no runtime args.
4. A live template definition must not reconstruct missing bytecode or missing
   signing args for an existing key.

### Off-Curve Requirement

Every persisted LogicSig key file must derive an off-curve LogicSig account
address from its stored bytecode.

Rules:

1. `salt_counter` is required for LogicSig keys.
2. The stored bytecode, not the `salt_counter` metadata field alone, determines
   the LogicSig address.
3. Changing `salt_counter` metadata without changing stored bytecode does not
   change the key address.
4. Key scan, signer load, backup verify, and restore reject LogicSig key
   payloads missing `salt_counter` or whose stored bytecode derives an on-curve
   address.

### Address Identity

Address identity derives from key material:

- native keys derive their address from stored public/private key material,
- DSA-backed LogicSig keys derive their account address from stored LogicSig
  bytecode,
- generic LogicSig keys may persist an `address` field for inventory and lookup,
  but the cryptographic LogicSig address is still derived from stored bytecode.

Signing metadata fields such as `signing_args`, `signing_metadata_version`,
`base_key_type`, `template_fingerprint`, and `salt_counter` are not independent
address derivation inputs.

## Signing Rules

Define:

```text
CanSign(key, request_args) -> true | Reject(reason)
AssembleAuthorization(key, txn, request_args) -> SignedOrAuthorizedTxn
```

Rules:

1. `CanSign` succeeds only when `key` has valid sign-time authority.
2. Native signing uses stored native key material.
3. Generic LogicSig signing assembles stored bytecode with runtime args ordered
   by stored `signing_args`.
4. DSA-backed LogicSig signing derives the key-type signing message, signs with
   stored private signing material, and packs the signature according to the
   signer-side base provider named by `base_key_type`.
5. The generic/composed template registered under the key's `key_type` is not
   consulted to assemble args at sign time.
6. Runtime args supplied by a caller must match the stored signing-argument
   contract.

## Invariants

### S1: Key File Authority

Existing-key signing behavior is a function of the decrypted key payload alone,
not of any live template definition. The base cryptographic provider named by
`base_key_type` must be registered for the behavior to be total, but the
provider is not an independent input; its identity is read from the payload.

```text
SignBehavior(existing_key) = F(stored_key_payload)
                             defined when provider(payload.base_key_type) is registered
```

Provider registration is an availability precondition, not an input that
could alter the behavior.

### S2: LogicSig v1 Required

No LogicSig key without v1 signing metadata can sign or restore as a signable
key.

```text
LogicSig(key) and key.signing_metadata_version < 1 => RejectForSigning(key)
```

### S3: Stored Bytecode Authority

LogicSig account identity and LogicSig assembly use stored bytecode.

```text
LogicSigAddress(key) = AddressOf(key.stored_bytecode)
LogicSigProgramForSigning(key) = key.stored_bytecode
```

### S4: Stored Signing Args Authority

Runtime argument ordering for existing LogicSig keys comes from stored
`signing_args`.

```text
ArgumentOrder(key) = key.stored_signing_args
```

### S5: No Template Reconstruction

Missing signing metadata for an existing key cannot be recovered from a live
template during signing.

```text
MissingDurableSigningMetadata(key) => RejectForSigning(key)
```

### S6: Off-Curve LogicSig Requirement

Every accepted persisted LogicSig key derives an off-curve address from stored
bytecode.

```text
AcceptedLogicSigKey(key) => OffCurve(AddressOf(key.stored_bytecode))
```

### S7: Salt Counter Required But Not Address Authority

`salt_counter` must be present for LogicSig keys, but address identity is still
derived from bytecode.

```text
AcceptedLogicSigKey(key) => HasSaltCounter(key)
AddressIdentity(key) = AddressOf(key.stored_bytecode)
```

### S8: Template Fingerprint Is Provenance Only

Template fingerprint mismatch may affect inventory reporting but not sign-time
behavior.

```text
TemplateFingerprintMismatch(key) =>
  SignBehavior(key) unchanged
```

### S9: Alias Conflict Rejects

Payload aliases with conflicting values reject at parse time.

```text
ConflictingAliases(payload) => RejectPayload(payload)
```

### S10: Runtime Index Is A Projection

The runtime key index does not authorize signing behavior that exceeds what
some validly loaded key file granted at the most recent scan-converged point.

```text
ResolvedAtScanPoint(t).index[address] = entry =>
  ExistsValidKeyFile(address, t) and
  entry is derived from that key file
```

The qualifier `at scan-converged point t` exists because reload is
asynchronous: between an on-disk change and the next completed scan, the
index may briefly describe state that no longer matches the filesystem. The
invariant constrains the relationship at scan-converged points, not at
arbitrary wall-clock instants.

Multi-field atomicity is enforced for planning by materializing a
per-request key-index snapshot. `Resolve`, `KeyType`, `LSigSize`, and the
signer-local known-address set used by request policy are derived from that
one copied snapshot rather than from separate live runtime reads. A reload
that completes after the snapshot is captured applies only to later
planning requests.

### S11: Key Selection Comes From The Index

For every accepted sign-mode entry, the key used to authorize the slot is
the one the runtime index resolves for the supplied `auth_address`. No
other lookup path (request fields, transaction sender, template registry,
audit log replay) can supply the signing key.

```text
SignMode(entry) and Accepted(entry) =>
  KeyForSlot(entry) = RuntimeKeyIndex.Resolve(entry.auth_address)
```

If `Resolve` returns `NotFound`, planning rejects before signing runs. The
implementation must not silently fall back to a different address or recover
a key by recomputing addresses from `signing_metadata_version`,
`base_key_type`, `template_fingerprint`, or `salt_counter` alone.

### S12: Auth Address Determines Policy Override

The key used for client-signing `key_overrides` selection is the request
`auth_address`. It is not derived from transaction sender. This preserves
rekey semantics: a rekeyed account uses the policy override for the signing
authority address.

```text
SignMode(entry) and Accepted(entry) =>
  EffectivePolicyKey(entry) = entry.auth_address
```

Missing key-type metadata still fails closed for signing dispatch and LogicSig
budget planning.

### S13: Canonical Filename Binding

Filename binding is a store invariant. A key file is loadable only if its
canonical filename matches the address derived from its decrypted payload.
The filename is not trusted as the authority; the payload-derived address is
still computed and compared to the filename.

```text
FileName(f) = X.key and AddressOf(Payload(f)) = Y and X != Y =>
  RuntimeKeyIndex.Resolve(Y) unchanged by f and
  f is reported as invalid key-file authority
```

Canonical writes and imports write to `X.key` for address `X`. Restore writes
the same canonical path when a restore operation elects to write the key;
higher-level restore may still skip an existing canonical key unless
`overwrite:true` is supplied. These write paths do not pre-scan the directory
for noncanonical duplicates. If a noncanonical `foo.key` also derives to `X`,
the scanner skips `foo.key` and loads `X.key`.

Status: implemented. See
[FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md) for concrete code and test
anchors.

## Assumptions

This model assumes:

- the identity master key correctly decrypts the key payload,
- provider registration supplies required base cryptographic providers for DSA
  signing when the stored key references them,
- transaction planning already selected a sign-mode slot and auth address,
- policy and lifecycle checks have allowed final signing to proceed.

## Non-Goals

This model does not prove:

- encryption envelope security,
- mnemonic correctness,
- off-curve salting search completeness,
- TEAL program semantic safety,
- cryptographic algorithm correctness,
- backup archive encryption or transport security,
- backup restore completeness (which keys end up loaded),
- policy approval correctness.

The model *does* constrain the key-payload validity rules that backup verify
and restore must enforce (off-curve LogicSig requirement, v1 metadata, etc.).
That is a property of the payload, not of backup machinery.

## Code and Test Anchors

These anchors are advisory pointers for traceability. They are not part of the
model and should be refreshed when code is renamed or ownership moves.

Implementation areas that should remain aligned with this model:

- `internal/keys`
- `internal/keystore`
- `internal/signingargs`
- `internal/signerapp/signing`
- `internal/signerapp/templates`
- `internal/signerapp/keyadmin`
- `internal/signerapp/backupadmin`
- `internal/lsigsalt`
- `lsig/`

High-value test anchors:

- LogicSig keys without `signing_metadata_version` reject for signing/restore,
- LogicSig keys without `salt_counter` reject,
- on-curve LogicSig bytecode rejects,
- conflicting key payload aliases reject,
- generic LogicSig signing uses stored `signing_args`,
- DSA LogicSig signing uses stored `base_key_type`,
- template fingerprint mismatch does not change signability,
- reload may change generation/discovery state but not existing-key signing
  behavior,
- sign-mode `auth_address` resolves through the runtime index; unresolved
  addresses reject in planning,
- `key_overrides` selection uses `auth_address`, not transaction sender,
- misnamed key files are skipped instead of being loaded under their
  payload-derived address.

## Open Questions

These should be resolved before a machine-checkable model:

1. Decide whether to model each key category separately or represent native,
   generic LogicSig, and DSA-backed LogicSig as one sum type.
2. Identify the smallest set of malformed key payload fixtures needed to cover
   the rejection invariants.
3. ~~Address-collision rejection (intended S13).~~ **Resolved as canonical
   filename binding.** The chosen form is now stated in S13 and implemented
   at key scan (`internal/keys/keys.go`). Canonical writes/imports/restores
   continue to write `{address}.key`; misnamed files are skipped rather than
   allowed to shadow or collide with canonical files.
4. ~~Cross-read snapshot consistency.~~ **Resolved.** Planning materializes a
   per-request key-index snapshot from the runtime once and uses that copied
   view for key-file resolution, key-type selection, LogicSig budget sizing,
   and signer-local known-address policy checks.
