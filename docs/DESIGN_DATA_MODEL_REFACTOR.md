# Data Model Refactor Plan

Status: historical pre-v1 refactor tracking. The sentry-era data model
audit is now recorded in [ARCH_DATA_CATALOG.md](ARCH_DATA_CATALOG.md), which is
the current catalog and slice completion record. Treat the slices below as
lineage and older design context; before using any item as open work, verify it
against `ARCH_DATA_CATALOG.md`, `ARCH_DATA_MODEL.md`, `ARCH_SPEC.md`, and
`ARCH_CONTRACTS.md`.

This document records the original accepted data-model refactor plan. The goal
was to reduce duplicate authority, remove lossy projections, harden persistent
and wire shapes, and make deferred architecture debt explicit without doing a
risky one-shot schema rewrite. The current sentry-aware authority map and
remaining deferred cleanup decisions live in
[ARCH_DATA_CATALOG.md](ARCH_DATA_CATALOG.md).

## Scope

This plan combines the data-model reviews in `temp/dmreview_results.md` and
`temp/dmreview_results_claude.md`, plus follow-up validation. It is intentionally
slice-oriented: each implementation slice should be small enough to review,
test, document, and commit independently.

## Guiding Rules

- Fix duplicate authority before broad cleanup.
- Keep durable key compatibility unless a format bump is explicitly chosen.
- Prefer adapters at wire boundaries over leaking wire DTOs deeper into domain
  code.
- Do not add new non-boundary callers of `pkg/signerapi`; REST/client boundary
  code may use SDK DTOs, but deeper signer domain packages should not grow new
  dependencies on the HTTP contract.
- Split security, persistence, wire, and UI changes into separate reviewable
  commits.
- For every behavior-changing slice, document the old behavior, new behavior,
  and migration impact.

## Cross-Slice Obligations

Every slice must check whether these apply:

- **Generated docs:** rerun config/doc generation when structs with generated
  config documentation change.
- **HTTP contract fixtures:** update `test/contracts/signerapi/*.json` for
  `pkg/signerapi` shape changes.
- **SDK coordination:** any `pkg/signerapi` change needs corresponding review in
  `aplane-algo/aplanesdk`.
- **Architecture docs:** update `ARCH_DATA_MODEL.md`, `ARCH_CONTRACTS.md`, or
  the owning architecture doc for compatibility-bearing changes.
- **User docs:** update user-facing docs when behavior changes, especially
  config strictness, policy editing, or backup restore behavior.
- **Behavior-change note:** each slice should explicitly list user-visible
  changes and new failure modes.

## Source-Of-Truth Decisions

| Area | Decision |
|------|----------|
| ASA identity and aliases | One canonical ASA registry/resolver should own built-ins, aliases, ambiguity handling, and metadata. JS and plugin helpers should project from it rather than maintain separate maps. |
| Plugin asset context | Structured asset records are the canonical plugin context. The deprecated `assetMap` projection has been removed before external plugin compatibility became a constraint. |
| Key payload parameters | Key payload readers should normalize legacy/cosmetic aliases such as `params`/`parameters` and `lsig_bytecode`/`bytecode_hex` at one parser boundary. Conflicting aliases should fail closed. |
| Template type ownership | `compiled_provider` is a library/admin projection, not a `templatestore.TemplateType`. Template storage should reject unknown template types instead of defaulting to generic. |
| Transfer route IDs | Stored transfer route IDs are persistent audit identifiers. The UI may generate route IDs using the `<guardName>_<assetSuffix>` convention for new routes, but it must not silently rewrite existing IDs on no-op edits. |
| Policy rule IDs | Stable policy rule IDs should be constants. Dynamic transfer rule IDs use the documented grammar `transfer_policy:<route_id>:<verdict>`. |
| IPC passphrases | Admin protocol passphrase fields should decode into mutable `protocol.SensitiveBytes` and be zeroed at client/handler boundaries while preserving JSON string wire compatibility. |
| Signing args | Key-file `signing_args` are existing-key signing authority. `/keytypes` `runtime_args` are future-generation metadata. Keep this distinction. |
| HTTP DTOs | `pkg/signerapi` is the SDK-facing HTTP contract. Domain packages should use internal types or adapters rather than adding new direct dependencies. |
| Config ownership | Client and signer config may share names such as `theme`, but ownership and mutation paths must be explicit. |
| Backup bundles | Backup bundle parsing should have one canonical shape/helper and an explicit payload version separate from the legacy `backup_bundle` sentinel. |

## Accepted Implementation Slices

### Slice 1: IPC Passphrase Safety

Convert remaining admin protocol passphrase fields from `string` to
`protocol.SensitiveBytes` while preserving JSON string compatibility.

Fields in scope:

- `AuthMessage.Passphrase`
- `UnlockMessage.Passphrase`
- `InitializeStoreMessage.Passphrase`
- `ChangeStorePassphraseMessage.CurrentPassphrase`
- `ChangeStorePassphraseMessage.NewPassphrase`
- `ExportKeyMessage.Passphrase`

Required tests:

- real JSON byte round trips for auth/unlock/store messages,
- handler/client zeroing behavior,
- existing IPC auth/unlock/store flows.

### Slice 2a: Template Type Boundary Hardening

Stop treating `compiled_provider` as a `templatestore.TemplateType`. Keep the
admin wire string stable, but separate storage template types from library/admin
display types.

Expected blast radius:

- `internal/templatelibrary`
- `internal/templatestore`
- `internal/adminproto`
- `internal/protocol`
- `internal/signertui`
- related `cmd/apsigner` and TUI tests

Required behavior:

- unknown template types fail closed,
- `compiled_provider` cannot enter template store paths,
- compiled-provider activation still writes `keytypestate.SourceCompiled`.

### Slice 2b: Template Lifecycle Boundary Cleanup

Clean adjacent template lifecycle drift:

- low-level template storage should write encrypted template bytes, while
  template library/admin code owns key type state writes,
- consolidate or alias duplicated `RegistrationReport` and `ReloadReport`
  outcome shapes,
- split public `InstallResult` from rollback bookkeeping,
- remove or implement producer-less/dead template outcome fields.

### Slice 3: Canonical ASA Registry And Resolver

Create one canonical ASA built-in/alias model, likely under `internal/asa`.
Move JS `getAsaId()` onto the same resolver path as engine/shell and remove
`jsapi.wellKnownAssets`.

Required tests:

- built-in lookup,
- alias lookup,
- cached asset lookup,
- unknown asset behavior,
- ambiguous unit/name collision behavior,
- JS `getAsaId()` matches canonical resolver behavior.

### Slice 4: Plugin Asset Context Cleanup

Status: implemented. Plugin execution context now exposes structured `assets`
records and no longer includes the deprecated `assetMap` projection.

Build on Slice 3. Add structured plugin asset records:

```json
{
  "assets": [
    { "assetId": 10458941, "name": "USDC", "unitName": "USDC", "decimals": 6 }
  ]
}
```

Plugins should resolve ASA identifiers from the structured `assets` list, with
native ALGO handled out-of-band as asset ID 0.

### Slice 5a: Key Payload Parameter Normalization

Status: implemented for current key metadata readers.

Add a canonical key payload metadata parser used by verify, restore, scan, and
backup paths. Normalize `params`/`parameters` and
`lsig_bytecode`/`bytecode_hex`; reject conflicting duplicates.

Do not force full `KeyPair`/`LSigFile` unification unless a format bump is
explicitly accepted.

### Slice 5b: Backup Bundle Parser And Test Fixture Cleanup

Centralize backup bundle parsing and remove duplicated test-only bundle structs.
Add an explicit bundle payload version separate from the `backup_bundle`
sentinel and reject unknown versions.

### Slice 6a: InputModes Wire Decision

Status: implemented as public metadata on HTTP and admin IPC key type/template
surfaces.

Decide whether `lsigprovider.ParameterDef.InputModes` is public UI metadata.

If public, add `input_modes` to:

- `pkg/signerapi.CreationParamInfo`
- `protocol.TemplateParamInfo`

Then update adapters, TUI reconstruction, fixtures, SDKs, and tests.

If local-only, document that explicitly and ensure remote/admin flows do not
depend on it.

### Slice 6b: Signing Argument Projection Cleanup

Status: partially implemented. `internal/signingargs.Info` is the internal
canonical signing-argument shape, with explicit aliases/projections for key
files, signer cache, and HTTP DTOs.

Review duplication between:

- `pkg/signerapi.SigningArgInfo`
- `internal/cache.SigningArgInfo`
- `keys.StoredSigningArg`

Do not blindly make cache persistence depend on SDK wire tags. Either keep
explicit projections with tests/comments or introduce an internal canonical
shape with separate wire/cache projections.

### Slice 7a: Policy Rule ID Constants And Documentation

Status: implemented for current stable policy rule IDs and dynamic transfer
route rule ID construction.

Promote remaining inline policy rule IDs to constants. Document the dynamic
grammar:

```text
transfer_policy:<route_id>:<verdict>
```

Add tests to catch typos in stable rule IDs.

### Slice 7b: Transfer Guard UI Round-Trip Semantics

Share duplicated guard helpers between `policyview` and `policytui`. Preserve
route IDs on no-op edit. Fix `ensureTransferPolicy()` so merely opening guard
UI cannot materialize enabled reject-all routing.

### Slice 7c: Policy Model Overlap And Violation Shapes

Document or lint top-level deny booleans versus transfer route
close/clawback rules:

- `reject_clawback`
- `reject_close_remainder`
- `reject_asset_close`
- route-level `close.allow`
- route-level `clawback.allow`

Review duplication between `policy.LintViolation` and
`signerapproval.Violation`. Start with typed severity and explicit mapping
helpers rather than forcing one shared type if UI concerns differ from policy
concerns.

### Slice 8: API/DTO Shape Cleanup

Clean stale or confusing public/admin shapes:

- remove or deprecate unused `pkg/signerapi.SignResponse`,
- keep `SignRequest.TxnSender` for now but document it as display/advisory,
- move `KeysResponse.Locked` out of the HTTP DTO or document it as client-only
  wrapper state,
- consider a standard HTTP `ErrorResponse`,
- move or rename admin policy UI sentinels that sit beside real writable
  setting keys:
  - `adminproto.PolicySettingTransferGuards`,
  - `adminproto.PolicySettingMaxASAAmounts`.

Any `pkg/signerapi` changes require contract fixture and SDK coordination.

### Slice 9a: Plugin Callback And Manifest Schema Cleanup

Status: mostly implemented. Callback params/results are typed for the existing
callback constants, and plugin manifests use `manifest_format` only. The legacy
manifest `protocol_version` alias is rejected.

### Slice 9b: Plugin Execution Context And LocalSigner Cleanup

Status: implemented for the active plugin contract. Unpopulated context fields
use `omitempty`, local signers are typed top-level payloads, legacy
`data.localSigners` is not accepted for signing, and `TransactionIntent` only
contains the supported `raw` fields.

### Slice 10a: Config Strictness And Ownership

Add `KnownFields(true)` parsing for client/server config after checking current
generated/example configs. Clarify client/signer theme ownership and review
`ConfigFileChanged` drift detection for ignored mutable fields:

- `signer_port`
- `ssh.port`
- `passphrase_command_env`
- `networks`

This is user-visible because YAML typos that were ignored may start failing.

### Slice 10b: Keystore Metadata Validation

Tighten keystore metadata v2 KDF validation. Version 2 metadata with missing or
zero KDF fields should fail closed rather than silently using legacy defaults.

### Slice 10c: Cache Payload Versioning And Reserved Names

Add cache payload schema versions where caches are long-lived enough to matter.
Move reserved set-name enforcement closer to persistence for `@signers` and
`@all`.

### Slice 11: Dead Model Cleanup

Delete orphan or dead model code only after behavior-changing slices are out of
the way. Candidates include:

- `cache.LSigConfig` and `cache/lsig.go`,
- stale protocol messages retained only for decode compatibility, such as
  `ExportKeyMessage` and `ExportResultMessage`,
- dead template/catalog fields not handled in Slice 2b.

## Deferred Architecture Work

### Signing Domain Types Versus HTTP DTOs

Current issue: `internal/signerapp/signing` uses
`signerapi.GroupSignRequest`, `signerapi.SignRequest`, and
`signerapi.MutationReport` as internal domain types.

Deferred plan:

- introduce `signing.PlanRequest`, `signing.SignRequest`, and
  `signing.MutationReport`,
- translate at the REST boundary,
- keep HTTP JSON wire shape stable.

Do this before v1 if the team wants a clean SDK boundary. Otherwise document it
as post-v1 architecture debt.

### Full KeyPair / LSigFile Unification

Current issue: key payload concepts are duplicated across `KeyPair` and
`LSigFile`.

Deferred plan: first land Slice 5a normalization. Only unify structs if a key
format bump or broader key-payload migration is explicitly accepted.

### Broad Schema Version Reservation

Current issue: several persistent shapes do not have payload-level schema
versions. IPC and HTTP peers also lack a direct version surface, so clients
must infer support from behavior or optional fields.

Deferred plan:

- add versions first where needed for concrete migration behavior:
  - backup bundles,
  - cache payloads,
  - key type state if changing shape,
  - config only if strict parsing/version semantics are accepted,
- consider reserving wire version surfaces when touching those contracts:
  - admin IPC `protocol_version`,
  - HTTP `api_version` or equivalent response/header convention.

Avoid adding fields everywhere without code that defines their meaning.

## Priority Order

1. Slice 1: IPC passphrase safety.
2. Slice 2a: template type boundary hardening.
3. Slice 3 and Slice 4: ASA resolver unification and plugin asset context.
4. Slice 5a and Slice 5b: key payload and backup bundle normalization.
5. Slice 6a and Slice 6b: parameter/signing-arg projection cleanup.
6. Slice 7a and Slice 7b: policy rule IDs and guard editor semantics.
7. Slice 2b, Slice 7c, Slice 8, Slice 9, Slice 10, and Slice 11 as lower-risk
   cleanup and compatibility work.

## Commit Discipline

- Keep each slice small enough to review.
- Prefer one package family per commit.
- End each slice with focused tests.
- Include docs and behavior notes in the same commit when public or durable
  behavior changes.
- If a slice touches `pkg/signerapi`, update fixtures and coordinate SDK impact
  before merging.
