# App Interaction Architecture

## Overview

App interaction extends APlane from a transaction-centric shell into an
application-aware execution layer for Algorand smart contracts.

It supports:
- application state reads
- raw application calls
- ARC-4 / ABI-backed method calls
- grouped app execution with companion payments
- scripting access through the JS runtime
- signer-side approval descriptions for app calls

## Scope

App interaction includes:
- app state reads from algod
- app call transaction preparation in `internal/engine`
- shell-facing app command orchestration in `internal/apshellapp`
- explicit ABI loading from local files
- grouped execution through a first-class `PreparedGroup`
- CLI and JS user surfaces
- signer approval rendering for application calls

App interaction does not include:
- interactive `group create/add/build/send` REPL state
- ABI discovery from network sources
- provider-layer redesign
- external authorizers such as ECDSA / EIP-712
- protocol-specific adapters for individual dApps

## Core Invariant

The main architectural invariant is:

**`PreparedGroup` is the canonical boundary between transaction preparation and grouped execution.**

App interaction does not introduce a new authorization abstraction, but it makes
grouped app execution explicit rather than treating it as ad hoc
`[]types.Transaction` plumbing at the outer layers.

This keeps the app interaction work compatible with the signer flow.

## Design Goals

### Engine-first

Core app preparation lives in `internal/engine`. Shell-facing command
workflows, alias resolution, and result shaping sit above that layer in
`internal/apshellapp`. `internal/apshellcli` owns shell command parsing, REPL
handling, and rendering, while `cmd/apshell` stays the thin binary adapter for
flags, provider registration, bootstrap, and mode selection.

This follows the same design rule as the rest of APlane:
- the engine operates on resolved addresses, numeric IDs, and prepared inputs
- `internal/apshellapp` owns shell command semantics and app-facing orchestration
- UI layers parse user syntax and format results

### Explicit ABI sourcing

ABI-backed calls require an explicit local ABI path. The system does not attempt
to discover ARC-4 contracts from the network.

This keeps method resolution deterministic and avoids introducing network
coupling, caches, or ambiguous discovery semantics into the engine.

### Group-first for real dApp flows

Many Algorand app interactions require more than one transaction. Companion
payments are the common first example.

Grouped execution is an engine primitive instead of modeling app calls only as
standalone transactions.

### Reuse the signer pipeline

App interaction prepares richer transaction plans, then routes them through
the shell-app to engine to signer path.

## Architecture

### Layering

```
┌──────────────────────────────────────────────────────────────┐
│ User Surfaces                                                │
│                                                              │
│  apshell CLI         apshell JS API          MCP exposure    │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ Shell Application Layer                                      │
│                                                              │
│  app read commands   raw call workflows   deploy workflows   │
│  method-call workflows                                       │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ Engine                                                       │
│                                                              │
│  app reads   raw app calls   ABI method calls   groups       │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ Existing signer/submission path                              │
│                                                              │
│  group planning   approval prompts   signing   submission    │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ Algod / Algorand SDK                                         │
└──────────────────────────────────────────────────────────────┘
```

### Main packages

| Package | Responsibility |
|---------|----------------|
| `internal/apshellapp/` | Shell-facing app command orchestration and result shaping |
| `internal/engine/app_read.go` | App info/global/local/box reads |
| `internal/engine/app_call.go` | Raw and ABI-backed app call preparation |
| `internal/engine/app_deploy.go` | App deployment preparation and created-app lookup |
| `internal/appspec/` | ARC-4 contract loading, method resolution, argument encoding |
| `internal/engine/group.go` | `PreparedGroup`, grouped preparation, grouped execution |
| `internal/appinput/` | Shared parsing helpers used by CLI and JS |
| `internal/apshellcli/commands_app*.go` | CLI adapter and app command parsing surface |
| `internal/jsapi/apps.go` | JS app interaction bindings |
| `internal/signerapp/txdesc/transaction_description.go` | Signer approval descriptions for app calls |

## App State Reads

App interaction provides five engine read operations:
- `ReadAppInfoWithContext(ctx, appID)`
- `ReadAppGlobalStateWithContext(ctx, appID)`
- `ReadAppLocalStateWithContext(ctx, address, appID)`
- `ReadAppBoxWithContext(ctx, appID, name)`
- `ListAppBoxesWithContext(ctx, appID)`

The CLI exposes these as:
- `app read info <app-id>`
- `app read global <app-id>`
- `app read local <app-id> <account>`
- `app read box <app-id> <box-name>`
- `app read boxes <app-id>`

Results are returned as structured JSON objects. Box names and values are
represented in both raw-safe and human-readable forms where possible so the same
surface works for scripting and manual inspection.

## App Call Preparation

### Raw calls

Raw app calls are prepared directly from explicit app arguments and references.

Supported preparation inputs include:
- sender
- app arguments
- foreign accounts
- foreign apps
- foreign assets
- box references
- on-completion
- update-only approval and clear programs
- per-call LogicSig arguments
- note
- fee / flat-fee control

The engine entrypoint is:
- `PrepareAppCallRawWithContext(ctx, params RawAppCallParams)`

The CLI surface is:
- `app call raw <app-id> from <account> ...`

Raw-call CLI arguments also include:
- `approval=` / `approval-teal=` / `approval-bin=` and `clear=` / `clear-teal=` / `clear-bin=` when `oncomp=update`
- `arg:name=value` for per-call LogicSig arguments passed through the existing signer flow

This path is the protocol-level fallback and does not depend on ABI metadata.

### App deploy

Application deployment is also prepared in the engine so program loading,
compilation, schema sizing, and sender/signing context all live below the UI
layer.

Supported deployment inputs include:
- sender
- approval program path
- clear program path
- source vs compiled program selection
- global and local schema sizing
- extra pages
- note
- fee / flat-fee control

The engine entrypoint is:
- `PrepareAppDeployWithContext(ctx, params AppDeployParams)`

The CLI surface is:
- `app deploy from <account> approval=<path>|approval-teal=<path>|approval-bin=<path> clear=<path>|clear-teal=<path>|clear-bin=<path> ...`

After confirmed submission, the engine can also resolve the created
application:
- `LookupCreatedApplicationWithContext(ctx, txID)`

### ABI-backed method calls

ARC-4 method calls build on top of the raw path.

The ABI layer:
- loads a contract JSON file from disk
- resolves a method by name or full signature
- encodes typed arguments
- prepends the selector
- delegates to the raw preparation path

The engine entrypoint is:
- `PrepareAppCallMethodWithContext(ctx, params MethodAppCallParams)`

The CLI surface is:
- `app call <app-id> <method> --abi <path> from <account> --arg ...`

This keeps ABI handling out of the signer and out of the low-level transaction
execution path.

## `PreparedGroup`

Grouped execution is represented by `PreparedGroup`:

```go
type PreparedGroup struct {
    Entries []PreparedGroupEntry
}

type PreparedGroupEntry struct {
    Transaction    types.Transaction
    SigningContext *SigningContext
    LsigArgs       map[string][]byte
    AppCallInfo    *signerapi.AppCallInfo
}
```

This type is owned by the engine. It represents:
- ordered transactions
- their derived signing metadata
- any per-entry LogicSig args

It does not represent authorization proofs, wallet sessions, or external
signing workflows.

### Why `PreparedGroup` exists

It serves three roles:

1. It gives grouped app execution a stable engine-level type.
2. It preserves transaction-order metadata needed by the signer path.
3. It provides a clean boundary for companion-payment flows without requiring an
   interactive group builder.

### Group preparation and execution

The engine exposes:
- `PrepareGroup(preps ...*TransactionPrepResult)`
- `PreparePaymentAppGroupWithContext(ctx, prepper, payment, app)`
- `PreparePaymentMethodGroupWithContext(ctx, prepper, payment, app)`
- `ExecutePreparedGroupWithContext(ctx, group, wait)`

The first concrete grouped dApp pattern is companion payment plus app call.

Both CLI and JS support this through a `pay` option:
- ABI-backed calls can prepend a payment to the app address
- raw calls can do the same without ABI metadata

The resulting group is signed and submitted through the group flow
rather than through a special-purpose protocol.

The paired helper methods are convenience helpers for the concrete grouped
patterns. More complex composition should
prepare transactions independently and compose them through
`PrepareGroup(...)` rather than multiplying bespoke helper functions.

This also marks a complexity boundary for `apshell`: the shell exposes
common app-interaction primitives and lightweight grouped patterns, but
it is not a general-purpose protocol orchestration DSL. When a
workflow requires richer multi-step composition, protocol-specific planning, or
substantial off-chain logic, the preferred approach is a custom script,
program, or adapter built on the same engine primitives.

## User Surfaces

### CLI

The primary user surface is `apshell`.

Supported commands include:
- `app read info|global|local|box|boxes`
- `app deploy ...`
- `app call raw ...`
- `app call <app-id> <method> --abi <path> ...`
- grouped companion-payment calls with `--pay <microalgos>`
- `simulate <command>` using the simulate prefix

The CLI remains responsible for:
- numeric and byte parsing
- user-facing syntax
- command help and completion

Alias resolution and asset-name resolution for app calls are owned by
`internal/apshellapp` before requests reach `internal/engine`.

### JavaScript API

App interaction also exposes bindings to the Goja-based scripting layer.

The JS API includes:
- `appDeploy(from, approvalPath, clearPath, opts)`
- `appInfo(appId)`
- `appGlobal(appId)`
- `appLocal(appId, account)`
- `appBox(appId, boxName)`
- `appBoxes(appId)`
- `appCallRaw(appId, from, appArgs, opts)`
- `appCall(appId, method, abiPath, from, args, opts)`

This is a convenience surface, not a separate architecture. JS bindings call
into the same engine primitives as the CLI.

### Shared input parsing

`internal/appinput/` holds app-specific parsing helpers reused by shell and JS
surfaces, including:
- byte value decoding
- on-completion parsing

This keeps app-call input handling consistent across user surfaces.

### MCP

MCP exposure is not a separate execution architecture. It is another thin user
surface over the same engine methods described in this document.

That means:
- MCP does not define its own transaction-preparation model
- MCP does not bypass `PreparedGroup`
- MCP should not accumulate app semantics that differ from CLI or JS

The engine remains the source of truth for app reads, app call preparation, and
grouped execution regardless of which surface invokes it.

## Reference Normalization

Application calls may include explicit references such as:
- foreign accounts
- foreign apps
- foreign assets
- box references

These are treated as engine preparation inputs rather than as surface-specific
concerns. The architectural rule is:

- user surfaces parse and resolve inputs
- the engine owns transaction construction
- any canonicalization or merge policy belongs in the engine, not in CLI, JS,
  or MCP wrappers

App interaction does not include a rich reference-planning abstraction. It
establishes the ownership boundary for normalization work
such as deduplication, ordering guarantees, and merge rules between
ABI-derived and user-supplied references.

## Signer Approval Descriptions

`apsigner` describes application calls during approval.

The signer renders:
- app ID
- sender
- on-completion label
- formatted app arguments
- foreign accounts, apps, and assets
- box references

This does not make the signer ABI-aware in a general sense. It makes app calls
reviewable at the approval boundary by improving raw transaction visibility.

## Testing Strategy

App interaction uses a repo-owned integration fixture rather than relying
only on third-party contracts.

### Test fixture

The fixture app in `test/fixtures/testapp/` is small and focused.
It supports:
- global state mutation
- local state
- box writes and reads
- grouped companion-payment deposit flow

### Integration harness

The harness in `test/integration/harness/testapp.go` deploys and seeds the test
app directly for integration tests.

### Coverage

The integration suite exercises:
- app deploy and created-app lookup
- app info reads
- app reads
- raw app calls
- ABI-backed app calls
- grouped payment + app call execution
- grouped simulation
- JS API bindings

This gives app interaction a stable in-repo validation environment instead of
depending on protocol-specific external fixtures.

## Relationship to Transaction Flow

App interaction does not replace the transaction flow documented in
`ARCH_TXNFLOW.md`. It extends the preparation side of that flow.

The engine produces richer prepared transactions and prepared groups, but
authorization and submission go through the signer pipeline.

This is an important architectural constraint:
- app interaction is additive
- signer providers are unchanged
- grouped execution reuses the canonicalization and submission path

## Summary

App interaction adds a subsystem to APlane:
- app-aware reads and transaction preparation in the engine
- local-file ABI-backed method calling
- grouped execution through `PreparedGroup`
- CLI and JS user surfaces
- signer approval descriptions that make app calls operable in practice

The key architectural result is a stable engine model for application
interaction that reuses the signer flow.
