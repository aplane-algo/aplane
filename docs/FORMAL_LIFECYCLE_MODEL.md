# Formal Lifecycle Model

> Status: precise English model, not machine-checked.
> This document formalizes identity runtime lifecycle and decommission behavior
> relevant to planning, approval, and final signing.
> Invariant status (implemented / intended / deferred / etc.) is tracked in
> [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).

## Sources

Normative inputs:

- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md): runtime lifecycle, decommission, key
  watching, reload, and template reload contracts.
- [ARCH_SPEC.md](ARCH_SPEC.md): server startup, identity runtime ownership,
  lock ordering, and architectural invariants.
- [ARCH_HTTP_API.md](ARCH_HTTP_API.md): decommissioned identity HTTP behavior.
- [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md): `identity.decommission` and
  sensitive-operation authorization.
- [FORMAL_TXN_PLANNING_MODEL.md](FORMAL_TXN_PLANNING_MODEL.md): final signing
  boundary that depends on lifecycle availability.
- [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md): policy snapshot stability
  across approval wait and final signing.

## Scope

This model covers the lifecycle decisions that determine whether an identity
runtime may accept new work and whether final signing may execute while
decommission races with an in-flight request.

It does not model:

- authorization grants for who may decommission,
- filesystem crash recovery beyond the documented persist-before-disable rule,
- fsnotify event ordering,
- HTTP routing internals,
- SSH authentication internals,
- operator decisions during approval.

## Notation

Pseudo-formal snippets in this document are relational pseudocode. `Reject(...)`
or `ErrDecommissioned` means no successful lifecycle-sensitive operation exists
for that input.

## Abstract Objects

### Identity Runtime

`Runtime` is the per-identity in-memory owner of:

- lock/unlock state,
- key session,
- key/template watcher,
- approval coordinator,
- policy snapshot,
- runtime key indexes,
- decommission flag,
- lifecycle lease lock.

### Stored Identity Config

`StoredConfig(identity)` includes identity-scoped settings under:

```text
identities/<identity>/config.yaml
```

`decommissioned:true` is an explicit disable marker. It is not inherited from
process-global defaults.

### Registry

`Registry` maps identity IDs to live runtimes for new lookup. Registry removal
prevents new lookup only. It is not the authority for in-flight runtime
lifecycle.

### Lifecycle Lease

`LifecycleLease` is the runtime operation lease acquired by final signing or
other non-interruptible identity work.

```text
BeginOperation(runtime) -> Release | ErrDecommissioned
```

`BeginOperation` and `Decommission` synchronize through the same lifecycle
read/write lock. `BeginOperation` acquires the read side and returns its release
function. `Decommission` acquires the write side before it persists and marks
the runtime decommissioned.

If a caller obtains the read-side lease before decommission obtains the write
side, decommission waits for release. If decommission obtains the write side and
marks the runtime first, `BeginOperation` fails.

### Pending Approval

`PendingApproval` is a queued or displayed signing or token-provisioning
approval request owned by the runtime approval coordinator.

## Startup Rules

1. `apsigner` discovers identity directories under `identities/`.
2. Identities with stored `decommissioned:true` are skipped or rejected at
   startup according to the active startup path.
3. Non-decommissioned identities get a runtime.
4. Locked and unlocked startup paths converge through reload/key-scan logic
   before session activation.

## Decommission Transition

Define:

```text
Decommission(runtime) -> Success | Reject(reason)
```

Successful live decommission proceeds in this order:

1. Acquire the lifecycle write lock shared with `BeginOperation`.
2. If already decommissioned, return success.
3. Persist `decommissioned:true` to stored identity config.
4. If persistence fails, leave runtime active and leave pending approvals
   untouched.
5. Mark runtime decommissioned.
6. Fail pending signing and token-provisioning approvals with an
   identity-decommissioned reason.
7. If unlocked, lock the runtime.
8. Stop the identity watcher.
9. Release lifecycle write lock.

Decommission is logical disablement. It does not delete key files, templates,
policy files, config files, backups, audit logs, or other identity data.

Step 3 performs disk I/O while holding the lifecycle write lock. This is
intentional: it guarantees no new `BeginOperation` lease can be obtained
between persistence and the mark-decommissioned step. Concurrent
`BeginOperation` callers wait until the write side is released. The
implementation may not move persistence outside the write lock, since doing
so would allow a sign request to begin after the disk state was already
"decommissioned" but before the in-memory flag was set.

Step 6 (fail pending approvals) must not perform any callback that itself
tries to acquire the lifecycle lock. Pending approval state updates use
their own coordinator-internal synchronization.

## Runtime Rejection Rules

A decommissioned identity rejects:

- unlock,
- reload,
- token provisioning,
- HTTP routing,
- SSH token authentication,
- SSH key checks,
- SSH key enrollment,
- final signing when no lifecycle lease was already acquired.

HTTP requests targeting unavailable or decommissioned authenticated identities
map to forbidden behavior according to the HTTP API contract.

## Registry Separation

`Registry.Remove(identityID)` and runtime decommission are separate contracts:

1. Registry removal prevents new registry lookup.
2. In-flight requests may already hold a `Runtime` pointer after registry
   removal.
3. Final signing must ask the runtime lifecycle lease, not the registry, whether
   execution may proceed.
4. Registry absence is not a final signing stop signal for an already-held
   runtime.

## Watcher and Reload Rules

Key/template watching is identity-owned:

1. The watcher starts when the identity runtime is unlocked or initialized.
2. It remains running across ordinary lock/unlock transitions.
3. When unlocked, qualifying file changes trigger reload.
4. When locked, qualifying file changes mark the identity dirty.
5. Watcher-triggered reload obtains the identity mutation lock before scanning.
6. The watcher stops on runtime shutdown or decommission.

Reload order is:

1. master key,
2. template registration,
3. key scan,
4. index replacement,
5. session activation,
6. notifications.

Reload may change generation/discovery state and runtime indexes, but it must
not reconstruct signing behavior for existing LogicSig key files from live
templates. That sign-time authority is modeled in
[FORMAL_SIGNING_AUTHORITY_MODEL.md](FORMAL_SIGNING_AUTHORITY_MODEL.md).

## Invariants

### L1: Decommission Is Logical

Decommission disables runtime use but does not delete identity data.

```text
Decommission(runtime) = Success =>
  DataFiles(identity) unchanged except StoredConfig.decommissioned = true
```

### L2: Persist Before Runtime Disable

Live decommission marks the runtime decommissioned only after persistence
succeeds. On persistence failure, decommission performs no further in-memory
state change.

```text
PersistDecommission(identity) fails =>
  runtime.decommissioned remains false and
  Decommission causes no transition on any p in PendingApprovals
```

Pending approvals may still change state independently (operator action,
timeout, cancellation); L2 only constrains transitions caused by the failed
decommission attempt itself.

### L3: Decommissioned Rejects New Work

After successful decommission, new lifecycle-sensitive work rejects.

```text
runtime.decommissioned = true =>
  Unlock, Reload, TokenProvision, HTTPRoute, SSHAuth, SSHKeyCheck,
  SSHKeyEnroll reject
```

### L4: Final Signing Uses Runtime Lease

Final signing is allowed only when it obtains the runtime lifecycle lease.

```text
BeginOperation(runtime) = ErrDecommissioned => FinalSigning rejects
BeginOperation(runtime) = Release => FinalSigning may proceed until Release()
```

### L5: Decommission Waits For Held Lease

If final signing already holds the lifecycle lease, decommission waits for
release before completing. This follows from `BeginOperation` holding the
read-side lifecycle lock and `Decommission` requiring the write side.

```text
LeaseHeld(runtime) and DecommissionStarts(runtime) =>
  DecommissionCompletes only after LeaseReleased(runtime)
```

### L6: Decommission Wins Race Before Lease

If decommission marks the runtime before final signing obtains the lease, final
signing fails cleanly.

```text
runtime.decommissioned = true before BeginOperation =>
  BeginOperation = ErrDecommissioned
```

### L7: Registry Is Not Lifecycle Authority

Registry removal cannot decide final signing for an already-held runtime.

```text
HeldRuntime(request) =>
  FinalSigningDecision = BeginOperation(HeldRuntime)
```

### L8: Pending Approvals Fail On Successful Decommission

Successful decommission fails the pending signing and token-provisioning
approvals that exist at the marking point, between step 5 (mark
decommissioned) and step 6 (fail pending approvals) of the decommission
transition. After step 5, no new pending approval can be added because L3
already rejects new lifecycle-sensitive work.

Let `Pending@MarkPoint(runtime)` denote that set. Then:

```text
Decommission(runtime) = Success =>
  forall p in Pending@MarkPoint(runtime):
    p.state ends as Failed(identity_decommissioned)
    unless p had already terminated (operator action, timeout, or
    cancellation) before step 6 ran
```

Approvals that terminated independently before step 6 retain their existing
terminal state; the decommission transition does not resurrect or rewrite
them.

### L9: Watcher Stops On Decommission

After successful decommission, the identity watcher is not running.

```text
Decommission(runtime) = Success => WatcherRunning(runtime) = false
```

### L10: Startup Skips Stored-Decommissioned Identities

Stored `decommissioned:true` prevents normal runtime activation.

```text
StoredConfig(identity).decommissioned = true =>
  StartupDoesNotActivateRuntime(identity)
```

### L11: Reload Step Order Is Fixed

Successful reload performs its steps in a fixed order. Earlier steps must
complete before later steps observe their results. Implementations may not
reorder, parallelize, or skip steps in a way that lets a later step run
against pre-reload state of an earlier one.

```text
ReloadSucceeds(runtime) =>
  steps = (master_key, template_registration, key_scan,
          index_replacement, session_activation, notifications)
  forall i < j: steps[i] completes before steps[j] begins
```

Reload does not reconstruct existing-key signing behavior from live
templates (see [FORMAL_SIGNING_AUTHORITY_MODEL.md](FORMAL_SIGNING_AUTHORITY_MODEL.md)
S1, S5).

## Assumptions

This model assumes:

- authorization has already permitted a decommission request,
- persistence accurately reports success or failure,
- runtime lock implementation provides normal mutual exclusion semantics,
- invariants about failed approvals after decommission apply only when the live
  decommission transition returns success and the process runs through the full
  in-memory sequence after persistence,
- pending approval failure notifications are best-effort beyond state update,
- data deletion, if ever added, would be a separate explicit operation.

## Non-Goals

This model does not prove:

- auth token validation,
- SSH host-key behavior,
- fsnotify delivery reliability,
- passphrase correctness,
- key-scan parsing correctness,
- policy decision correctness,
- cryptographic signing correctness,
- process crash recovery during decommission persistence.

## Code and Test Anchors

These anchors are advisory pointers for traceability. They are not part of the
model and should be refreshed when code is renamed or ownership moves.

Implementation areas that should remain aligned with this model:

- `internal/signerapp/identity/runtime.go`
- `internal/signerapp/startup`
- `internal/signerapp/rest`
- `internal/signerapp/signing/service.go`
- `internal/signerapp/approval`
- `internal/signerapp/filewatcher`
- `internal/signerapp/templates`
- `cmd/apsigner/http_runtime.go`
- `internal/adminproto`

High-value test anchors:

- stored decommissioned identities do not activate normally,
- live decommission persists before marking runtime disabled,
- persistence failure leaves runtime active and pending approvals intact,
- decommission fails pending approvals,
- decommission locks an unlocked runtime,
- decommission stops the watcher,
- `BeginOperation` rejects after decommission,
- decommission waits for an already-held operation lease,
- registry removal does not decommission a held runtime,
- HTTP plan/sign reject decommissioned runtimes.

## Open Questions

These should be resolved before a machine-checkable model:

1. Decide whether lifecycle should be modeled independently in TLA+ before it is
   composed with signing approval.
2. Identify the minimal state needed to model approval cancellation, timeout,
   and decommission failure reasons together.
3. Decide whether watcher dirty/reload behavior belongs in the lifecycle model
   or a later reload-specific model.
