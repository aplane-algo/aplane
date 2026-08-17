# Fix Plan v2 (Second-Review Issues)

Date: 2026-07-02

Supersedes `temp/fixplan.md`. Same confirmed-issue set (all ten items were
re-verified against the working tree; the v1 confirmation matrix is accurate
and is not repeated here). This version changes four things:

1. **Drift controls move to the front.** They are test-only, independent, and
   protect every later phase's wire changes.
2. **The non-interactive carve-out in the plugin-review fix is removed.**
   "Fail closed unless an explicit safe policy gate" was an undefined hole in
   the most security-sensitive item. Fail closed, period; automation opt-in is
   its own explicit, named mechanism with its own tests.
3. **Lock ordering for the new provider-owner lock is pinned**, not left to
   the implementer — this is exactly where the currently-acyclic daemon lock
   graph could acquire a reversed edge.
4. **Version negotiation is trimmed to version surfacing.** Peers ship in
   lockstep today (same stance as the SensitiveBytes contract); full
   capability negotiation across three SDK languages remains separately
   deferred. It is not coupled to dormant multi-identity behavior. Version
   fields make skew *diagnosable* now at a fraction of the cost.

It also adds items v1 omitted: the admin-IPC legacy string-classification
fallback, the F3 residuals (component-pair validator duplication,
`familyImportExceptions` staleness guard), the TLA copied-operator sync check,
and the project-mandatory verification steps (integration suite, testmode
build).

---

## Phase 0 — Contract drift controls and quick independent fixes

Phase 0a is contract drift scaffolding and should land first. Phase 0b contains
small independent cleanups that are low risk, but not "no risk"; they should not
block Phase 1 if they uncover unrelated churn.

### 0.1 Error-code set-equality tests across the four mirrors

- Generate and commit `error_codes.json` into both fixture dirs
  (`test/contracts/signerapi/` and aplanesdk `contracts/signerapi/`) from
  `pkg/signerapi/error_codes.go`.
- Add set-equality tests in four places: `pkg/signerapi`, aplanesdk
  `go/errors.go` mirror, `typescript/src/types.ts` `ErrorCodes`, python
  `signer.py` `ERR_CODE_*`. Each test enumerates its language's constant set
  and compares to the fixture — adding a code anywhere without updating the
  fixture fails a build.
- Also commit a fixture for the code→semantic-classification map
  (for example locked→locked, not_found→not_found, unavailable→temporary),
  currently hand-mirrored 3× in the SDKs. Do not encode language-specific
  exception class names in this fixture; each SDK maps semantic buckets to its
  own idioms.

### 0.2 Fixture-directory sync check

- Commit a SHA-256 manifest of the fixture directory in each repo; each
  repo's CI verifies its own directory against its manifest. A fixture change
  then forces a visible manifest edit in *both* repos in the same review —
  the failure mode today is silently-stale SDK fixtures with all tests green.
- Add a cross-repo sync check that compares APlane's fixture directory against
  an explicit SDK checkout (`APLANESDK_DIR`) or the default sibling checkout
  (`../aplanesdk`). The per-repo SHA manifests catch local uncommitted drift;
  the cross-repo check is what proves the two repos are synchronized.
- Replace the four hand-duplicated fixture name arrays
  (`pkg/signerapi/types_contract_test.go`, aplanesdk
  `go/types_contract_test.go`, `python/tests/test_contracts.py`,
  `typescript/tests/contracts.test.ts`) with a committed manifest each test
  reads.

### 0.3 Admin service result codes become constants; delete dead mappings

- Declare the service result codes (`activation_failed`, `key_type_in_use`,
  `restore_rate_limited`, `decrypt_failed`, ...) as constants in
  `internal/protocol`, used by producers
  (`internal/signerapp/templateadmin/service.go:119,263,414`,
  `backupadmin/service.go:120`) and by the consumer
  (`cmd/apstore/exit_codes.go:104-140`).
- Delete the consumer entries with no producer (`template_conflict`,
  `key_already_exists`, `provider_collision`, `exit_codes.go:117-119`) — they
  are proof the unshared list rots; do not keep dead mappings "just in case".

### 0.4 Sentry endpoint: classify by code before HTTP status

- `internal/engine/sentry_endpoint.go:231-240`: branch on
  `HTTPStatusError.Code` first (`locked` → lock/unavailable class, not
  `ErrSentryDiscoveryAuth`); keep the status fallback only for empty-`Code`
  old servers. Tests for locked / forbidden / unauthorized / refresh codes.

### 0.5 SSH runtime lock narrowing

- `internal/signerapp/daemon/ssh_runtime.go:174-181`: under `sshRuntimeMu`,
  take and clear the runtime pointer; release the lock; then call `Stop()`.
  Add a comment stating why (Stop joins per-connection handlers that may call
  `currentSSHServer()`), so a future live-restart path doesn't reintroduce
  the self-arrest.

### 0.6 F3 residuals (from the architecture-review scrutiny)

- Replace the byte-for-byte duplicate probe-validate in
  `internal/signerapp/signing/component_sign.go:244-266` with a call to the
  existing `keytypes.ValidateComponentPair` registry
  (`internal/sentry/keytypes/componentpair.go:27`) — real duplication today,
  independent of any second guarded family.
- Give `familyImportExceptions` (`test/arch/layering_test.go:101-105`) the
  same self-shrinking staleness guard `signerappExceptions` already has, so
  the Falcon exemption cannot outlive its reason.

### 0.7 TLA copied-operator sync check

- Small script (make target, wired into `formal-test`) that diffs the shared
  operators copied into `composition.tla` / `approval_composition.tla` /
  `lifecycle_composition.tla` against their source modules, allowing only the
  documented intentional deltas (Init/Safety/TypeOK/vars, UNCHANGED
  extensions). Both formal docs already admit the copies are fragile; this
  makes the current verified-clean state durable.

## Phase 1 — Active trust-boundary and lock-invariant gaps

### 1.1 Legacy plugin `localSigners` groups get the mandatory decoded review

Today the all-plugin-senders path (`internal/engine/plugin_signing.go:255-293`)
bypasses apsigner and its only gate
(`internal/apshellcli/external_plugins.go:130-148`) shows `"[n] pay
transaction"` with no sender/amount/receiver, prompts only if the *plugin*
sets `RequiresApproval`, and is skipped under `AutoConfirm` (unconditional in
MCP and script modes — `mcp.go:50`, `repl.go:173`).

- Route legacy-mode plugin groups through the same decoded-bytes renderer as
  pregrouped-signed (`internal/apshellcli/plugin_group_review.go`): sender,
  receiver, amount, asset, fee, rekey field, app-call detail, local-signer
  provenance per slot; undecodable content is marked **opaque**, never
  omitted.
- Review is mandatory. The plugin's `RequiresApproval` bool no longer gates
  it in either direction (a plugin may not waive review of its own output).
- **Non-interactive modes fail closed unconditionally**, matching
  pregrouped-signed (`external_plugins.go:157-183`). No policy-gate
  carve-out.
- Automation opt-in, if needed, is a separate follow-up with its own design:
  an explicit per-plugin allowlist in client config (named plugin + named
  group mode), off by default, surfaced in `--help` and docs as a security
  setting. Do not fold it into this change.
- Tests: interactive approve/reject with display-content assertions;
  MCP/script mode rejection; mixed vs all-plugin routing unchanged for the
  mixed path (apsigner approval already displays passthrough slots —
  `internal/signerapp/signing/approval.go:182-216`).
- Note expected behavior change: existing MCP/script flows that used
  all-local plugin groups will now fail closed. That is the point; release
  notes must say so.

### 1.2 Admin-session ownership invariant (unlock must have an owner)

Today `AuthenticateOutcome` unlocks during auth
(`internal/signerapp/adminserver/session.go:210-215`), promotion happens
afterward (`internal/signerapp/daemon/ipc.go:196-207`), and disconnect cleanup
(fail-all + `lock_on_disconnect`) runs only when
`authenticated && wasActiveClient` (`ipc.go:157-173`). Any failure between
unlock and promotion can leave the identity unlocked with zero admin clients
and the lock-on-disconnect contract silently void.

- State the invariant in code comments and enforce it structurally: **if an
  identity is unlocked on behalf of an admin session, either an active owner
  session exists, or cleanup locks the identity (when `lock_on_disconnect`)
  and fails pending approvals — no third state.**
- Preferred mechanism: split verify from commit. Derive/verify the master key
  during auth *without* installing it; promote the session; then commit the
  unlock as the promoted owner. If that split is too invasive for the
  keystore session model, use the fallback:
- Fallback: provisional-unlock ownership. The authenticating session takes a
  provisional owner token before `UnlockIdentity`; a single `defer` releases
  it — if at defer time the session is not the promoted active owner and no
  other active owner exists, run the same cleanup path as active-client
  disconnect (fail-all + conditional lock).
- Displacement ordering: the old active session remains cleanup owner until
  the replacement is authenticated *and* promoted; ownership transfer is
  atomic in the session manager (extend
  `adminserver/displacement.go:57-67` so clearing the old active and
  promoting the new one is one step, or the old session keeps ownership on
  any failure).
- Regression tests: (a) auth succeeds, `MovePendingToIdentity` fails, session
  exits → identity locked when `lock_on_disconnect`; (b) displacement offer
  rejected after unlock → same; (c) competing pending sessions where both
  fail differently; (d) happy path unaffected. Exercise via the batch/IPC
  path so it runs without a TUI.

### 1.3 Approval-prompt lifecycle: one owner, three consistent triggers

Disconnect fails pending approvals (`daemon/ipc.go:163`), decommission does
(`identity/runtime.go:536`), explicit lock does not
(`adminserver/handlers.go:210`) — and displacement deliberately skips the old
session's cleanup, orphaning a delivered prompt and head-of-line-blocking the
identity for up to `ApprovalWait` (60s default).

- On displacement: before closing the old session, either fail the in-flight
  delivered prompt with a "displaced" reason or requeue it for redelivery to
  the new active session. Requeue is better UX and is feasible — the request
  goroutine holds the payload and already loops on delivery-turn acquisition;
  add a "delivery invalidated, retry" signal parallel to the existing cancel
  channel. If requeue proves invasive, fail-with-reason is acceptable; pick
  one, don't leave the orphan.
- On explicit lock: `HandleLockIdentity` calls
  `FailAllPendingApprovals("identity locked")` before `ir.Lock()`, so the
  operator sees a cancellation, not the misleading "signer not unlocked"
  stale-KeySession error (`keystore/session.go:63`) after a later
  re-unlock+approve.
- Tests: replacement apadmin receives the next prompt immediately after
  displacement (no 60s stall); explicit lock produces a structured
  cancellation on the client side; decommission/disconnect behavior
  unchanged.

## Phase 2 — Process-global state under local locks

### 2.1 LSig provider registry: process-scoped ownership with pinned lock order

Removal for identity A holds only A's mutation lock and unregisters globally
(`internal/signerapp/templateadmin/service.go:385-397` →
`lsigprovider.Unregister`); identity B loses its provider with no repair path
until restart. The install-rollback path already guards on `AlreadyExists`
(`service.go:641-645`); removal needs the equivalent, but done properly:

- Introduce a process-scoped **template provider owner** that tracks, per key
  type, which identities reference it (populated at startup scan and on every
  install/remove). Register idempotently; unregister only when the reference
  count for that key type reaches zero.
- **Lock ordering, pinned:** identity mutation lock → provider-owner lock →
  `lsigprovider.registerMu`, always in that order, never holding the
  provider-owner lock while acquiring any identity lock. Add this edge to the
  lock-ordering documentation (`internal/signerapp/identity/runtime.go:41-79`
  block and `docs/ARCH_SPEC.md` lock table). The current daemon lock graph is
  acyclic (verified in the audit); this is the one place this plan adds a
  cross-cutting lock, so the order is part of the design, not an
  implementation detail.
- The provider-owner lock only updates in-memory refcounts and calls
  `lsigprovider`; it must not scan the filesystem, reload identities, invoke
  watcher callbacks, or run any operation that can acquire an identity lock.
- On removal that drops the count to zero, unregister; on removal where other
  identities still reference it, leave the registry untouched and only delete
  A's files/state.
- Multi-identity regression test: install the same template in identities A
  and B, remove from A, verify B still generates/derives/signs; then remove
  from B, verify the provider unregisters.

### 2.2 ASA metadata: no network I/O under the global lock

`asametadata.cacheMu` (`internal/signerapp/asametadata/cache.go:22`) is
package-global across identities and is held across live algod fetches with
no context deadline (`internal/cache/asa.go:78`) on a client with no HTTP
timeout (`internal/signing/fees.go:40`). `/sign` policy formatting contends on
the same mutex (`internal/policy/lint.go:141-158`).

- Split cache access from resolution: hold `cacheMu` only to read/write the
  map; do live fetches outside it with per-(network, assetID) singleflight so
  duplicate lookups coalesce without serializing unrelated assets/identities.
- Add a context deadline to the fetch and an HTTP timeout to the algod client
  used here.
- Sign-path formatting must never wait behind a live fetch: it is local-only
  today by configuration — make that structural (the sign-path resolver gets
  a cache-only handle that cannot block on I/O; on miss, format
  conservatively in base units).
- Decommission notification I/O: move the `onLocked` → IPC `NotifyLocked`
  socket write out from under `lifecycleMu`
  (`identity/runtime.go:523-542`) — mark state and clear key material under
  the lock, enqueue notifications after release. Decommission is terminal, so
  post-release delivery cannot race a re-unlock.
- Test: a black-holed metadata resolver (blocked fetch) while signing and
  policy rendering for other assets and identities proceed.

## Phase 3 — Coordinator ↔ formal model alignment

### 3.1 Decommission becomes a coordinator-visible guard

The spec guards `Deliver` on `~decommissioned` and drains queued work
(`docs/formal/approval_coordinator.tla:93,156-162`); the code's only check is
the pre-queue fast-path (`identity/runtime.go:457`), and the post-turn
rechecks (`approval/coordinator.go:315-335`) cover ctx/cancel/`hasClient` but
not decommission — a queued approval can be delivered and approved after the
mark (output is stopped only by the downstream `BeginOperation` lease).

- Inject a decommission predicate into the coordinator at construction
  (`startup/identity_build.go:204-232`, alongside `hasClient`) and recheck it
  after `acquireDeliveryTurnContext`, mirroring the `hasClient` recheck at
  `coordinator.go:326`.
- `Decommission` fails queued waiters, not just delivered ones: either the
  predicate recheck suffices (waiters fail on their next turn) or fail-all
  also signals queued waiters — match the spec's
  `FailQueuedWhileDecommissioned` semantics either way.
- Keep the lease gate as defense in depth (do not weaken
  `beforeExecute`/`BeginOperation`).
- Fix the doc over-claim: `docs/FORMAL_APPROVAL_COORDINATOR_MODEL.md:264-267`
  currently asserts the race cannot happen. Update it (and
  `FORMAL_TRACEABILITY.md` rows for AP6/L8) in the **same PR** as the code
  change, after code and model agree.
- Regression test: request queued behind a delivered prompt, decommission
  fires, delivered prompt fails, queued request is never delivered; assert no
  operator prompt and a structured decommission error to the client.
- While in the file: replace the wholesale 1024-entry wipe in
  `rememberCanceledSignRequestLocked` (`coordinator.go:188-193`) with
  oldest-first eviction. Cosmetic; one line of intent.

## Phase 4 — Version surfacing (trimmed from v1's negotiation)

Lockstep shipping makes silent field-dropping a diagnosability problem, not a
correctness emergency. Surface versions everywhere; defer negotiation.

- REST: add `protocol_version` as `{major, minor}` and build version to
  `HealthResponse`/`StatusResponse` (`pkg/signerapi/types.go`), update both
  fixture dirs + manifests (Phase 0 machinery makes this a forced, visible
  change), and mirror the fields in the three SDKs' status types.
- Admin IPC: add a `{major, minor}` protocol version to the auth/hello
  exchange (`internal/protocol/messages.go:142-146`). Log a warning on minor
  mismatch; reject only on major-version mismatch. SSH-transported admin runs
  the same exchange (it's the same messages).
- Plugin protocol: replace the hardcoded `"1.0"`
  (`internal/plugin/manager/manager.go:462`) with a named host protocol
  version constant; require the plugin's initialize result to echo a
  supported version; **fail plugin startup** on mismatch (this surface is the
  one place third-party skew is expected, so it gets enforcement, not just
  surfacing). Document the distinction between JSON-RPC `"2.0"`,
  `manifest_format`, and the aPlane plugin protocol version in
  `docs/ARCH_PLUGINS.md`.
- Explicitly deferred: capability negotiation, client-side pre-op checks,
  strict server-side unknown-field rejection. Revisit at multi-user, recorded
  alongside the other multi-tenant deferrals.

## Phase 5 — Plugin footguns

### 5.1 Remove the dead plugin→host `signTransaction` callback

- Delete `CallbackSignTransaction` and the unused plugin→host callback types
  from `internal/plugin/jsonrpc/methods.go:257-347`. Nothing installs a
  production handler (`SetRequestHandler` appears only in tests), no shipped
  plugin can be using it, and a typed "host signs what the plugin asks" API
  with no review design is a landmine. Deletion over documentation — there is
  no compatibility to preserve.
- Keep the inbound-request routing plumbing if other future callbacks are
  plausible, with a test asserting production clients answer
  method-not-found; otherwise delete that too.
- Any future host-signing callback must be designed through the mandatory
  decoded review path (reference Phase 1.1) — record that constraint in
  `docs/ARCH_PLUGINS.md`.

### 5.2 Plugin state directory locking and lifecycle

- Take a `flock` on a lockfile in `plugin-state/<name>` before launching a
  plugin with writable state (`internal/plugin/manager/manager.go:104-127`);
  fail startup with a clear "state directory in use by another shell" error.
  This matters because the motivating plugins carry funds-bearing state.
- Uninstall semantics: preserve state by default (current behavior,
  intentional), add an explicit `--purge-state`/documented manual path, and
  say in docs that state may contain key material.
- Test: two managers contending for one state dir; loser fails cleanly.

## Phase 6 — Remaining compatibility edges

### 6.1 Version the two main config files

- Add optional `schema_version: 1` to client config
  (`internal/config/config.go`) and server config
  (`internal/serverconfig/serverconfig.go`); absent means v1. Keep
  `UnmarshalKnownFields` strictness for typo protection, but wrap the
  unknown-field error so a downgrade reads "config written by a newer
  version (field X unknown)" instead of a raw yaml error.

### 6.2 Admin-IPC legacy string classification (v1 omission)

- `internal/protocol/IPCErrorCode` (`error_codes.go:73-116`) exact-matches
  lowercase message text and silently falls through to `ErrCodeInternal` on
  any rewording; `cmd/apstore/exit_codes.go:62-101` additionally
  substring-matches prose (including the word "rate_limited" inside message
  text). With Phase 0.3's constants in place, producers attach codes at the
  source — shrink `IPCErrorCode` to a legacy fallback for codeless peers
  (same pattern as the REST client), and delete the prose substring matching
  in apstore in favor of code-only dispatch plus a generic fallback exit
  code.

---

## Fix order

1. **Phase 0** — one aplane PR + one aplanesdk PR, test-only plus trivial
   fixes. Everything later that touches the wire is then drift-checked.
2. **Phase 1** — the security-adjacent items. 1.1 is independent of 1.2/1.3
   and can land alone; 1.2 and 1.3 both touch session lifecycle and should be
   sequenced (1.2 first — it defines the ownership model 1.3's displacement
   handling builds on).
3. **Phase 2** — cross-identity breakage and stall hazards. 2.1 and 2.2 are
   independent.
4. **Phase 3** — with the doc/traceability update in the same PR.
5. **Phase 4** — coordinated aplane + aplanesdk PRs (fixture changes forced
   visible by Phase 0).
6. **Phases 5–6** — small independent PRs, any order.

## Verification (per landing PR, not once at the end)

- `make fmt-check vet staticcheck lint build-check` (CI is authoritative; the
  Makefile targets are the single definition).
- `go build -tags testmode ./...` — **mandatory**: `cmd/apadmin/batch.go` is
  invisible to untagged builds and Phase 1.2 touches the auth flow batch mode
  drives; this exact gap has caused an integration failure before.
- `go test -race ./internal/signerapp/...` for Phases 1–3 (approval,
  displacement, unlock-ownership, coordinator changes).
- `make integration-test-localnet` after every Phase 1–3 PR and after 2.1
  (structural refactor discipline; requires the test env from
  `test/setup-test-env.sh`; do not mutate the working tree while the suite
  runs). Known flake: `TestSignerRejectsWhenLocked` can fail 400-vs-403 on a
  race — rerun before suspecting a regression.
- `make formal-test` after Phase 3 (TLC over all specs, including the
  operator-sync check added in 0.7).
- aplanesdk: Go/TS/Python contract tests after Phase 0 and Phase 4 changes.
- Phase 1.1: manual/scripted check that MCP mode rejects an all-local plugin
  group with a clear error (fail-closed observable end to end, not just unit
  tests).
