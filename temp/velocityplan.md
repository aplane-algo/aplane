# Implementation Plan: Sentry Audit Enrichment + Velocity Limits

> Status: plan, July 2026. Two deliverables: (A) enrich sentry component-signing
> audit records, (B) stateful velocity limits in the sentry policy domain.
> Design constraint honored throughout: **no change** to sentry1 choreography,
> component message, TEAL templates, `/sign/component` / `/sign/assemble` wire
> shapes, or SDKs. Everything lives in the sentry's off-chain policy domain.

## Motivation (short)

Sentry policy is stateless per-transaction: a policy-compliant fat-fingered
loop (or a compromised signer machine draining at full speed within policy
bounds) passes N times. Velocity limits convert "compromised signer can do what
policy permits" into "bounded loss per window + detection interval". The lsig
must stay stateless; the sentry daemon need not. Audit enrichment is a
prerequisite-adjacent fix: today's sentry audit entries carry no txid, amount,
or asset, which limits forensics and makes incidents harder to reconstruct.

---

## Part A: Sentry audit enrichment

### Current state (verified)

- `internal/signerapp/signing/sentry_policy.go:200` `logSentryComponentApproved`
  emits one `LogSignApproved(identityID, componentKey, target.Sender, "sentry
  component signature target %d signed")` per target — no txid, no txn type, no
  movement facts.
- Rejections (`logSentryPolicyRejections`, same file) carry reason + first
  `policy_rule_id` only.
- `internal/signerapp/audit/audit.go:56` `AuditEntry` already has unused-here
  fields: `TxID`, `TxnType`, `TxnDetails`.
- `ComponentSignTarget` (`signing/component.go:24`) already carries
  `TxID [32]byte` — the data is in hand at both log sites.
- ARCH_SENTRY.md calls the current projection "an MVP projection".

### Changes

1. **New optional audit interface** in `internal/signerapp/signing`
   (follow the existing optional-upgrade pattern used for
   `AuditRejectPolicyRuleLogger`):

   ```go
   type AuditComponentLogger interface {
       LogSentryComponentDecision(e ComponentAuditEvent)
   }
   type ComponentAuditEvent struct {
       IdentityID   string
       ComponentKey string // Sentry Key ID -> txn_auth
       TargetIndex  int
       Sender       string // -> txn_sender
       TxID         string // canonical base32 txid string -> txid
       TxnType      string // pay / axfer -> txn_type
       Details      string // movement summary -> txn_details
       Outcome      string // approved | rejected
       Reason       string // rejection reason ("" for approvals)
       PolicyRuleID string
   }
   ```

2. **Details string** built by a shared deterministic formatter over
   `policy.ExtractTransferMovements(txn)`, plus an explicit `RekeyTo` clause
   (rekey is a transaction field, not a transfer movement): one clause per
   fact, e.g.
   `pay 1500000µA -> RECV...ADDR` / `axfer asa:31566704 25000000 -> RECV...` /
   `pay_close unknown -> CLOSE...ADDR` / `rekey -> TARGET...`. Raw on-chain
   units only (no ASA metadata lookups on the sentry — keep it deterministic
   and offline). Unknown close amounts are rendered as `unknown`, never as 0.

3. **Wire both log sites** (`logSentryComponentApproved`,
   `logSentryPolicyRejections`) to prefer `AuditComponentLogger` when the
   configured `AuditLog` implements it, falling back to today's calls
   otherwise. Rejections gain per-target txid/type/details too. For a
   transaction-scoped rejection, each target receives the first violation whose
   `TxnIndex` matches that target. Group-scoped violations apply to every target.
   A target that was individually valid but belongs to an all-or-nothing rejected
   request is still recorded as rejected, with the full request reason and no
   falsely attributed transaction rule ID.

4. **Implement in the daemon audit logger** (`internal/signerapp/audit` +
   the `signingAudit` adapter in `internal/signerapp/daemon/signing_service.go`):
   map fields onto the existing `AuditEntry` — reuses `SIGN_APPROVED` /
   `SIGN_REJECTED` event types, so **no new event family** and no consumer
   breakage (these are newly populated existing `omitempty` fields, not new
   audit keys).

5. **Docs**: update the audit sections of ARCH_SENTRY.md ("MVP projection"
   paragraph) and ARCH_POLICY.md; check ARCH_CONTRACTS.md audit section for
   compatibility-bearing statements and extend it (new populated fields are
   additive).

### Tests (Part A)

- Unit: `component_test.go` — approval and rejection entries carry txid
  (matches `plan.Targets[i].TxID` base32), txn_type, details for pay, axfer,
  pay+close (two movements, one entry per target with combined details), rekey.
- Unit: multi-target rejection attributes each transaction rule only to its
  matching target; individually valid targets in a rejected request do not
  inherit another target's rule ID.
- Unit: fallback path when logger does not implement `AuditComponentLogger`.

Estimated size: ~150 lines + tests. Ships standalone (commit 1).

---

## Part B: Velocity limits

### B1. Policy grammar (`internal/policy/transfer_routing.go`)

Extend route `limits` (and `limits_by_network` values) with an optional
`velocity` list. Stored form:

```yaml
transfer_policy:
  schema_version: 1
  enabled: true
  routes:
    - id: treasury_usdc
      networks: [mainnet]
      sources: ["@treasury"]
      assets: ["asa:31566704"]
      destinations: ["@vendors"]
      limits:
        reject_above: 1000000000        # existing per-txn ceiling
        velocity:
          - window: 24h
            max_total: 5000000000       # raw units, same unit rules as reject_above
            max_count: 200
          - window: 1h
            max_total: 1000000000
```

Types:

```go
type StoredVelocityWindow struct {
    Window   string  `yaml:"window"`              // Go duration string
    MaxTotal *uint64 `yaml:"max_total,omitempty"`
    MaxCount *uint64 `yaml:"max_count,omitempty"`
}
type VelocityWindow struct {
    Window   time.Duration
    MaxTotal *uint64
    MaxCount *uint64
}
// StoredAmountLimits + compiled AmountLimits (transfer_routing.go:138/194)
// each gain: Velocity []…VelocityWindow
```

Validation rules (in the existing route-compile path):

- **Sentry-domain only.** Signer-domain `policy.yaml` rejects `velocity`
  at load, same mechanism/wording as `rekey_policy` rejection in the signer
  domain. Rationale: enforcement requires daemon state; client-signing has the
  human-review tier instead. (Revisit later if wanted for client signing.)
- `window` parses via `time.ParseDuration`, bounds `[1m, 720h]`; at least one
  of `max_total` / `max_count`; no duplicate parsed durations per limits block
  (`60m` and `1h` are duplicates); zero is allowed for either cap and means the
  corresponding activity is blocked;
  `max_total` obeys the existing "route with amount limits must resolve to at
  most one asset unit per network" rule (already enforced for
  `reject_above` — velocity inherits the same check); `max_count`-only
  velocity is exempt from the single-unit rule (counting is unit-free).
- `limits_by_network` overrides replace (not merge) the global `velocity`
  list for that network, consistent with existing threshold override
  semantics.
- Key-override overlay: unchanged — overrides that provide `routes` replace
  the route list; velocity rides inside routes.
- Extend every stored/compiled clone path to deep-copy the velocity slice and
  cap pointers; policy snapshots must remain immutable after publication.
- Unknown-field strictness is already in place, so an **old daemon fails
  closed** when handed a velocity policy (operator must upgrade binary before
  policy — the right failure direction). Keep `schema_version: 1`.
- `appolicy --to-sentry` projection: velocity is already sentry-domain;
  projection passes it through untouched. `appolicy` guided editor: YAML-only
  in v1 (precedent: clawback routes); ensure round-trip preservation test.

### B2. Route-match resolver (`internal/policy/transfer_routing_eval.go`)

Velocity needs *which route matched which movement*; today's eval returns only
violations. The internals already exist: `matchingTransferRoutes` (line 291),
`effectiveRouteLimits` (line 436). Add an exported resolver that reuses them:

```go
type MovementRouteMatch struct {
    MovementIndex int              // index in ExtractTransferMovements(txn)
    Movement      TransferMovement // Kind, Network, Asset, Amount, AmountKnown, …
    RouteID       string
    Velocity      []VelocityWindow // effective network-resolved limits
}
// ResolveSentryMovementMatches(txn types.Transaction, cfg *Config)
//     ([]MovementRouteMatch, error)
```

Contract: called only after the existing sentry lints pass, so every movement
has ≥1 matching route and network resolution succeeded. When multiple routes
match a movement, velocity applies from **every** matching route that has
velocity configured (consistent with `aggregatedRejectThreshold`'s
most-restrictive-wins philosophy; each route's counters are tracked under its
own route ID). Refactor the existing eval loop minimally so match collection
is shared, not duplicated — behavior-preserving for current verdict output
(guarded by existing `transfer_routing_eval_test.go`).

`max_count` counts matched **movement authorizations**, not HTTP requests or
transactions. A pay+close transaction has two movements and consumes one count
in each matching route scope for each movement. If a movement matches two
velocity-bearing routes, it consumes one count in each route scope. This is the
same unit of accounting used by `max_total` and by journal idempotency. Zero
amount payments and ASA opt-ins also consume count capacity when they match a
count-limited route; policy authors can use narrower routes when that is not
desired.

### B3. Velocity store (new package `internal/velocity`)

The package owns the durable format, replay, counters, compaction, master-key
rotation, and verification. It is below the daemon layer so `internal/storepass`
and `cmd/apstore` can use the same implementation without importing a
`signerapp` package. `internal/signerapp/signing` depends only on a small
`VelocityReserver` interface.

**Journal**: append-only JSONL at
`identities/<identity>/velocity.jsonl` on the sentry node. Add the path to
`internal/storepaths`; create it with the repository's store-file ownership and
permission helpers rather than relying on process umask.

The first line is a versioned, HMAC-protected generation header. Reservation
calls append one batch line containing every newly-accounted route match:

```json
{"kind":"header","version":1,"journal_id":"128-bit-hex","generation":3,
 "created_at":"2026-07-09T12:00:00Z","previous_generation":2,
 "previous_seq":841,"previous_hmac":"hex","hmac":"hex"}
{"kind":"reservation","version":1,"journal_id":"128-bit-hex",
 "generation":3,"seq":42,"ts":"2026-07-09T12:01:00Z",
 "entries":[
   {"component_key":"SENTRYKEYID…","txid":"BASE32…","mvt":0,
    "route":"treasury_usdc","net":"mainnet","unit":"asa:31566704",
    "amount":25000000,"amount_known":true}
 ],"hmac":"hex"}
```

- `mvt` is the index from `ExtractTransferMovements`; a pay+close transaction
  has movement indices 0 and 1.
- A reservation **entry identity** is the structured tuple
  `(component_key, txid, mvt, route, net, unit)`. Do not persist or compare
  delimiter-concatenated keys. This permits one movement to count against every
  matching route while making retries idempotent.
- On retry, `Reserve` partitions proposed entries into already-recorded and new
  identities. Existing entries are no-ops; all new entries are evaluated and
  appended together. A policy change may therefore add a newly matching route
  scope for an already-signed txid without double-counting scopes already
  recorded.
- A duplicate entry represents a previously durable authorization and is not
  re-evaluated against a newly lowered velocity cap. Current stateless sentry
  policy still runs before `Reserve`; the distinction is necessary because a
  prior signature may have been delivered even when the client retries. Tests
  pin this behavior explicitly.
- Velocity is scoped per effective Sentry Key policy in v1:
  - total counter key = `(component_key, route, network, unit)`;
  - count counter key = `(component_key, route, network)`.
  `max_count`-only routes may span asset units and intentionally aggregate those
  units. A route with `max_total` is already constrained to one unit per network.
  Identity-global or cross-Sentry-Key caps require an explicit future grammar
  field; they must not arise accidentally from route-ID collisions.
- Route IDs are durable counter-scope identifiers. Reusing an ID for edited
  route terms preserves that scope's retained history (conservative but possibly
  over-counting); changing an ID starts a new scope. Policy tooling and user docs
  warn about this behavior.
- Counting happens at authorization time. A signed but unsubmitted transaction
  counts until its authorization timestamp leaves the configured rolling
  window; v1 does not query the chain or retain it specifically until
  `LastValid`.
- A record is in a window when `record.ts > now-window`; the exact lower
  boundary is expired. Future timestamps remain in-window, conservatively, until
  wall clock catches up and the normal window passes.

**Canonical encoding and integrity (v1, DECIDED: middle way)**:

- Define header and reservation records as fixed Go structs with no maps.
  Canonical bytes are `encoding/json` output of the corresponding no-HMAC struct,
  using UTC `RFC3339Nano`, validated canonical txid/component-key/network/unit
  strings, bounded entry counts, and a bounded line size. The exact algorithm,
  domain tags, and test vectors are an on-disk contract in ARCH_CONTRACTS.md.
- Header HMAC is over a fixed header domain tag plus the canonical header bytes.
  Reservation HMAC is
  `HMAC(key, previous_hmac || canonical_no_hmac_record)`. Sequence numbers are
  contiguous within one generation.
- The key is a new HKDF derivation from the identity master key (parallel to
  `PolicyIntegrityKeyID`; label `velocity-journal-hkdf-v1`). Derived keys and
  temporary canonical buffers are zeroed where applicable. The store retains
  only its private key copy, zeroes it on `Close`, and relies on the process
  memory-locking boundary used for other in-memory key material.
- Replay verifies the header, journal ID/generation on every record, full chain,
  contiguous sequence, field bounds, and duplicate entry identities. A
  malformed committed line or mid-file corruption is a hard open failure.
- A non-newline-terminated final fragment is treated as an uncommitted append:
  replay verifies the committed prefix, truncates only that fragment, fsyncs,
  and emits a warning/checkpoint. This is safe because `Reserve` never returns
  success before the complete line is fsynced. It remains observable rather than
  enforcement against malicious tail truncation in v1.
- Chaining detects forged/edited records, mid-file deletion, reordering, and
  corruption. It does not enforce against replacement by an older complete
  generation or deletion of the whole journal; Phase 2 remains the enforcement
  upgrade.

**Audit-log velocity checkpoints (v1, best-effort detection layer)**:

- Emit `VELOCITY_CHECKPOINT` with
  `{identity, journal_id, generation, seq, chain_hmac, entry_count, ts, reason}`
  on unlock after replay, before and after compaction/rekey, on close, and every
  100 newly persisted reservation batches or 1h of activity, whichever comes
  first.
- Add corresponding optional fields to `audit.AuditEntry`
  (`velocity_journal_id`, `velocity_generation`, `velocity_seq`,
  `velocity_chain_hmac`, `velocity_entry_count`, `velocity_reason`) rather than
  packing checkpoint authority into a prose details string. Register the new
  event type and document these additive JSONL fields in ARCH_CONTRACTS.md.
- The generation header links compaction/rekey to the prior generation head, so
  a lower post-compaction sequence is not mistaken for truncation.
- `apstore velocity verify` verifies the journal HMAC with the store passphrase,
  then scans `audit.log`, `.1`, and `.2` for matching identity/journal ID. It
  reports `verified`, `discrepancy`, or `inconclusive`; missing/rotated/dropped
  checkpoints are **inconclusive**, never proof that truncation did not occur.
- The command is an offline read/verification operation: require apsigner to be
  stopped, acquire the cooperative store lock, prompt for the passphrase, and
  tolerate no concurrent journal mutation. A future live verifier would belong
  behind an authenticated admin operation, not an unlocked filesystem read.
- Audit writes remain observability, not signing authority. Checkpoint sink
  failure is loudly logged but does not reject an otherwise durable reservation.
  Any actual generation/head discrepancy observed in the field remains the
  empirical trigger for Phase 2.
- Never invoke the audit sink while holding the velocity store mutex. Capture an
  immutable checkpoint under the mutex, release it, then emit, so audit locking
  cannot enter the store lock order.

**Persistence semantics**:

- Under one store mutex, `Reserve` deduplicates entries, evaluates all new entries
  against the replayed counters plus the complete proposed batch, serializes one
  reservation line, appends it, and fsyncs before updating in-memory state and
  returning success. No new entries means success without an append.
- A single batch line gives crash-atomic replay semantics: a complete verified
  line counts, while an incomplete tail never counts. A batch can over-count if
  the process crashes after durable append but before signing; that is the safe
  direction and needs no release path.
- Two concurrent plans that are individually under-cap but jointly over-cap
  cannot both pass. Use overflow-safe comparisons (`amount > max-used`) rather
  than `used + amount`; include `math.MaxUint64` tests.
- Append/write/fsync failure makes the store sticky-failed and returns an error;
  signing maps it to `sentry_policy:velocity_unavailable`.
- Velocity violations include route ID, window, used value, proposed increment,
  and cap in the message while retaining the stable rule IDs below.

**Compaction**:

- Compact on unlock and daily thereafter, stopping the background loop on
  `Close`. Inject `Now func() time.Time` and the compaction trigger for tests.
- Retain the fixed grammar maximum window (`720h`) plus 1h slack, not the current
  policy maximum. This preserves history if a later policy reload lengthens a
  window.
- Under the store mutex, write a new generation to a temp file, link its header
  to the old head, re-chain retained batches, fsync and close the temp file,
  rename it, fsync the parent directory, and reopen the append handle. A crash
  must leave either the old generation or the complete new generation valid.
  Do not assume `WriteConfigAtomic` supplies the required file and directory
  durability without verifying/augmenting it.

**API**:

```go
type Store struct { … } // one per unlocked sentry identity
type CheckpointSink func(Checkpoint) // best-effort audit adapter
type OpenOptions struct { IdentityID, Path string; HMACKey []byte;
                          CheckpointSink CheckpointSink; Now func() time.Time }
func Open(OpenOptions) (*Store, error)              // replay + verify
func Failed(error) *Store                           // sticky unhealthy sentinel
func (s *Store) Reserve([]Reservation) ([]Violation, error)
func (s *Store) Verify() (VerificationReport, error)
func (s *Store) Close() error
type Reservation struct { ComponentKey, TxID string; TargetIndex, Mvt int;
                          RouteID, Network, Unit string; Amount uint64;
                          AmountKnown bool; Limits []policy.VelocityWindow }
```

Fail-closed edges inside `Reserve`:

- `AmountKnown == false` on a movement whose route has any `max_total` window
  produces a violation. `max_count`-only windows still count it.
- A nil, closed, sticky-failed, or unwritable store returns an error; when the
  effective policy contains velocity, signing converts it to
  `velocity_unavailable`. Non-velocity requests do not consult the store.

### B4. Evaluation hook (`internal/signerapp/signing`)

`sentry_policy.go` — add phase 4 to `evaluateSentryComponentPolicy` (line 14),
after existing config/deterministic/per-target lints pass:

```go
// phase 4: velocity (stateful; only after all stateless lints pass)
matches := resolve matches for every plan.Target via policy.ResolveSentryMovementMatches
if anyVelocityConfigured(matches) {
    if s.Velocity == nil { return reject(velocity_unavailable) }   // fail closed
    v, err := s.Velocity.Reserve(toReservations(plan, matches))
    if err != nil { return reject(velocity_unavailable with err context) }
    if len(v) > 0 {
        return s.rejectSentryComponentPolicy(identityID, plan, v)
    }
}
```

- `Service` (service.go:30) gains `Velocity VelocityReserver` next to
  `SentryPolicy`.
- **Nil-store semantics**: a request whose matched routes contain no velocity is
  a no-op. If any matched route contains velocity, a nil/closed/failed store
  rejects. Policy load/reload also logs loudly when any base or override policy
  configures velocity while the runtime store is unhealthy, but unrelated
  non-velocity routes remain available as decided below.
- Rekey targets: no route match ⇒ no velocity in v1. Optionally add
  `rekey_policy.velocity` later; out of scope now (rekeys are already
  edge-allowlisted and shape-constrained).
- Rule IDs (append to `internal/policy/ruleids.go`, grammar-consistent):
  - `transfer_policy:<route_id>:velocity_total`
  - `transfer_policy:<route_id>:velocity_count`
  - `sentry_policy:velocity_unavailable`
- Rejection audit flows through the Part A enriched path automatically.

### B5. Daemon lifecycle wiring (`internal/signerapp/daemon`)

- `identity.Runtime` owns exactly one velocity store reference (or failed
  sentinel) for a sentry identity and exposes a concurrency-safe snapshot to the
  per-request signing-service constructor. Signer-role identities never create
  one. Do not put ownership on the per-request `signing.Service`.
- Add an identity-runtime **pre-unlocked publication hook** invoked by
  `performUnlock` after key reload and verified sentry-policy publication succeed
  but before `signerruntime.TryUnlock` exposes `SignerStateUnlocked`. Open and
  install either the healthy store or failed sentinel there. The existing
  `onUnlocked` callback runs after the state transition and is too late: a signing
  request could otherwise observe unlocked state before velocity is installed.
- Do not open from template `BeforeKeyScan`: a later key reload failure must not
  leak an open store. Ordinary `Reload` and the `ReloadWithPassphrase` used by
  passphrase rotation reuse/replace the owned store explicitly; neither may
  implicitly open another descriptor, replay counters, or start another
  compaction goroutine. If `Lock` wins the unlock-generation race after the hook,
  the existing losing-unlock cleanup must also close/detach the new store.
- A missing journal creates a fresh random journal ID/generation and emits an
  `initialized` checkpoint. In v1 this is intentionally indistinguishable from
  whole-journal deletion and therefore resets counters; the warning and
  best-effort checkpoint expose the event, while the Phase-2 anchor is the
  enforcement fix. A corrupt existing journal never falls back to fresh.
- Derive the velocity HMAC key, call `velocity.Open`, zero the derived key after
  the store has copied/locked what it needs, and install the store atomically.
  The checkpoint sink adapts to the daemon audit logger.
- Open failure does **not** block identity unlock. Install `velocity.Failed(err)`
  instead, emit loud console/audit diagnostics, reject matched velocity routes,
  and allow unrelated non-velocity routes. This makes the `Open` return contract
  consistent with sticky failure behavior. After operator repair, a lock/unlock
  cycle retries open; ordinary policy/key reload does not clear a sticky failure.
- On lock, decommission, shutdown, or replacement after passphrase rotation,
  atomically detach then `Close` the store. `Close` and `Reserve` share the store
  mutex: a request holding an old snapshot either completes its durable reserve
  first or receives a closed/unavailable error. A reserve that succeeds just
  before later key-signing failure remains counted, which is conservative.
- Policy reload recomputes "does any effective base/override policy configure
  velocity" for diagnostics, but counters are shared live state rather than part
  of the policy snapshot. In-flight requests retain their captured policy and
  limit values. Retention is fixed at 721h, so later window enlargement does not
  lose history.
- Add lifecycle lock-order documentation and race tests covering Reserve versus
  lock, decommission, reload, and Close. Do not introduce a new store mutex edge
  that violates the repository lock hierarchy.

### B6. Passphrase rotation and backup/recovery

**Passphrase rotation is required in v1**, because `changepass` replaces the
identity master key:

- Extend the existing `internal/storepass.Rotate` write-new/verify/swap/rollback
  transaction with a velocity-journal participant. Using `internal/velocity`,
  verify the old journal with the old derived key and stage a new linked
  generation re-HMACed with the new derived key.
- For online rotation, quiesce `Reserve` under the store mutex, close the append
  handle, include the staged journal in the same pending-file swap as `.keystore`
  and policy/node-role sidecars, then reopen/publish the new generation. Rollback
  restores and reopens the old generation. Offline `apstore changepass` uses the
  same journal implementation.
- Any verification, staging, swap, reopen, or post-swap reload failure follows
  the existing rotation failure/rollback contract; a successful passphrase
  change must never leave a journal authenticated only by the old master key.
- Emit pre/post-rekey checkpoints with the same journal ID and incremented
  generation. Zero both derived velocity keys.

**Managed backup and recovery semantics**:

- `backup create all` includes a mutex-consistent, verified forensic copy at
  `velocity/velocity.jsonl` when present, and records the journal ID/generation/
  head in the backup manifest. Address-selective backups omit the identity-wide
  journal rather than leaking other Sentry Key activity or attempting to slice
  an HMAC chain. The source master key verifies the copy before archive
  publication. Deep verification checks the HMAC when the source key is
  available; standalone archive verification can validate archive integrity and
  format but reports source-journal HMAC authenticity as unavailable.
- The archived journal is source-store provenance and is **not automatically
  installed by restore/rebuild**, just like archived policy is not blindly
  installed. Its HMAC is bound to the source master key, and restoring an older
  counter snapshot could roll limits back.
- Restoring keys into an existing identity leaves that identity's live journal
  untouched. A replacement-keystore rebuild or mnemonic-only recovery creates a
  new master key and therefore starts a new journal/counter epoch on first
  sentry unlock. `apstore rebuild`, the unlock checkpoint (`reason: initialized`),
  and user docs must call this a security-relevant velocity reset, not transparent
  continuity.
- A cold standby preserves counters only when activated from a consistent full
  data-root snapshot containing `.keystore`, policy, and velocity journal. Key
  mnemonic recovery preserves signing availability but resets velocity history
  in v1. Phase 2 adds the gated reset/import workflow needed for stronger
  continuity guarantees.

### B7. Phase-2 head sidecar: DEFERRED, with named triggers

The enforcement upgrade (atomic `velocity.jsonl.head` sidecar storing
`{journal_id, generation, seq, chain_hmac}`; head-ahead-of-journal ⇒ sticky
fail-closed) is deferred.
It ships as a **complete unit** — sidecar + "velocity-was-initialized" anchor
in an already-integrity-protected location + passphrase-gated, audited
`velocity reset` operator command — never piecemeal. Rationale recorded:
enforcement converts legitimate ops (partial restores, snapshot skew) into
lockouts and, without the anchor, deleting both files bypasses it anyway.

Any ONE of these triggers pulls it in:

1. **Third-party / asymmetric sentry deployment** (collaborative custody,
   sentry-as-a-service, corridor counterparty running its own sentry) —
   counters become a contract between parties. Same trigger as the guarded
   timelock-recovery template variant; ship together as the "third-party
   sentry" package.
2. **A future separately designed tenant product** — counter reset would gain
   cross-tenant blast radius. This is not a trigger to retain tenant switches,
   per-client tokens, or per-client revocation in the single product.
3. **Assurance/compliance demand** — an auditor or institutional customer asks
   "what prevents an administrator from resetting the limits?".
4. **Write-access set outgrows key-custody set** — sentry moves onto shared or
   orchestrated infrastructure (config management, k8s, hosted ops) where
   filesystem writers were never meant to hold spending authority.
   Plus the empirical tripwire: any checkpoint-vs-journal discrepancy observed
   in the field.

### B8. Deployment constraint (docs)

Velocity v1 assumes **one live sentry node per sentry key**. Hot replicas
holding the same key would keep independent counters and multiply every cap.
Document in ARCH_SENTRY.md (deployment note) and USER docs: replicas require
either shared counter state or statically split caps. A consistent full-data-root cold standby can
preserve counters; mnemonic-only recovery resets them as described in B6.

### B9. Formal model and architecture contracts

Velocity changes sentry policy from a one-shot predicate to a state transition.
Add `FORMAL_VELOCITY_MODEL.md` and a small bounded TLA+ module (or extend the
guarded-signing companion only if that remains clearer) covering:

- accepted velocity-bearing sentry output implies a durable reservation;
- an accepted reservation never moves any applicable total/count above its cap;
- concurrent reservations serialize, so two individually admissible batches
  cannot jointly exceed a cap;
- retrying the same structured entry identity consumes capacity once;
- failed/unavailable state cannot produce a velocity-bearing sentry signature;
- replay of a valid committed prefix reconstructs the same retained counters.

Update `FORMAL_GUARDED_SIGNING_MODEL.md` A4 so
`SentryPolicyAllowsAllTargets` includes the successful velocity transition,
and update `FORMAL_LIFECYCLE_MODEL.md` plus its model for the invariant that a
sentry identity cannot publish unlocked state before a healthy/failed velocity
owner is installed. Then add implementation/test anchors to
`FORMAL_TRACEABILITY.md`. Add the new module to `make formal-test` and record its
state/depth metrics under the normal formalization discipline.

---

## Rule ID summary (new)

| Rule ID | Meaning |
|---|---|
| `transfer_policy:<route_id>:velocity_total` | Window cumulative amount would exceed `max_total` |
| `transfer_policy:<route_id>:velocity_count` | Window authorization count would exceed `max_count` |
| `sentry_policy:velocity_unavailable` | Velocity configured but store nil/failed/unwritable/corrupt |

## Testing plan

Unit:

- `internal/policy`: grammar parse/validate (window bounds, duplicate windows,
  canonical-duration duplicate detection, zero caps, total-without-unit
  rejection, count-only unit exemption, signer-domain rejection including key
  overrides, `limits_by_network` replacement, override round-trip); resolver
  behavior-preservation against existing eval fixtures; movement indices and
  multiple matching routes; add cases to the shared fixture corpus.
- `internal/velocity`: window boundaries with an injected clock (reject iff the
  proposed value is strictly greater than the cap); `math.MaxUint64` overflow;
  per-component counter isolation; count-only aggregation across units; total
  separation by unit; multi-route entry identities; exact retry idempotency;
  duplicate retry after a cap is lowered remains the prior authorization; retry
  after policy adds a new route scope evaluates only that new scope; group
  atomicity under concurrency (`-race`).
- `internal/velocity` durability: canonical JSON/HMAC vectors; malformed fields,
  duplicate entry identities, chain corruption, mid-file deletion, sequence
  gap, oversized line, unwritable directory, write/fsync failure ⇒ sticky
  failure; incomplete final-fragment recovery; complete-batch crash replay;
  restart preserves counters.
- `internal/velocity` compaction/checkpoints: old-or-new crash safety including
  parent-directory durability; linked generation headers; fixed 721h retention
  followed by a policy-window increase; future timestamps count; no background
  goroutine leak; checkpoints at unlock, close, compaction/rekey, and the
  100-batch/1h cadence with matching journal identity/head.
- `internal/storepass`: online and offline passphrase changes re-HMAC the journal;
  old key fails/new key succeeds; injected stage/swap/reopen/post-reload failures
  restore the old master key and old journal together; concurrent Reserve is
  quiesced; derived keys are zeroed.
- Backup/rebuild: all-key backup captures a verified consistent journal and
  manifest head; address-selective backup omits it; standalone verification
  distinguishes archive integrity from unavailable source-HMAC authentication;
  existing-identity restore leaves it untouched; rebuild does not install the
  source journal and clearly reports the new counter epoch.
- `apstore velocity verify`: prompts for/derives the current master key, agrees on
  an intact journal, flags a synthetic older generation/head, scans all retained
  audit generations, and reports missing checkpoints as `inconclusive` rather
  than verified.
- `internal/signerapp/signing`: phase-4 hook — velocity violations reject with
  correct rule IDs and enriched audit; nil-store + velocity-configured
  matched route rejects; nil-store + no matched velocity passes; unknown-amount
  vs `max_total`; one request matching two routes reserves both.
- `internal/signerapp/identity`/daemon: one store per successful unlock; no
  request can observe unlocked state before healthy/failed store publication;
  `BeforeKeyScan`, ordinary reload, and rotation's `ReloadWithPassphrase` do not
  accidentally open another; losing-unlock, lock, decommission, and Close races
  are clean under `-race`; and an open failure installs the failed sentinel
  without blocking non-velocity work.
- appolicy: velocity YAML round-trips through guided edits untouched;
  `--to-sentry` passes velocity through; validation errors readable.

Integration (localnet, `make integration-test-localnet`):

- New test: sentry policy with `max_count: 2` on a route; first two guarded
  sends succeed, third rejects 403 with `velocity_count` in the reason;
  restart apsignerd (SignerRestart pattern exists) and confirm the cap remains;
  do not sleep for the 1m grammar minimum in integration tests (expiry is covered
  deterministically by injected-clock unit tests).
- Change the sentry store passphrase, restart, and confirm the same cap remains.
- Assert enriched audit entries (txid/type/details) for both approve and
  reject, plus a checkpoint whose journal ID/generation/head verifies.

Gauntlet per standing discipline: `go build -tags testmode ./...`, fmt/vet/
staticcheck/lint via make targets, targeted and full race tests, security
analyzers, `make formal-test`, full integration suite, and no tree mutation
mid-run.

## Commit sequence

1. **Part A** audit enrichment (standalone, immediately useful).
2. **B2 resolver refactor only** (behavior-preserving; no velocity YAML is
   accepted yet, existing eval tests remain green).
3. **B3 dormant `internal/velocity` package**: versioned batch journal, chained
   HMACs, replay, counters, compaction, verification, and unit tests. It is not
   wired and the policy parser still rejects `velocity` as unknown.
4. **B6 operational plumbing while dormant**: passphrase-rotation participant,
   backup snapshot support, storepaths, and tests. No accepted policy can depend
   on it yet.
5. **Atomic activation commit**: B1 grammar/validation + B4 evaluation hook + B5
   runtime ownership/lifecycle + rule IDs + checkpoint audit fields/event +
   `apstore velocity verify`. There must never be a buildable commit that accepts
   `velocity` YAML but silently ignores it.
6. Integration tests and the full contract/doc update in the same PR before
   merge: ARCH_SPEC.md, ARCH_POLICY.md, ARCH_SENTRY.md, ARCH_CONTRACTS.md,
   ARCH_DATA_MODEL.md, ARCH_DATA_CATALOG.md, ARCH_SECURITY.md,
   FORMAL_GUARDED_SIGNING_MODEL.md, FORMAL_LIFECYCLE_MODEL.md,
   FORMAL_VELOCITY_MODEL.md, FORMALIZATION_ROADMAP.md, FORMAL_TRACEABILITY.md,
   formal metrics/run lists, USER_TRANSFER_ROUTING.md, USER_LOGGING.md, and
   backup/recovery user docs.
7. (Deferred until a B7 trigger fires) Phase-2 enforcement unit: head sidecar
   + initialized-anchor + `velocity reset` command. Additive thanks to
   day-one chaining. Policy dry-run tooling (replay journal against draft
   policy) remains a natural independent follow-on once the journal exists.

## Explicit non-goals (v1)

- No client-signing-domain velocity (human review tier covers it there).
- No rekey velocity (already edge-allowlisted + shape-constrained).
- No shared/replicated counter state; single-live-sentry documented instead.
- No identity-global or cross-Sentry-Key cap; v1 scopes counters by component
  key and route. Add an explicit grammar field later rather than coupling keys
  through coincidentally equal route IDs.
- No on-chain anything: sentry1, TEAL, wire, SDKs untouched.
- No claim that mnemonic/rebuild recovery preserves counters; only a consistent
  full-data-root standby does so in v1.
- No identity-wide (route-less) global caps in v1 — velocity attaches to
  routes. A per-Sentry-Key broad cap can be approximated with a catch-all route;
  an identity-global cap needs an explicit future scope field.

## Resolved decisions

1. **Boundary semantics:** reject when the proposed value is strictly greater
   than the cap, consistent with `reject_above`; implement with overflow-safe
   subtraction rather than unchecked addition.

   **Decision: yes.**

2. **Journal location:** use the flat
   `identities/<identity>/velocity.jsonl` path with temp-file compaction in the
   same directory.

   **Decision: yes.**

3. **Phase-2 head sidecar:** defer enforcement until a B7 trigger.

   **Decision: middle way.** Ship chained HMACs, generation linkage,
   best-effort `VELOCITY_CHECKPOINT` events, and offline verification in v1.
   Missing checkpoints are inconclusive. The later enforcement unit is sidecar
   + initialized anchor + reset/import command.

4. **Window bounds:** `[1m, 720h]`.

   **Decision: yes.** Compaction retains the maximum 720h plus 1h slack so a
   later policy enlargement does not invent an empty history.

5. **Counter scope:** isolate by Sentry Key ID, route, and network; additionally
   isolate totals by unit. Counts intentionally aggregate units only for
   count-only routes.

   **Decision: yes.** Identity-global caps require future explicit grammar.

6. **Recovery:** managed backups retain a forensic source-journal copy, but
   restore/rebuild does not automatically install it. Full-data-root standby
   preserves history; mnemonic/new-master-key recovery begins a new counter
   epoch and must say so explicitly.

   **Decision: yes for v1.** Strong rollback-resistant import/reset belongs to
   the complete Phase-2 operator workflow.

7. **Rolling-window boundary:** timestamps exactly equal to `now-window` are
   expired; timestamps greater than that boundary count, including future
   timestamps after a clock regression.

   **Decision: yes.** Tests use an injected clock and cover exact-boundary,
   one-nanosecond-inside, and future-record cases.
