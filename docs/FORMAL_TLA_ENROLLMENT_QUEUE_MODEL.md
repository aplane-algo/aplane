# Client Enrollment Queue Machine-Checkable Model

> Status: TLC checked with `Keys = {k1, k2, k3}` and `MaxPending = 2` under
> key symmetry; the recorded positive run generated 2,340 distinct reachable
> states at depth 11 with no counterexamples, and the deep run
> (`enrollment_queue_deep.cfg`, four keys, `MaxPending = 3`) 12,168 distinct
> states at depth 15. The expected-failure negative control
> (`enrollment_queue_negative.cfg`, `RequireDurableAck = FALSE`) violates
> `EQ2_PendingAckSurvivesCrash` after 167 distinct states at depth 3 and must
> keep producing that exact counterexample.

This model checks the two daemon-written documents that decide which SSH
client keys may connect: the enrolled-key registry
(`identities/default/.ssh/authorized_keys`) and the pending-enrollment queue
(`pending_enrollments.json`). A client's enrollment request is answered at
once and waits on disk for the operator; every change to either document is
one atomic, durable publish that can fail before or after its rename. The
model is about what the node may tell a client, audit, or act on when such a
write fails, and what a crash can then take back.

The spec lives at [formal/enrollment_queue.tla](formal/enrollment_queue.tla).

## What it covers

| Invariant | Meaning | TLA+ predicate |
|---|---|---|
| EQ1 | No success answer (`pending`, `enrolled`) is given on the strength of a file whose last write did not complete its syncs | `EQ1_NoAckFromUnsyncedFile` |
| EQ2 | A request the client was told is pending stays in the queue across a crash, until the operator answers it or it lapses | `EQ2_PendingAckSurvivesCrash` |
| EQ3 | A key the client was told is enrolled stays in the registry across a crash, until it is revoked | `EQ3_EnrolledAckSurvivesCrash` |
| EQ4 | Every enrolled key was audited `CLIENT_ENROLLED`, including keys whose registry write was applied but not durable | `EQ4_EnrolledKeysAudited` |
| EQ5 | The queue never exceeds `MaxPending`; a repeated request refreshes its entry instead of adding one | `EQ5_QueueBounded` |
| EQ6 | Rejecting never drops the request of a key that is already enrolled | `EQ6_RejectNeverStrandsEnrolledKey` |

## What TLC actually verifies

The transitions transcribe `internal/signerapp/productruntime/runtime.go`
and the packages around it:

- A publish has three outcomes, from `fsutil.WriteFileDurable` as classified
  by `publishRegistryFileLocked` and `publishQueueFileLocked`: `ok` (renamed
  and synced), `early` (failed before the rename; the file holds the old
  document), and `late` (failed after the rename; the file holds the new
  document, which may not survive a crash). In every case the live view is
  whatever the file holds, so the model has one variable per document, plus
  the content known to be durable and a synced flag.
- `RequestEnrolled` and `RequestQueued` are `QueueEnrollment` and
  `enrollment.Service.Request`: the `already enrolled` answer waits for the
  registry to be synced, a queued request is answered `pending` only when its
  write completed, and a late failure records the request (the operator can
  act on it, and it is audited and announced) but answers the client with an
  error so it retries. The retry refreshes the entry and is acknowledged only
  once a sync has succeeded.
- `Approve`, `Reject`, `Import`, and `Revoke` are `ApproveEnrollment`,
  `RejectEnrollment`, `ImportClientKey`, and `RevokeAuthorizedKey`. Approval
  publishes the registry before the queue; a key that reached the live
  registry is audited whether or not the write was durable, and only an early
  registry failure leaves the request untouched. Rejection refuses a request
  whose key is enrolled (`ErrAlreadyEnrolled`). Import follows the same
  registry-before-queue rule as approval. Each operation first
  re-publishes a file left unsynced by an earlier failure
  (`ensureRegistryDurableLocked`, `ensureQueueDurableLocked`), modeled as the
  `ResyncRegistry` and `ResyncQueue` actions that gate the operations.
- `Crash` is a restart: each file comes back as either what it last held or
  what was last durable, and `LoadAuthorizedKeys` and `LoadEnrollmentQueue`
  read both as the state of record. `Lapse` is `enrollqueue.TTL`.

EQ1 and EQ6 are mutation-sensitive history flags. `ackedUnsynced` is set by
a success answer whose file is not synced; it stays `FALSE` only because
`RequestEnrolled` waits for the registry and `RequestQueued` acknowledges
only an `ok` write. `rejectedEnrolled` is set by a rejection of an enrolled
key's request; it stays `FALSE` only because of the `k \notin reg` check.
Dropping either guard flips its flag and TLC reports a `Safety` violation.

The negative control is a first-class run: with `RequireDurableAck = FALSE`,
`RequestQueued` answers `pending` on a late-failed write, `Crash` reverts the
queue to its durable content, and EQ2 fails in three steps: the client holds
a promise the node no longer has. The harness
(`scripts/run-formal-tests.py`) requires exactly that
`EQ2_PendingAckSurvivesCrash` violation, so the durable-acknowledgement rule
cannot silently stop being load-bearing.

## Modeling choices and limits

- Keys stand for client public keys by fingerprint; labels, remote
  addresses, timestamps, and queue order are not modeled. One entry per key
  is therefore structural (`queue` is a set).
- "The view follows the file" is modeled by construction: a single variable
  is both. The code property that makes this sound, a failed publish
  reloading the file and installing whatever it holds, is pinned by
  `TestRevokeAuthorizedKeyFailedPublishDoesNotRetainStaleAuthority` and
  `TestRejectEnrollmentFailedPublishResyncsQueue`.
- A file that is unreadable after a failed publish (the runtime then serves
  an empty registry or queue until it is repaired) is not modeled: the
  rename-based write leaves the file holding the old or the new document,
  never a torn one.
- `Lapse` removes an entry from the live and durable contents together,
  since every reader (`Parse`, `Pruned`) drops lapsed entries; the on-disk
  bytes are rewritten at the next publish.
- Revocation closing the key's live tunnels, the SSH-side caps on
  `request-enrollment` connections and channels, and the apadmin
  notification of a new request are outside the model; the first is covered
  by `internal/sshtunnel` tests, the caps by
  `internal/sshtunnel/enrollment_bounds_test.go`.
- The model is safety-only. Operator answers are choices and carry no
  fairness; a request's only guaranteed exit is `Lapse`.

## How to check

```sh
make formal-test
make formal-test-deep
```

For the focused runs:

```sh
java -jar tla2tools.jar -config docs/formal/enrollment_queue.cfg \
  docs/formal/enrollment_queue.tla
java -jar tla2tools.jar -config docs/formal/enrollment_queue_negative.cfg \
  docs/formal/enrollment_queue.tla
```

The negative run is expected to fail with an `EQ2_PendingAckSurvivesCrash`
counterexample; the make harness asserts that expectation.

## Linking back

- Architecture: [ARCH_SECURITY.md](ARCH_SECURITY.md) ("Client Enrollment
  via SSH") and [ARCH_STORE_OWNERSHIP.md](ARCH_STORE_OWNERSHIP.md).
- Traceability: the Client Enrollment section and the Enrollment queue
  module section in [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).
- Concrete tests: `internal/signerapp/productruntime/client_registry_test.go`,
  `internal/signerapp/enrollqueue/queue_test.go`,
  `internal/signerapp/enrollment/service_test.go`, and
  `internal/signerapp/daemon/enrollment_test.go`.
