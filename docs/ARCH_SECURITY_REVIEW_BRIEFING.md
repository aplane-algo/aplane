# Architecture Security Review Briefing

## Purpose

This briefing evaluates six security and liveness observations about the
current APlane architecture. It distinguishes implementation defects from
documented limitations, explains the relevant trust boundaries, and describes
what a correction can and cannot accomplish. It is not an implementation plan.

The six observations are:

1. signed simulation discloses executable transaction groups to algod;
2. admin idle expiration depends on cooperative client behavior;
3. restore historically activated keys without a distinct policy-transition gate;
4. policy reload failure is fail-stale with respect to operator intent;
5. the bounded1 fee ceiling can become a liveness fuse; and
6. bounded1 provides transaction-local, not group-wide, semantic containment.

All six concerns are addressable; observation 3 is corrected by the direct
credential-restore boundary described below. The first four can be corrected in the
runtime, configuration, storage, and administrative surfaces. The final two
involve immutable LogicSig semantics: stronger guarantees can be provided for
new accounts through a new contract or profile, but cannot be added
retroactively to existing bounded1 bytecode.

## 1. Signed Simulation And The Algod Trust Boundary

### Prior behavior and finding

The former signer-managed ordinary and guarded simulation endpoints created
fully executable signatures, skipped ordinary review and operator approval, and
sent the signed group to signer-configured algod while withholding it from the
client response. That protected only the client API boundary. A malicious or
compromised algod could submit the reusable group during its validity window.
Claims that the bytes never left apsigner were therefore incorrect.

An explicit trusted-algod designation could have reduced accidental exposure,
but it would not have repaired the more fundamental mismatch: a request labeled
as simulation was producing real authorization under weaker approval semantics.
Trust would also have been an operator assertion rather than a property that
apsigner could derive from a URL or network topology.

### Corrected boundary

Apsigner no longer exposes simulation endpoints or a simulation-only signing
mode. Full simulation follows the ordinary executable path:

1. the client verifies that its algod connection is available;
2. apsigner applies normal policy, review, operator approval, signing, and audit
   behavior through `/sign` and, for guarded groups, `/sign/component` plus
   `/sign/assemble`;
3. apsigner returns the executable signed group to the client; and
4. the client sends those exact bytes to its configured algod simulation
   endpoint instead of the submission endpoint.

Apsigner cannot know or safely rely on the client's eventual routing decision.
The same authorization is therefore required whether the client later
simulates, submits, stores, or discards the group. Audit events record signature
authorization and release, not chain submission or commitment.

### Security significance

This removes the omitted signer-to-algod trust boundary and the simulation
approval bypass. It does not make signed simulation non-executable: the client
and its selected algod receive network-submittable bytes that remain valid
until expiry. Client documentation must state that fact, and guarded headless
simulation now requires the same user auto-approval configuration as guarded
headless submission.

Unsigned `/plan` remains available for canonical group inspection without key
access or approval. It is not equivalent to full LogicSig execution and is not
a substitute for signed simulation.

### Fixability

This concern is corrected by removing signer-owned simulation and making
simulation a post-signing client routing choice. No trusted-algod designation
is needed in apsigner because apsigner no longer contacts algod for simulation.

## 2. Server Ownership Of Admin Session Expiration

### Corrected behavior

The configured `passphrase_timeout` is implemented as an apadmin-local idle
disconnect timer. Keyboard input rearms the timer. When the timer expires,
apadmin closes its authenticated admin connection. Apsigner then observes the
disconnect and applies its signer-owned `lock_on_disconnect` setting, which may
lock the product runtime and clear the term-key session.

The signer therefore owns the lock transition and key zeroing, but it does not
own the event that normally initiates idle expiration. As long as the
authenticated admin connection remains open, the local keyboard-idle timeout
does not independently force a server-side transition.

### Security significance

The intended expiration property depends on a cooperative apadmin client. A
crashed client may leave transport behavior dependent on operating-system
connection detection. A modified or malicious client can deliberately retain
the connection and avoid the client-side timer entirely.

This means `passphrase_timeout` is not currently a hard upper bound on an
unlocked product runtime or authenticated admin session. It is a UX-driven idle
disconnect policy implemented by the reference client.

Moving last-activity tracking to the signer is necessary but not sufficient if
the threat model includes a malicious client. The signer can observe protocol
traffic, but it cannot prove that a human generated that activity. A malicious
client can send keepalives or harmless requests to defeat a protocol-idle
timer just as it can defeat a local UI timer.

### Correctable boundary

The signer can enforce security properties that do not depend on claims of
human activity:

- an absolute authenticated-session lifetime;
- an absolute unlock or term-key lease;
- a server-observed protocol-inactivity timeout;
- forced closure of expired sessions;
- cancellation of pending approvals on expiration; and
- a signer-owned lock transition when the final owning session expires.

An absolute lifetime or unlock lease is the strongest correction because
client-generated traffic cannot extend it indefinitely. Renewal should require
reauthentication or another explicit signer-approved ceremony rather than an
activity notification.

The existing apadmin keyboard-idle timer remains useful. It can disconnect
sooner when the reference UI is abandoned and gives immediate local feedback,
but it should be described as a convenience layered on top of server-owned
limits.

Headless operation needs separate semantics. Current headless configurations
intentionally disable idle locking so unattended signing can continue. A
server-owned lease design must preserve that explicit operating mode rather
than applying interactive-session assumptions silently.

### Fixability

This is fully correctable in the admin-session and product-runtime lifecycle. The
important limitation is conceptual: the signer can enforce time and protocol
activity, but cannot securely infer human keyboard activity from an untrusted
client.

## 3. Restore And Effective Authorization Transitions

### Corrected behavior

Managed backups contain complete encrypted credential records and no source
policy, approval settings, templates, or operational configuration. Restore
preview exposes credential selectors, key types, and destination conflicts.
Apply authenticates and validates the whole selected set before any write;
replacement of a different or unreadable destination credential is a separate
explicit option.

The server commits restore by minting a complete new generation and
flipping the `CURRENT` pointer in one durable rename; the outgoing generation
is sealed first and remains the exact rollback target. Reload failure rolls
the pointer back to it; an interrupted attempt leaves no committed state, and
a commit with unconfirmed durability blocks signing in recovery mode until
reconciliation.

### Security significance

Credential restoration and policy migration are deliberately separate.
Restoring a native spending key, or a LogicSig whose intrinsic program is less
restrictive than the source signer policy, into a more permissive destination
can widen effective authority. The operator owns that decision; the archive
does not carry source policy or claim to reproduce source security posture.

### Implemented boundary

A restore authenticates and validates the complete archive before publishing
one generation:

```text
archive -> validate credentials -> atomic generation -> reload
```

Credentials do not enter the runtime index until the generation commit and
successful reload. Reload failure rolls the pointer back to the sealed parent;
uncertain durability enters recovery mode. The apadmin TUI and batch client use
the same server operation. Restore intent/outcome and rollback
carry structured audit events with product-runtime, principal, session, transport,
operation ID, archive SHA-256, and generation ID.

### Resolution status

Implemented in admin protocol v5. Earlier internal backup formats and recovered
batch operations are unsupported because this is the first supported release.
Offline `apstore rebuild` remains an explicitly separate, absent-store rescue
path.

## 4. Policy Reload Failure: Fail-Closed And Fail-Stale

### Current behavior

Policy reload verifies schema, role-specific policy constraints, and the policy
integrity sidecar. If verification fails, the replacement policy is rejected
and the previous in-memory policy remains active when one exists. This avoids
publishing malformed or unauthenticated policy and keeps in-flight/runtime
readers on a coherent last-known-good snapshot.

The architecture currently describes this behavior as fail-closed. Runtime
health and status do not expose a durable policy-reload failure state. An
unlocked product runtime with a retained policy can continue to report ready for
signing.

### Security significance

The behavior is fail-closed with respect to the invalid candidate: malformed
or unauthenticated bytes never become active policy. It is fail-stale with
respect to operator intent: an attempted restriction or revocation did not
take effect, and the old policy continues authorizing requests.

This distinction matters most when the active policy is permissive and the
failed replacement was intended to tighten it. The signer preserves service
availability but may continue unattended or auto-approved signing under rules
the operator attempted to revoke.

Calling the entire behavior simply "fail-closed" hides that operational state.
Neither term is sufficient alone; the architecture should state the object of
the failure explicitly: candidate policy admission fails closed while active
authorization remains last-known-good and therefore stale.

### Correctable boundary

The runtime can retain last-known-good policy while recording a durable
degraded condition that includes:

```text
policy_reload_status: failed
active_policy_digest: <last-known-good>
disk_policy_status: invalid
reload_failure_time: <timestamp>
reload_failure_reason: <sanitized reason>
```

Health, status, apadmin, and audit output should surface this state. A strong
production default would suspend unattended and auto-approved signing while
allowing administration, policy repair, explicit lock operations, and a
carefully defined manual recovery path. Successful verified reload should
clear the condition. An acknowledgement mechanism may permit an operator to
continue deliberately under the retained policy, but the acknowledgement must
itself be durable and audited.

Not every reload failure needs identical treatment. Role-conflicting inventory
already closes the node more aggressively, while ordinary rejected artifacts
may be excluded as diagnostics. The degraded-state contract should distinguish
policy/config staleness from inventory contradictions and per-item rejection.

### Fixability

This is fully correctable in runtime state, health/status DTOs, audit records,
and signing gates. No policy file format change is required.

## 5. Bounded1 Fee Ceiling And Long-Term Liveness

### Current behavior

Bounded1 compiles an absolute maximum per-transaction fee of 10,000
microAlgos. The framework requires LogicSig budget dummy transactions for large
Falcon programs and pools their minimum-fee cost onto protected LogicSig
transactions.

The audited maximum rekey-locked allowlist profile requires an eight-entry
group for its largest spend and admin paths. With one protected LogicSig
transaction, the required pooled fee is eight times the network minimum fee.
The current ceiling is therefore viable only while the minimum fee is at most
1,250 microAlgos. The planner correctly rejects combinations that cannot fit
under the compiled ceiling.

The fee assertion runs before spend/admin routing, so the same ceiling applies
to the external contract-admin rekey path. Current planning does not provide a
separate external fee sponsor that can absorb the dummy budget without raising
the protected transaction's planned fee.

### Security significance

Rejecting an unaffordable group is safe failure, but it can permanently strand
an immutable account. If network minimum fees rise beyond the profile's viable
threshold, ordinary spending can stop. More importantly, the external
contract-admin rekey escape path can stop at the same threshold, removing the
mechanism intended to recover from spending-key compromise or policy
obsolescence.

This is not an immediate Algorand compatibility defect. It is a long-term
liveness dependency compiled into immutable authorization bytecode. Monitoring
can warn before the threshold, but cannot recover an account after every
available rekey path has become nonviable.

### Correctable boundary

New contract/profile designs can provide one or more of the following:

- distinct fee ceilings for ordinary spending and emergency admin rekey;
- a compact emergency rekey path requiring fewer budget dummies;
- a planner-supported, contract-constrained external fee sponsor;
- a deliberately larger admin-path fee allowance; and
- generation-time liveness analysis against current and stress-case network
  parameters.

Operational monitoring should report remaining minimum-fee headroom and warn
well before a configured migration threshold. Monitoring is necessary for
existing accounts but is not a substitute for a structurally viable escape
path in future profiles.

### Fixability And Retroactivity

This is fixable for newly generated accounts through a new bounded contract or
profile. Existing accounts cannot receive a larger fee allowance without
changing their LogicSig program and therefore their authorizer address.

Existing accounts must migrate through a currently viable rekey path before
network parameters cross their compiled limit. Once all authorized paths are
nonviable, an off-chain software update cannot override the on-chain LogicSig.

## 6. Transaction-Local Versus Group-Wide Containment

### Current behavior

Bounded1 classifies and constrains each protected transaction. It admits a
closed set of direct effects, rejects hybrid danger fields, caps the protected
transaction's fee, and applies Layer 3 policy to the protected transaction.

The contract does not constrain the complete atomic group. A protected payment
or asset transfer can coexist with unrelated transactions, including entries
authorized by other parties. Bounded1 does not generally assert exact group
size, ordering, authorizer identities, absence of application calls, or a
complete semantic shape for non-protected entries.

This limitation is already stated in the bounded architecture: bounded1
guarantees each protected transaction's envelope, not group-wide semantic
safety.

### Security significance

Transaction-local containment is still meaningful. A protected account cannot
directly exceed its allowed payment or asset-transfer envelope merely because
another transaction appears in the group. Atomic grouping, however, can couple
that direct movement to unrelated application calls, transfers, or other
economic effects.

Descriptions such as a "closed transfer mesh" are accurate only for direct
movements made by the protected transactions. They should not be interpreted
as proving that every arbitrary atomic group containing those movements is
economically benign or free of application-mediated effects.

This is a documented scope boundary rather than an implementation violation of
the current bounded1 contract.

### Correctable boundary

A future high-assurance profile can define a versioned group contract covering:

- exact or maximum group size;
- allowed transaction types by position;
- allowed senders and effective authorizers;
- ordering constraints;
- whether application calls are forbidden or restricted;
- permitted fee-sponsor transactions; and
- exact canonical shapes and positions for LogicSig budget dummies.

Those constraints must account for APlane's budget expansion and multiparty
group workflows. They should be represented in canonical profile metadata,
compiled into TEAL, enforced by signer planning, and tested as one coherent
group-shape contract rather than added as isolated checks.

### Fixability And Retroactivity

This is fixable for new accounts through a new versioned bounded contract or
profile. It cannot be added to an existing bounded1 LogicSig without changing
the program and address. Existing bounded1 accounts continue to provide
transaction-local containment, and documentation must preserve that limitation
prominently.

## Overall Assessment

The first two findings concern trust-boundary ownership and should be treated
as the most immediate security corrections. Credential restore and policy
reload status are administrative-state problems that can be corrected without
changing cryptographic formats. The fee-liveness and group-containment issues
belong together in the design of a successor bounded contract because both
affect immutable on-chain semantics and require an explicit migration story.

The central documentation correction is to qualify security claims by their
actual boundary. "Never leaves the signer," "idle timeout," "restore," and
"fail-closed" each currently compress multiple distinct properties. Naming
the protected object, enforcement owner, and retained authority makes those
claims testable and prevents operational assumptions from becoming stronger
than the implementation.
