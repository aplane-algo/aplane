// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/stagetable"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Recovery of a rotating account's live stage.
//
// The stage table worker classifies every observed authorizer before it
// derives anything: stage 0, a stage already in the table, or a credential
// this signer holds each resolve the observation on their own. Only an
// authorizer that is none of those is unknown, and only an unknown
// authorizer is searched for, under a grant.
//
// A grant is one bounded search. The worker starts an automatic grant from
// the account's per-unlock allowance (rotating.recovery_max_stages, counted
// from the table's edge, never replenished within the unlock); an operator
// starts one explicitly with its own stage budget, optionally with a stage
// hint. At most one grant is active per account. Prepares are not grants:
// they run their own bounded discovery and charge nothing.
//
// Session ownership. Every operation on this memory belongs to one
// unlocked session, identified by the lock runtime's generation: a counter
// every lock and maintenance transition advances under the runtime's own
// mutex and an unlock leaves unchanged. An operation captures its session
// once, when it starts (the worker pass together with the context a lock
// cancels; an operator request at entry), and carries it into every call.
// The memory holds a live reader of that generation and, under its own
// mutex, on every entry: rebinds to the live generation if it moved,
// discarding everything of the session that ended, and then admits the
// caller only if its session is the live one. So the rule is stated once
// and enforced in one place: an operation is invalid from the moment the
// runtime's generation differs from the one it captured, whether or not
// anything else has observed the new session, and a lock that lands right
// after an operation was admitted simply ends the session it was admitted
// to, which the next entry discards.
//
// The credential generation, represented by the stage table handle a grant
// derived into, owns the results: a replaced credential invalidates the
// grant, but what it already charged stands against the session's
// allowance.

// AuthorizerClass is the worker's reading of an observed authorizer.
type AuthorizerClass string

const (
	// ClassStage: the authorizer is stage 0 or a stage in the table.
	ClassStage AuthorizerClass = "stage"
	// ClassHeldKey: the authorizer is a credential this signer holds. The
	// account was rekeyed away from its rotating stages; no stage is
	// searched for.
	ClassHeldKey AuthorizerClass = "held_key"
	// ClassUnknown: not a stage this signer has derived and not a key it
	// holds. A bounded search may still find the stage.
	ClassUnknown AuthorizerClass = "unknown"
)

// classifyAuthorizer applies the ladder: stage 0, table, own inventory,
// unknown. The stage 0 rule runs first because a self-bound account's own
// address is also one this signer holds. (An exit record, once the rotating
// exit exists, slots in between the table and the inventory.)
func classifyAuthorizer(table *stagetable.Table, account, authorizer types.Address, held map[string]bool) (uint64, AuthorizerClass) {
	if stage, ok := resolveStage(table, account, authorizer); ok {
		return stage, ClassStage
	}
	if held[authorizer.String()] {
		return 0, ClassHeldKey
	}
	return 0, ClassUnknown
}

// GrantKind says who granted a search.
type GrantKind string

const (
	GrantAutomatic GrantKind = "automatic"
	GrantOperator  GrantKind = "operator"
)

// Stop reasons, as reported in status.
const (
	StopFound              = "found"
	StopAllowanceExhausted = "allowance exhausted"
	StopBudgetExhausted    = "stage budget exhausted"
	StopTimedOut           = "timed out"
	StopCancelled          = "cancelled"
	StopSuperseded         = "superseded by operator"
	StopAuthorizerChanged  = "authorizer changed"
	StopCredentialReplaced = "credential replaced"
	StopHintNotFound       = "hint not found within window"
	StopResolved           = "resolved by observation"
	StopHeldKey            = "account is rekeyed to a held key"
)

// Defaults for an operator grant.
const (
	DefaultOperatorRecoveryStages  uint64        = 4096
	DefaultOperatorRecoveryTimeout time.Duration = 5 * time.Minute
	DefaultRecoveryHintWindow      uint64        = 64
	// MaxRecoveryHintWindow bounds how far a hinted search probes around
	// the hint before it is called wrong; a probe is one derivation.
	MaxRecoveryHintWindow uint64 = 4096
)

// RecoveryGrant is one bounded search for an account's live stage. Fields
// are read and written only under RotatingRecovery's lock; the worker gets
// copies through Snapshot.
type RecoveryGrant struct {
	ID         uint64
	Kind       GrantKind
	Epoch      uint64
	Account    string
	Authorizer types.Address // the observed authorizer sought; zero until the worker observes
	MaxStages  uint64        // stages this grant may derive
	Timeout    time.Duration // active-time cap
	Hint       *uint64       // operator stage hint, if any
	Window     uint64        // hint probe radius
	StartedAt  time.Time

	table *stagetable.Table // credential generation the grant derives into

	Charged uint64        // derivations charged to this grant
	Active  time.Duration // time spent deriving for this grant
	// Found is the hinted stage once a probe matched the authorizer; the
	// grant's remaining work is filling the table up to it.
	Found     *uint64
	nextProbe uint64 // probes issued so far: 0 = hint, then +1, -1, +2, -2 …
	cancelled bool
}

// RecoveryStop records why the last grant ended.
type RecoveryStop struct {
	GrantID uint64
	Kind    GrantKind
	Reason  string
	Charged uint64
	Stage   *uint64 // the stage found, when Reason is StopFound
	At      time.Time
}

// RecoveryState is one account's recovery status, snapshotted for status.
type RecoveryState struct {
	Grant          *RecoveryGrant // active grant, copied; nil when idle
	Last           *RecoveryStop
	AllowanceSpent uint64
	AllowanceMax   uint64
	// Suppressed is the authorizer for which automatic recovery has been
	// exhausted in this unlock; zero when none.
	Suppressed types.Address
}

// RotatingRecovery is the process memory of rotating stage recovery: the
// per-unlock allowance, the active grant and the last stop per account. It
// is observational and operational state only; it never changes what the
// signer signs. See "Session ownership" above.
type RotatingRecovery struct {
	mu sync.Mutex
	// generation reads the runtime's live lock generation; nil means a
	// single unending session (tests without a runtime).
	generation func() uint64
	epoch      uint64
	nextGrant  uint64
	accounts   map[string]*recoveryAccount
	// MaxStages is the automatic per-unlock allowance per account; 0
	// disables automatic recovery. Timeout caps one automatic grant's active
	// time. Both are set by the daemon from configuration.
	MaxStages uint64
	Timeout   time.Duration
}

type recoveryAccount struct {
	spent      uint64
	suppressed types.Address
	grant      *RecoveryGrant
	last       *RecoveryStop
}

func (r *RotatingRecovery) account(account string) *recoveryAccount {
	if r.accounts == nil {
		r.accounts = make(map[string]*recoveryAccount)
	}
	a, ok := r.accounts[account]
	if !ok {
		a = &recoveryAccount{}
		r.accounts[account] = a
	}
	return a
}

// Configure sets the automatic allowance and timeout from configuration. A
// change applies to grants started afterwards.
func (r *RotatingRecovery) Configure(maxStages uint64, timeout time.Duration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.MaxStages, r.Timeout = maxStages, timeout
}

// SetGenerationSource installs the reader of the runtime's live lock
// generation. Idempotent; the daemon calls it whenever it builds the
// rotating dependencies.
func (r *RotatingRecovery) SetGenerationSource(generation func() uint64) {
	if r == nil || generation == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.generation = generation
}

// Session returns the live session an operation starting now belongs to.
func (r *RotatingRecovery) Session() uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.syncLocked()
	return r.epoch
}

// syncLocked rebinds the memory to the runtime's live generation if it has
// moved since the last entry, discarding every grant and allowance of the
// session that ended. Called under mu at every entry.
func (r *RotatingRecovery) syncLocked() {
	if r.generation == nil {
		return
	}
	if live := r.generation(); live != r.epoch {
		r.epoch = live
		r.accounts = nil
	}
}

// admitLocked is the one place the session rule is enforced: after syncing
// to the live generation, the caller is admitted only if the session it
// captured is the live one. Called under mu by every mutation.
func (r *RotatingRecovery) admitLocked(gen uint64) bool {
	r.syncLocked()
	return gen == r.epoch
}

// Admit reports whether an operation that captured gen may still act.
func (r *RotatingRecovery) Admit(gen uint64) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.admitLocked(gen)
}

// Prune drops the grant and last stop of accounts the signer no longer
// holds. The allowance already spent in this epoch is kept: a credential
// removed and imported again within the unlock does not get a fresh one.
func (r *RotatingRecovery) Prune(gen uint64, held func(account string) bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.admitLocked(gen) {
		return
	}
	for account, a := range r.accounts {
		if held(account) {
			continue
		}
		if a.grant != nil {
			r.stopLocked(a, a.grant, StopCredentialReplaced, nil)
		}
		a.last = nil
	}
}

// StartOperator starts an operator grant for an account. It replaces an
// active automatic grant, whose charge stands, and refuses while another
// operator grant is active, or when the caller's session is no longer the
// bound one.
func (r *RotatingRecovery) StartOperator(gen uint64, account string, hint *uint64, window, maxStages uint64, timeout time.Duration) (*RecoveryGrant, *ServiceError) {
	if r == nil {
		return nil, internal("rotating recovery is not configured")
	}
	if window == 0 {
		window = DefaultRecoveryHintWindow
	}
	if window > MaxRecoveryHintWindow {
		return nil, badRequest(fmt.Sprintf("window must be at most %d stages", MaxRecoveryHintWindow))
	}
	if maxStages == 0 {
		maxStages = DefaultOperatorRecoveryStages
	}
	if timeout <= 0 {
		timeout = DefaultOperatorRecoveryTimeout
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.admitLocked(gen) {
		return nil, staleSession()
	}
	a := r.account(account)
	if g := a.grant; g != nil {
		if g.Kind == GrantOperator {
			return nil, badRequest(fmt.Sprintf("recovery is already running for this account (grant %d); cancel it first", g.ID))
		}
		r.stopLocked(a, g, StopSuperseded, nil)
	}
	r.nextGrant++
	g := &RecoveryGrant{
		ID: r.nextGrant, Kind: GrantOperator, Epoch: r.epoch, Account: account,
		MaxStages: maxStages, Timeout: timeout, Hint: hint, Window: window, StartedAt: time.Now(),
	}
	a.grant = g
	cp := *g
	return &cp, nil
}

// Cancel ends the account's active operator grant. It reports the grant it
// cancelled, or 0 when none was active or the caller's session is stale; an
// automatic grant is not an operator's to cancel and is left alone.
func (r *RotatingRecovery) Cancel(gen uint64, account string) uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.admitLocked(gen) {
		return 0
	}
	a, ok := r.accounts[account]
	if !ok || a.grant == nil || a.grant.Kind != GrantOperator {
		return 0
	}
	a.grant.cancelled = true
	id := a.grant.ID
	r.stopLocked(a, a.grant, StopCancelled, nil)
	return id
}

// grantFor returns the grant the worker should execute for an account whose
// observed authorizer is unknown, starting an automatic one when the
// allowance permits. It ends a grant whose credential or authorizer changed
// under it (its charge stands) and binds a fresh operator grant to the
// observation. nil means no search: automatic recovery is disabled,
// exhausted, or suppressed for this authorizer, or the caller's session is
// stale.
func (r *RotatingRecovery) grantFor(gen uint64, account string, authorizer types.Address, table *stagetable.Table) *RecoveryGrant {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.admitLocked(gen) {
		return nil
	}
	a := r.account(account)
	if g := a.grant; g != nil {
		switch {
		case g.table != nil && g.table != table:
			r.stopLocked(a, g, StopCredentialReplaced, nil)
		case !g.Authorizer.IsZero() && g.Authorizer != authorizer:
			r.stopLocked(a, g, StopAuthorizerChanged, nil)
		default:
			if g.table == nil {
				g.table = table
			}
			if g.Authorizer.IsZero() {
				g.Authorizer = authorizer
			}
			cp := *g
			return &cp
		}
	}
	if r.MaxStages == 0 || a.suppressed == authorizer {
		return nil
	}
	if a.spent >= r.MaxStages {
		a.suppressed = authorizer
		return nil
	}
	r.nextGrant++
	g := &RecoveryGrant{
		ID: r.nextGrant, Kind: GrantAutomatic, Epoch: r.epoch, Account: account, Authorizer: authorizer,
		MaxStages: r.MaxStages - a.spent, Timeout: r.Timeout, StartedAt: time.Now(), table: table,
	}
	a.grant = g
	cp := *g
	return &cp
}

// live returns the account's active grant if it is still g, in the live
// session, and not cancelled. Called under mu; it syncs first, so a grant
// of a session a lock has ended is gone the moment anyone asks.
func (r *RotatingRecovery) live(g *RecoveryGrant) *RecoveryGrant {
	r.syncLocked()
	a, ok := r.accounts[g.Account]
	if !ok || a.grant == nil || a.grant.ID != g.ID || a.grant.Epoch != r.epoch || a.grant.cancelled {
		return nil
	}
	return a.grant
}

// allow reports how many more stages grant g may derive right now: zero
// when it is no longer live, out of stages, or out of active time.
func (r *RotatingRecovery) allow(g *RecoveryGrant) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.live(g)
	if cur == nil || cur.Active >= cur.Timeout || cur.Charged >= cur.MaxStages {
		return 0
	}
	return cur.MaxStages - cur.Charged
}

// charge records derivations done for g. Accounting outlives the grant
// within its epoch: work completed after the grant was superseded,
// cancelled or otherwise ended still counts against the automatic
// allowance and is added to the grant's stop record, because the seed was
// opened and the derivation ran. Only a grant from another epoch charges
// nothing, since the allowance it drew on no longer exists.
func (r *RotatingRecovery) charge(g *RecoveryGrant, derived uint64, active time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.admitLocked(g.Epoch) {
		return
	}
	a, ok := r.accounts[g.Account]
	if !ok {
		return
	}
	switch {
	case a.grant != nil && a.grant.ID == g.ID:
		a.grant.Charged += derived
		a.grant.Active += active
	case a.last != nil && a.last.GrantID == g.ID:
		a.last.Charged += derived
	}
	if g.Kind == GrantAutomatic {
		a.spent += derived
	}
}

// reconcile ends an account's active grant when an observation resolved
// the account without it: the authorizer is a cached stage (an operator
// granted a search for a stage the signer already had, or a prepare found
// it first), or the account was rekeyed to a key this signer holds.
func (r *RotatingRecovery) reconcile(gen uint64, account string, reason string, stage *uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.admitLocked(gen) {
		return
	}
	a, ok := r.accounts[account]
	if !ok || a.grant == nil {
		return
	}
	r.stopLocked(a, a.grant, reason, stage)
}

// progress copies the live grant's counters into g, or reports it gone.
func (r *RotatingRecovery) progress(g *RecoveryGrant) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.live(g)
	if cur == nil {
		return false
	}
	g.Charged, g.Active, g.Found, g.nextProbe = cur.Charged, cur.Active, cur.Found, cur.nextProbe
	return true
}

// setFound records the stage a hint probe matched.
func (r *RotatingRecovery) setFound(g *RecoveryGrant, stage uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur := r.live(g); cur != nil {
		s := stage
		cur.Found = &s
	}
}

// nextProbes returns the next n probe stages for a hinted grant and
// advances its probe cursor. Probes alternate outward from the hint: hint,
// hint+1, hint−1, hint+2, hint−2 … within the window; stages below zero are
// skipped. An empty result means the window is exhausted.
func (r *RotatingRecovery) nextProbes(g *RecoveryGrant, n uint64) []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.live(g)
	if cur == nil || cur.Hint == nil {
		return nil
	}
	var out []uint64
	for uint64(len(out)) < n {
		i := cur.nextProbe
		if i > 2*cur.Window {
			break
		}
		cur.nextProbe++
		if i == 0 {
			out = append(out, *cur.Hint)
			continue
		}
		step := (i + 1) / 2
		if i%2 == 1 {
			out = append(out, *cur.Hint+step)
		} else if *cur.Hint >= step {
			out = append(out, *cur.Hint-step)
		}
	}
	return out
}

// finish ends g with reason if it is still the account's active grant.
func (r *RotatingRecovery) finish(g *RecoveryGrant, reason string, stage *uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.admitLocked(g.Epoch) {
		return
	}
	a, ok := r.accounts[g.Account]
	if !ok || a.grant == nil || a.grant.ID != g.ID {
		return
	}
	r.stopLocked(a, a.grant, reason, stage)
}

func (r *RotatingRecovery) stopLocked(a *recoveryAccount, g *RecoveryGrant, reason string, stage *uint64) {
	a.last = &RecoveryStop{GrantID: g.ID, Kind: g.Kind, Reason: reason, Charged: g.Charged, Stage: stage, At: time.Now()}
	if g.Kind == GrantAutomatic && (reason == StopAllowanceExhausted || reason == StopTimedOut) {
		a.suppressed = g.Authorizer
	}
	a.grant = nil
}

// State snapshots one account's recovery status.
func (r *RotatingRecovery) State(account string) RecoveryState {
	if r == nil {
		return RecoveryState{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.syncLocked()
	st := RecoveryState{AllowanceMax: r.MaxStages}
	a, ok := r.accounts[account]
	if !ok {
		return st
	}
	st.AllowanceSpent, st.Suppressed = a.spent, a.suppressed
	if a.grant != nil {
		cp := *a.grant
		st.Grant = &cp
	}
	if a.last != nil {
		cp := *a.last
		st.Last = &cp
	}
	return st
}

func staleSession() *ServiceError {
	return unavailable("the signer's session changed while the request was in flight; retry")
}

// recoveryStatus projects an account's recovery state onto the wire.
func recoveryStatus(st RecoveryState) *signerapi.RotatingRecoveryStatus {
	out := &signerapi.RotatingRecoveryStatus{
		AllowanceSpent: st.AllowanceSpent,
		AllowanceMax:   st.AllowanceMax,
	}
	if !st.Suppressed.IsZero() {
		out.SuppressedAuthorizer = st.Suppressed.String()
	}
	if g := st.Grant; g != nil {
		out.Active = true
		out.Kind = string(g.Kind)
		out.GrantID = g.ID
		out.StagesCharged = g.Charged
		out.MaxStages = g.MaxStages
		out.ActiveSeconds = int64(g.Active / time.Second)
		out.Hint = g.Hint
		out.FoundStage = g.Found
	}
	if l := st.Last; l != nil {
		out.Stopped = l.Reason
		out.StoppedKind = string(l.Kind)
		out.StoppedGrantID = l.GrantID
		out.StoppedStage = l.Stage
	}
	if !out.Active && out.Stopped == "" && out.AllowanceSpent == 0 && out.SuppressedAuthorizer == "" {
		return nil
	}
	return out
}
