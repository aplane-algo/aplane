// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/stagetable"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// DefaultStageBatch is how many stages a table grows per durable write.
const DefaultStageBatch = 256

// DefaultChainReadTimeout bounds one authorizer read from the node during a
// fill. A node that sends headers and then stalls its body would otherwise
// hold the pass, and with it the single background worker, indefinitely.
const DefaultChainReadTimeout = 20 * time.Second

// StageFillOptions tune one pass of FillStageTables.
type StageFillOptions struct {
	searchAnchor   *uint64
	persistBatches bool
	// Horizon is how many stages past a resolved account's live stage the
	// table is extended, so upcoming rotations never wait on derivation.
	Horizon uint64
	// Batch is the number of stages derived per durable write. Zero means
	// DefaultStageBatch.
	Batch int
	// MaxDerivations bounds the derivations spent on one account in this
	// pass, whether it is searching for its live stage under a recovery
	// grant or extending its lookahead. Zero means one batch. Progress is
	// kept in the table, so the next pass continues where this one stopped;
	// the ceiling on a search is the grant's, not the pass's.
	MaxDerivations int
	// Parallel is the number of concurrent derivations. Zero means one.
	Parallel int
	// Pace, if set, runs after each chunk of derivations with the time the
	// chunk took, after the seed has been released; the background worker
	// sleeps here to hold its CPU budget.
	Pace func(derivation time.Duration)
	// ChainReadTimeout bounds each authorizer read. Zero means
	// DefaultChainReadTimeout.
	ChainReadTimeout time.Duration
	// KeyUse, if set, brackets every window in which the seed is held: it
	// returns a context that is cancelled when the signer locks and a
	// release to call once the seed is zeroed. The runtime's lock waits for
	// every release. Nothing that can block on I/O or the network happens
	// inside a window. Prepare and sign set it from RotatingDeps.KeyUse and
	// the daemon's worker passes the runtime's; unset, it is a no-op, which
	// only the table-fill and restore tests rely on.
	KeyUse func(ctx context.Context) (context.Context, func())
	// Session, if set, is the lock generation the caller read when it
	// created the pass's context, so the recovery session the pass acts in
	// is the one that owns its cancellation. Unset, the pass reads the
	// generation itself.
	Session *uint64
}

func (o StageFillOptions) batch() int {
	if o.Batch <= 0 {
		return DefaultStageBatch
	}
	return o.Batch
}

func (o StageFillOptions) maxDerivations() int {
	if o.MaxDerivations <= 0 {
		return o.batch()
	}
	return o.MaxDerivations
}

func (o StageFillOptions) parallel() int {
	if o.Parallel <= 0 {
		return 1
	}
	return o.Parallel
}

func (o StageFillOptions) chainReadTimeout() time.Duration {
	if o.ChainReadTimeout <= 0 {
		return DefaultChainReadTimeout
	}
	return o.ChainReadTimeout
}

func (o StageFillOptions) keyUse(ctx context.Context) (context.Context, func()) {
	if o.KeyUse == nil {
		return ctx, func() {}
	}
	return o.KeyUse(ctx)
}

// stageFillOptions intersects caller budgets with the family's operational
// ceilings. A caller may always request less work, including no lookahead.
func (s *Service) stageFillOptions(account string, opts StageFillOptions) StageFillOptions {
	p, _ := rotatingkey.Lookup(s.Planner.Snapshot().KeyTypes[account])
	limits := p.Preparation
	if limits.MaxLookahead > 0 {
		opts.Horizon = min(opts.Horizon, limits.MaxLookahead)
	}
	if limits.MaxDerivations > 0 {
		opts.MaxDerivations = min(opts.maxDerivations(), limits.MaxDerivations)
		opts.Batch = min(opts.batch(), limits.MaxDerivations)
	}
	if limits.MaxParallel > 0 {
		opts.Parallel = min(opts.parallel(), limits.MaxParallel)
	}
	return opts
}

// StageTableReport is one account's outcome of a FillStageTables pass.
type StageTableReport struct {
	Account string
	// Resolved reports whether the account's authorizer maps to a stage in
	// the table. Stage is that stage when it does.
	Preparation string
	Resolved    bool
	Stage       uint64
	// Class is the worker's reading of the observed authorizer (empty when
	// the read failed). ClassHeldKey and ClassUnknown are both unresolved;
	// only ClassUnknown is ever searched for.
	Class AuthorizerClass
	// Scanned is the table's length after the pass: the number of stages
	// whose addresses are known.
	Scanned uint64
	// Pending reports that this pass stopped at its derivation budget with
	// work left: a recovery grant is still searching, or the lookahead is
	// short. An unknown authorizer with no grant is not pending.
	Pending bool
	// Recovery is the account's recovery state after the pass.
	Recovery RecoveryState
	// Observed reports that the chain read succeeded; Authorizer and Round
	// are then what the node reported, and ObservedSeq is the release
	// memory's sequence just before the read. RotatingStatus uses these even
	// when a later table write failed.
	Observed    bool
	Authorizer  types.Address
	Round       uint64
	ObservedSeq uint64
	// Discarded is set when an unusable on-disk table was replaced.
	Discarded error
	// Err is set when the account could not be processed (chain read,
	// derivation or write failure). Completed probes remain cached.
	Err error
}

// FillStageTables extends every rotating account's stage address table. For
// an account whose authorizer is in the table (or is the account itself,
// stage 0) it derives ahead to Horizon past that stage. For an account whose
// authorizer is not in the table it classifies the authorizer first: a
// credential this signer holds means the account was rekeyed away and
// nothing is derived; anything else is unknown and is searched for under a
// recovery grant (automatic from the per-unlock allowance, or an operator's)
// that stops early when the authorizer appears. A pass spends at most
// MaxDerivations on one account and reports Pending when work remains, so
// no account is held for long and the caller schedules the next pass. A
// search that ends without finding the stage leaves the account unresolved
// with its stop recorded; it is never called foreign.
//
// The seed is loaded only for the duration of one chunk of derivations and
// zeroed before anything that can block: the chain read, the table write
// and the pacing sleep all run with no key material in memory. Each chunk
// is bracketed by KeyUse so the signer's lock can cut a pass short and wait
// for the seed to be released.
//
// No account lock is taken. Derivation is a pure function of the seed, the
// table serializes its own writes and tolerates two fills deriving the same
// range, and the chain is only read. A prepare or sign running concurrently
// is never blocked by table maintenance.
//
// The table is a cache. Every address it holds was derived from the seed by
// this routine, and signing re-derives whatever it uses, so nothing here
// changes what the signer signs.
func (s *Service) FillStageTables(ctx context.Context, session *keystore.KeySession, opts StageFillOptions) []StageTableReport {
	deps, depErr := s.rotatingDeps()
	if depErr != nil {
		return nil
	}
	if ctx.Err() != nil {
		// A cancelled pass resuming after a lock must not bind, prune or
		// derive: the inventory it would read is the locked signer's empty
		// one, and the session it would bind may already be a later
		// unlock's.
		return nil
	}
	gen, ok := deps.recoverySession(opts.Session)
	if !ok {
		// This pass belongs to a session a lock has ended; a later unlock
		// is already live. Its context is cancelled or about to be.
		return nil
	}
	accounts := s.rotatingAccounts()
	live := make(map[string]bool, len(accounts))
	for _, a := range accounts {
		live[a] = true
	}
	deps.Recovery.Prune(gen, func(account string) bool { return live[account] })
	var reports []StageTableReport
	for _, account := range accounts {
		if ctx.Err() != nil {
			break
		}
		reports = append(reports, s.fillStageTable(ctx, deps, gen, account, session, opts))
	}
	return reports
}

// stageDeriver derives a contiguous range of stage addresses for one
// account. Each call opens the seed, derives, and zeroes the seed again.
type stageDeriver func(ctx context.Context, from, to uint64) ([]types.Address, error)

func (s *Service) fillStageTable(ctx context.Context, deps *RotatingDeps, gen uint64, account string, session *keystore.KeySession, opts StageFillOptions) StageTableReport {
	opts = s.stageFillOptions(account, opts)
	report := s.fillStageTableOnce(ctx, deps, gen, account, session, opts)
	report.Recovery = deps.Recovery.State(account)
	return report
}

func (s *Service) fillStageTableOnce(ctx context.Context, deps *RotatingDeps, gen uint64, account string, session *keystore.KeySession, opts StageFillOptions) (report StageTableReport) {
	report = StageTableReport{Account: account}
	opts.persistBatches = true

	// Identity and network come from the key file; the seed is opened and
	// closed again inside the call.
	acct, genesis, svcErr := s.rotatingIdentity(ctx, account, session, opts)
	if svcErr != nil {
		report.Err = errors.New(svcErr.Message)
		return report
	}
	present := func() bool {
		_, ok := s.Planner.Snapshot().KeyFiles[account]
		return ok
	}
	table, tableErr := deps.Tables.Table(acct, genesis, present, s.Planner.Snapshot().KeyTypes[account])
	if table == nil {
		report.Err = tableErr
		return report
	}
	if errors.Is(tableErr, stagetable.ErrDiscarded) {
		report.Discarded = tableErr
	}
	defer func() {
		if err := table.Flush(); err != nil {
			if report.Err == nil {
				report.Err = err
			}
			if errors.Is(err, stagetable.ErrClosed) {
				report.Resolved = false
				report.Observed = false
				report.Class = ""
				report.Pending = ctx.Err() == nil
			}
		}
		report.Scanned = table.Len()
		report.Preparation = "unresolved"
		if report.Pending {
			report.Preparation = "locating"
		}
		if report.Resolved {
			report.Preparation = "preparing_successor"
			if a, ok := table.Address(report.Stage + 1); ok && table.Verified(report.Stage+1, a) {
				report.Preparation = "ready"
			}
		}
	}()
	report.Scanned = table.Len()

	report.ObservedSeq = deps.Releases.Seq()
	readCtx, cancelRead := context.WithTimeout(ctx, opts.chainReadTimeout())
	view, readErr := deps.Chain.ReadAccount(readCtx, genesis, acct)
	cancelRead()
	if readErr != nil {
		report.Err = readErr
		return report
	}
	report.Observed, report.Authorizer, report.Round = true, view.Authorizer, view.Round

	opts.searchAnchor = releaseSearchAnchor(deps, account)
	derive := s.stageDeriver(account, session, opts)
	budget := opts.maxDerivations()
	held := knownAddressesFromSnapshot(s.Planner.Snapshot())
	proven, class := classifyAuthorizer(table, acct, view.Authorizer, held)
	if class == ClassStage && proven != 0 && !table.Verified(proven, view.Authorizer) {
		addrs, err := derive(ctx, proven, proven+1)
		budget--
		if err != nil {
			report.Err = err
			return report
		}
		if len(addrs) != 1 {
			return report
		}
		if _, err := table.RecordDerived(proven, addrs); err != nil {
			report.Err = err
			return report
		}
		if addrs[0] != view.Authorizer {
			class = ClassUnknown
		}
	}
	report.Class = class
	switch class {
	case ClassStage:
		// A grant started for a stage the signer already has, or one a
		// prepare found first, is over.
		stage := proven
		deps.Recovery.reconcile(gen, account, StopResolved, &stage)
	case ClassHeldKey:
		// Rekeyed to a credential this signer holds: resolved without a
		// stage, nothing to derive, and no search to continue.
		deps.Recovery.reconcile(gen, account, StopHeldKey, nil)
		return report
	case ClassUnknown:
		grant := deps.Recovery.grantFor(gen, account, view.Authorizer, table)
		if grant == nil {
			// Automatic recovery is disabled, exhausted or suppressed for
			// this authorizer: unresolved and idle until an operator
			// grants a search or the chain moves.
			return report
		}
		found, pending, spent, grantErr := s.runRecoveryGrant(ctx, deps.Recovery, grant, table, account, session, view.Authorizer, budget, opts)
		report.Scanned = table.Len()
		// Hinted probes consume work even when they do not extend the prefix.
		budget -= spent
		if grantErr != nil {
			report.Err = grantErr
			return report
		}
		if !found {
			report.Pending = pending && ctx.Err() == nil
			return report
		}
		proven, class = classifyAuthorizer(table, acct, view.Authorizer, held)
		report.Class = class
		if class != ClassStage {
			return report
		}
	}
	if proven >= math.MaxUint64-1 {
		report.Err = errors.New("live stage has no representable successor")
		return report
	}
	report.Resolved, report.Stage = true, proven
	s.rememberStage(table, proven, view.Authorizer, view.Round)

	// Lookahead: cover stages through proven + Horizon, within what is left
	// of this pass's budget. A family whose stages share trees stops at the
	// last tree that is built, building the next one from the midpoint of
	// the live one.
	target := proven + min(max(uint64(1), opts.Horizon), math.MaxUint64-proven-1) + 1
	if budget > 0 && ctx.Err() == nil {
		next := proven + 1
		a, ok := table.Address(next)
		if !ok || !table.Verified(next, a) {
			addrs, err := derive(ctx, next, next+1)
			budget -= len(addrs)
			if _, e := table.RecordDerived(next, addrs); e != nil {
				report.Err = e
				return report
			}
			if err != nil {
				report.Err = err
				return report
			}
		}
	}
	if limit, capped := s.treeFrontier(ctx, account, session, opts, proven); capped && target > limit {
		target = limit
	}
	from := table.FirstMissing(proven)
	for from < target && budget > 0 && ctx.Err() == nil {
		addrs, err := derive(ctx, from, from+1)
		if len(addrs) > 0 {
			budget -= len(addrs)
			if _, e := table.RecordDerived(from, addrs); e != nil {
				report.Err = e
				break
			}
		}
		if err != nil {
			report.Err = err
			break
		}
		if len(addrs) == 0 {
			break
		}
		if err := publishStageBatch(table, opts.maxDerivations()-budget-len(addrs), opts.maxDerivations()-budget, opts); err != nil {
			report.Err = err
			return report
		}
		from = table.FirstMissing(from)
	}
	report.Scanned = table.Len()
	report.Pending = report.Err == nil && ctx.Err() == nil && from < target
	return report
}

// rotatingIdentity returns the account address and genesis hash of a
// rotating key. It opens the key material only long enough to copy the
// genesis hash out, inside a KeyUse window.
func (s *Service) rotatingIdentity(ctx context.Context, account string, session *keystore.KeySession, opts StageFillOptions) (types.Address, []byte, *ServiceError) {
	ctx, release := opts.keyUse(ctx)
	defer release()
	if ctx.Err() != nil {
		return types.Address{}, nil, lockedError()
	}
	rs, svcErr := s.openRotatingSession(ctx, account, session)
	if svcErr != nil {
		return types.Address{}, nil, svcErr
	}
	defer rs.close()
	return rs.account, bytes.Clone(rs.secret.GenesisHash), nil
}

// stageDeriver returns the deriver for one account. Every call loads the
// seed inside a KeyUse window, derives the requested stages with up to
// opts.Parallel in flight, zeroes the seed, releases the window, and only
// then paces. A cancelled window (the signer locked) returns the contiguous
// prefix derived so far with no error, so the caller can write it and stop.
func (s *Service) stageDeriver(account string, session *keystore.KeySession, opts StageFillOptions) stageDeriver {
	return func(parent context.Context, from, to uint64) ([]types.Address, error) {
		count := int(to - from)
		if count <= 0 {
			return nil, nil
		}
		started := time.Now()
		work := func() ([]types.Address, error) {
			ctx, release := opts.keyUse(parent)
			defer release()
			if ctx.Err() != nil {
				return nil, nil
			}
			rs, svcErr := s.openRotatingSession(ctx, account, session)
			if svcErr != nil {
				if svcErr.Kind == ErrorLocked {
					return nil, nil
				}
				return nil, errors.New(svcErr.Message)
			}
			defer rs.close()
			return deriveRange(ctx, rs, from, to, opts)
		}
		key := stageJobKey{account: account, from: from, to: to, credential: s.Rotating.Tables.Epoch()}
		if s.Rotating.LockGeneration != nil {
			key.session = s.Rotating.LockGeneration()
		}
		addrs, err := s.Rotating.Locks.deriveJob(parent, key, work)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			err = nil
		}
		if err == nil && len(addrs) > 0 && opts.Pace != nil {
			opts.Pace(time.Since(started))
		}
		return addrs, err
	}
}

// runRecoveryGrant does one pass's worth of work for a recovery grant: at
// most budget derivations, each one checked against the grant's remaining
// stages, active time and cancellation before it runs. A hinted grant
// probes outward from the hint first, one derivation per probe, and once a
// probe matches it resolves immediately; an unhinted grant searches
// sparse gaps with a preference for the last observed stage. The grant's
// counters are charged per derivation, so a grant of 100 derives at most
// 100 and a cancel lands between two derivations, not after a batch. It
// returns whether the authorizer is now in the table, whether the grant is
// still active with work left, the derivations spent (including probes), and
// any derivation or write error.
func (s *Service) runRecoveryGrant(ctx context.Context, rec *RotatingRecovery, g *RecoveryGrant, table *stagetable.Table, account string, session *keystore.KeySession, authorizer types.Address, budget int, opts StageFillOptions) (found, pending bool, spent int, err error) {
	unpaced := opts
	unpaced.Pace = nil
	base := s.stageDeriver(account, session, unpaced)
	// derive caps every call at what the grant may still spend, charges the
	// grant for what came back, and paces afterwards with the seed released.
	// A zero result is a cut: extendUntil and extendTo write the prefix
	// they have and stop.
	derive := func(ctx context.Context, from, to uint64) ([]types.Address, error) {
		allow := rec.allow(g)
		if allow == 0 || ctx.Err() != nil {
			return nil, nil
		}
		if to-from > allow {
			to = from + allow
		}
		started := time.Now()
		addrs, err := base(ctx, from, to)
		elapsed := time.Since(started)
		spent += len(addrs)
		rec.charge(g, uint64(len(addrs)), elapsed)
		if err == nil && len(addrs) > 0 && opts.Pace != nil {
			opts.Pace(elapsed)
		}
		return addrs, err
	}

	if g.Hint != nil && g.Found == nil {
		for budget > 0 && ctx.Err() == nil {
			probes := rec.nextProbes(g, 1)
			if len(probes) == 0 {
				rec.finish(g, StopHintNotFound, nil)
				return false, false, spent, nil
			}
			stage := probes[0]
			addrs, err := derive(ctx, stage, stage+1)
			if err != nil {
				return false, false, spent, err
			}
			if len(addrs) == 0 {
				break
			}
			budget--
			if _, err := table.RecordDerived(stage, addrs); err != nil {
				return false, false, spent, err
			}
			if err := publishStageBatch(table, spent-len(addrs), spent, opts); err != nil {
				return false, false, spent, err
			}
			if addrs[0] == authorizer {
				rec.setFound(g, stage)
				s := stage
				g.Found = &s
				break
			}
		}
	}
	switch {
	case g.Hint != nil && g.Found == nil:
		// Still probing, or cut short.
	case g.Found != nil:
		_, found = table.Lookup(authorizer)
	default:
		if budget > 0 {
			found, err = extendUntil(ctx, table, derive, authorizer, budget, opts)
			if err != nil {
				return false, false, spent, err
			}
		}
	}
	if found {
		stage, _ := table.Lookup(authorizer)
		rec.finish(g, StopFound, &stage)
		return true, false, spent, nil
	}
	if !rec.progress(g) {
		// Cancelled, superseded or invalidated while this pass ran.
		return false, false, spent, nil
	}
	switch {
	case g.Charged >= g.MaxStages:
		if g.Kind == GrantAutomatic {
			rec.finish(g, StopAllowanceExhausted, nil)
		} else {
			rec.finish(g, StopBudgetExhausted, nil)
		}
		return false, false, spent, nil
	case g.Active >= g.Timeout:
		rec.finish(g, StopTimedOut, nil)
		return false, false, spent, nil
	}
	return false, true, spent, nil
}

// resolveStage maps the authorizer to a stage: the account itself is stage
// 0 (no authorizer set); anything else must be in the table.
func resolveStage(table *stagetable.Table, account, authorizer types.Address) (uint64, bool) {
	if authorizer == account {
		return 0, true
	}
	return table.Lookup(authorizer)
}

// extendUntil uses the same sparse coverage and bounded forward preference for
// prepare and background recovery. Each probe is retained, including misses.
func extendUntil(ctx context.Context, table *stagetable.Table, derive stageDeriver, target types.Address, budget int, opts StageFillOptions) (bool, error) {
	initialBudget := budget
	for budget > 0 && ctx.Err() == nil {
		var anchors []uint64
		if opts.searchAnchor != nil {
			anchors = []uint64{*opts.searchAnchor}
		}
		n := table.NextCandidate(anchors...)
		if n == math.MaxUint64 {
			return false, errors.New("stage space exhausted")
		}
		// The first probe is the candidate alone: after a restore or a single
		// rotation it is usually the live stage, and one derivation proves it.
		// Once it misses, derive the gap that starts at each candidate in one
		// call, so up to opts.Parallel derivations run at once. A chunk never
		// crosses a cached entry, so nothing already held is derived again.
		chunk := uint64(1)
		if budget < initialBudget {
			chunk = uint64(min(opts.parallel(), budget))
			if room := math.MaxUint64 - n; chunk > room {
				chunk = room
			}
			chunk = max(table.MissingRun(n, chunk), 1)
		}
		before := initialBudget - budget
		addrs, err := derive(ctx, n, n+chunk)
		if len(addrs) > 0 {
			if _, e := table.RecordDerived(n, addrs); e != nil {
				return false, e
			}
			if slices.Contains(addrs, target) {
				return true, nil
			}
			budget -= len(addrs)
			if err := publishStageBatch(table, before, initialBudget-budget, opts); err != nil {
				return false, err
			}
		}
		if err != nil {
			return false, err
		}
		if len(addrs) == 0 {
			break
		}
	}
	return false, nil
}

// deriveRange derives the addresses of stages from … to-1, in order, with
// up to opts.Parallel derivations in flight. A cancelled ctx returns the
// contiguous prefix derived so far.
func deriveRange(ctx context.Context, rs *rotatingSession, from, to uint64, opts StageFillOptions) ([]types.Address, error) {
	count := int(to - from)
	if count <= 0 {
		return nil, nil
	}
	out := make([]types.Address, count)
	errs := make([]error, count)
	workers := opts.parallel()
	if workers > count {
		workers = count
	}
	next := make(chan int, count)
	for i := 0; i < count; i++ {
		next <- i
	}
	close(next)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if ctx.Err() != nil {
					errs[i] = ctx.Err()
					continue
				}
				out[i], errs[i] = rs.stageAddress(from + uint64(i))
			}
		}()
	}
	wg.Wait()
	// Keep the contiguous prefix: a later failure must not leave a gap.
	for i, err := range errs {
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return out[:i], nil
			}
			return out[:i], fmt.Errorf("derive stage %d: %w", from+uint64(i), err)
		}
	}
	return out, nil
}

func sortStrings(s []string) { sort.Strings(s) }

// treeFrontier returns the lookahead limit of an account whose stages share
// trees (rotatingkey.Profile.StagesPerTree): one past the last stage of the
// last tree that is ready, at most one tree beyond the live stage's. From
// the midpoint of the live tree it builds the next tree first, inside a
// key-use window, so the frontier normally moves long before the live stage
// reaches it; a late build is handled by the signing path's own readiness
// check, not assumed away. It reports false for a family without shared
// trees.
func (s *Service) treeFrontier(ctx context.Context, account string, session *keystore.KeySession, opts StageFillOptions, live uint64) (uint64, bool) {
	profile, ok := rotatingkey.Lookup(s.Planner.Snapshot().KeyTypes[account])
	if !ok || profile.StagesPerTree <= 0 {
		return 0, false
	}
	per := uint64(profile.StagesPerTree)
	tree := live / per
	next := (tree + 1) * per
	ready := false
	func() {
		ctx, release := opts.keyUse(ctx)
		defer release()
		if ctx.Err() != nil {
			return
		}
		rs, svcErr := s.openRotatingSession(ctx, account, session)
		if svcErr != nil {
			return
		}
		defer rs.close()
		treeOps, ok := rs.ops.(coresigning.RotatingTreeOps)
		if !ok {
			return
		}
		ready = treeOps.TreeReady(rs.secret, next)
		if !ready && live%per >= per/2 {
			if err := treeOps.Prepare(rs.secret, next); err == nil {
				ready = true
			}
		}
	}()
	if ready {
		return next + per, true
	}
	return next, true
}

// Audit releases propose candidates only; they are not chain observations.
func releaseSearchAnchor(deps *RotatingDeps, account string) *uint64 {
	if r, ok := deps.Releases.Get(account); ok && r.Stage < math.MaxUint64-1 {
		n := r.Stage
		return &n
	}
	return nil
}

// publishStageBatch preserves completed work during a long paced pass: it
// flushes once each time the pass's derivations cross a batch boundary.
// before and after are the derivations spent before and after the latest
// call, so a chunk that steps over a boundary still publishes. Foreground
// discovery only updates memory and wakes the worker to publish it.
func publishStageBatch(table *stagetable.Table, before, after int, opts StageFillOptions) error {
	if !opts.persistBatches || after <= before || after/opts.batch() == before/opts.batch() {
		return nil
	}
	err := table.Flush()
	if errors.Is(err, stagetable.ErrPersistence) {
		return nil
	} // Retried at pass end.
	return err
}
