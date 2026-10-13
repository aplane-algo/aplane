// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/stagetable"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// DefaultStageBatch is how many stages a table grows per durable write.
const DefaultStageBatch = 256

// StageFillOptions tune one pass of FillStageTables.
type StageFillOptions struct {
	// Horizon is how many stages past a resolved account's live stage the
	// table is extended, so upcoming rotations never wait on derivation.
	Horizon uint64
	// Batch is the number of stages derived per durable write. Zero means
	// DefaultStageBatch.
	Batch int
	// MaxDerivations bounds the derivations spent on one account in this
	// pass, whether it is scanning for its live stage or extending its
	// lookahead. Zero means one batch. Progress is kept in the table, so the
	// next pass continues where this one stopped; there is no ceiling.
	MaxDerivations int
	// Parallel is the number of concurrent derivations. Zero means one.
	Parallel int
	// Pace, if set, runs after each chunk of derivations with the time the
	// chunk took, after the seed has been released; the background worker
	// sleeps here to hold its CPU budget.
	Pace func(derivation time.Duration)
	// KeyUse, if set, brackets every window in which the seed is held: it
	// returns a context that is cancelled when the signer locks and a
	// release to call once the seed is zeroed. The runtime's lock waits for
	// every release. Nothing that can block on I/O or the network happens
	// inside a window.
	KeyUse func(ctx context.Context) (context.Context, func())
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

func (o StageFillOptions) keyUse(ctx context.Context) (context.Context, func()) {
	if o.KeyUse == nil {
		return ctx, func() {}
	}
	return o.KeyUse(ctx)
}

// StageTableReport is one account's outcome of a FillStageTables pass.
type StageTableReport struct {
	Account string
	// Resolved reports whether the account's authorizer maps to a stage in
	// the table. Stage is that stage when it does.
	Resolved bool
	Stage    uint64
	// Scanned is the table's length after the pass: the number of stages
	// whose addresses are known.
	Scanned uint64
	// Pending reports that this pass stopped at its derivation budget with
	// work left: the account is unresolved, or its lookahead is short.
	Pending bool
	// Discarded is set when an unusable on-disk table was replaced.
	Discarded error
	// Err is set when the account could not be processed (chain read,
	// derivation or write failure). The table is left prefix-complete.
	Err error
}

// FillStageTables extends every rotating account's stage address table. For
// an account whose authorizer is in the table (or is the account itself,
// stage 0) it derives ahead to Horizon past that stage. For an account whose
// authorizer is not yet in the table it derives further, stopping early when
// the authorizer appears. Either way a pass spends at most MaxDerivations on
// one account and reports Pending when work remains, so no account is held
// for long and the caller schedules the next pass. It never classifies an
// unresolved authorizer as foreign: the caller decides what a long run of
// unresolved passes means.
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
	var reports []StageTableReport
	for _, account := range s.rotatingAccounts() {
		if ctx.Err() != nil {
			break
		}
		reports = append(reports, s.fillStageTable(ctx, deps, account, session, opts))
	}
	return reports
}

// stageDeriver derives a contiguous range of stage addresses for one
// account. Each call opens the seed, derives, and zeroes the seed again.
type stageDeriver func(ctx context.Context, from, to uint64) ([]types.Address, error)

func (s *Service) fillStageTable(ctx context.Context, deps *RotatingDeps, account string, session *keystore.KeySession, opts StageFillOptions) StageTableReport {
	report := StageTableReport{Account: account}

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
	table, tableErr := deps.Tables.Table(acct, genesis, present)
	if table == nil {
		report.Err = tableErr
		return report
	}
	if errors.Is(tableErr, stagetable.ErrDiscarded) {
		report.Discarded = tableErr
	}
	report.Scanned = table.Len()

	view, readErr := deps.Chain.ReadAccount(ctx, genesis, acct)
	if readErr != nil {
		report.Err = readErr
		return report
	}

	derive := s.stageDeriver(account, session, opts)
	budget := opts.maxDerivations()
	proven, resolved := resolveStage(table, acct, view.Authorizer)
	if !resolved {
		before := table.Len()
		found, extendErr := extendUntil(ctx, table, derive, view.Authorizer, budget, opts)
		report.Scanned = table.Len()
		budget -= int(table.Len() - before)
		if extendErr != nil {
			report.Err = extendErr
			return report
		}
		if !found {
			report.Pending = ctx.Err() == nil
			return report
		}
		proven, resolved = resolveStage(table, acct, view.Authorizer)
	}
	report.Resolved, report.Stage = resolved, proven

	// Lookahead: cover stages through proven + Horizon, within what is left
	// of this pass's budget.
	target := proven + opts.Horizon + 1
	if table.Len() < target {
		limit := table.Len() + uint64(max(budget, 0))
		if limit > target {
			limit = target
		}
		if err := extendTo(ctx, table, derive, limit, opts); err != nil {
			report.Err = err
		}
	}
	report.Scanned = table.Len()
	report.Pending = report.Err == nil && ctx.Err() == nil && table.Len() < target
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
		addrs, err := func() ([]types.Address, error) {
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
		}()
		if err == nil && len(addrs) > 0 && opts.Pace != nil {
			opts.Pace(time.Since(started))
		}
		return addrs, err
	}
}

// resolveStage maps the authorizer to a stage: the account itself is stage
// 0 (no authorizer set); anything else must be in the table.
func resolveStage(table *stagetable.Table, account, authorizer types.Address) (uint64, bool) {
	if authorizer == account {
		return 0, true
	}
	return table.Lookup(authorizer)
}

// extendUntil derives up to max further stages and reports whether target
// appeared among them. Derivation proceeds in chunks of opts.Parallel so the
// search stops as soon as the target is derived, while writes happen once
// per batch. A chunk that comes back short means the signer locked or the
// pass was cancelled: whatever contiguous prefix was derived is written and
// the pass ends, so the table stays prefix-complete and the next pass
// resumes from its length.
func extendUntil(ctx context.Context, table *stagetable.Table, derive stageDeriver, target types.Address, max int, opts StageFillOptions) (bool, error) {
	remaining := max
	for remaining > 0 && ctx.Err() == nil {
		from := table.Len()
		var pending []types.Address
		found, cut := false, false
		for len(pending) < opts.batch() && remaining > 0 && !found && !cut && ctx.Err() == nil {
			chunk := opts.parallel()
			if room := opts.batch() - len(pending); chunk > room {
				chunk = room
			}
			if chunk > remaining {
				chunk = remaining
			}
			start := from + uint64(len(pending))
			addrs, err := derive(ctx, start, start+uint64(chunk))
			if err != nil {
				return false, err
			}
			cut = len(addrs) < chunk
			for _, a := range addrs {
				pending = append(pending, a)
				remaining--
				if a == target {
					found = true
					break
				}
			}
		}
		if len(pending) > 0 {
			if err := table.AppendFrom(from, pending); err != nil {
				return false, err
			}
		}
		if found {
			return true, nil
		}
		if cut {
			return false, nil
		}
	}
	return false, nil
}

// extendTo grows the table to cover stages 0 … target-1, one batch per
// write, stopping early when a chunk comes back short.
func extendTo(ctx context.Context, table *stagetable.Table, derive stageDeriver, target uint64, opts StageFillOptions) error {
	for table.Len() < target && ctx.Err() == nil {
		from := table.Len()
		end := from + uint64(opts.batch())
		if end > target {
			end = target
		}
		var pending []types.Address
		cut := false
		for from+uint64(len(pending)) < end && !cut && ctx.Err() == nil {
			start := from + uint64(len(pending))
			chunk := uint64(opts.parallel())
			if start+chunk > end {
				chunk = end - start
			}
			addrs, err := derive(ctx, start, start+chunk)
			if err != nil {
				return err
			}
			cut = uint64(len(addrs)) < chunk
			pending = append(pending, addrs...)
		}
		if len(pending) > 0 {
			if err := table.AppendFrom(from, pending); err != nil {
				return err
			}
		}
		if cut {
			return nil
		}
	}
	return nil
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
