// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
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
	// MaxDerivations bounds the derivations spent on one unresolved account
	// in this pass. Zero means one batch. Progress is kept in the table, so
	// the next pass continues where this one stopped; there is no ceiling.
	MaxDerivations int
	// Parallel is the number of concurrent derivations. Zero means one.
	Parallel int
	// Pace, if set, runs after each derivation with the time it took; the
	// background worker sleeps here to hold its CPU budget.
	Pace func(derivation time.Duration)
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
	// Discarded is set when an unusable on-disk table was replaced.
	Discarded error
	// Err is set when the account could not be processed (chain read,
	// derivation or write failure). The table is left prefix-complete.
	Err error
}

// FillStageTables extends every rotating account's stage address table. For
// an account whose authorizer is in the table (or is the account itself,
// stage 0) it derives ahead to Horizon past that stage. For an account whose
// authorizer is not yet in the table it derives further, up to
// MaxDerivations in this pass, stopping early when the authorizer appears.
// It never classifies an unresolved authorizer as foreign: the caller
// decides what a long run of unresolved passes means.
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

func (s *Service) fillStageTable(ctx context.Context, deps *RotatingDeps, account string, session *keystore.KeySession, opts StageFillOptions) StageTableReport {
	report := StageTableReport{Account: account}
	unlock := deps.Locks.Lock(account)
	defer unlock()

	rs, svcErr := s.openRotatingSession(ctx, account, session)
	if svcErr != nil {
		report.Err = errors.New(svcErr.Message)
		return report
	}
	defer rs.close()

	table, tableErr := rs.table(deps)
	if table == nil {
		report.Err = tableErr
		return report
	}
	if errors.Is(tableErr, stagetable.ErrDiscarded) {
		report.Discarded = tableErr
	}
	report.Scanned = table.Len()

	view, readErr := deps.Chain.ReadAccount(ctx, rs.secret.GenesisHash, rs.account)
	if readErr != nil {
		report.Err = readErr
		return report
	}

	proven, resolved := resolveStage(table, rs.account, view.Authorizer)
	if !resolved {
		found, extendErr := extendUntil(ctx, table, rs, view.Authorizer, opts.maxDerivations(), opts)
		report.Scanned = table.Len()
		if extendErr != nil {
			report.Err = extendErr
			return report
		}
		if !found {
			return report
		}
		proven, resolved = resolveStage(table, rs.account, view.Authorizer)
	}
	report.Resolved, report.Stage = resolved, proven

	// Lookahead: cover stages through proven + Horizon.
	target := proven + opts.Horizon + 1
	if target > stagetable.MaxStages {
		target = stagetable.MaxStages
	}
	if table.Len() < target {
		if err := extendTo(ctx, table, rs, target, opts); err != nil {
			report.Err = err
		}
	}
	report.Scanned = table.Len()
	return report
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
// per batch. ctx cancellation ends the pass with whatever contiguous prefix
// was derived written, so the table stays prefix-complete and the next pass
// resumes from its length.
func extendUntil(ctx context.Context, table *stagetable.Table, rs *rotatingSession, target types.Address, max int, opts StageFillOptions) (bool, error) {
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
			addrs, err := deriveRange(ctx, rs, start, start+uint64(chunk), opts)
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
			if err := table.Append(pending); err != nil {
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

// extendTo grows the table to cover stages 0 … target-1.
func extendTo(ctx context.Context, table *stagetable.Table, rs *rotatingSession, target uint64, opts StageFillOptions) error {
	for table.Len() < target {
		if ctx.Err() != nil {
			return nil
		}
		from := table.Len()
		to := from + uint64(opts.batch())
		if to > target {
			to = target
		}
		addrs, err := deriveRange(ctx, rs, from, to, opts)
		if err != nil {
			return err
		}
		if len(addrs) == 0 {
			return nil
		}
		if err := table.Append(addrs); err != nil {
			return err
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
				started := time.Now()
				out[i], errs[i] = rs.stageAddress(from + uint64(i))
				if opts.Pace != nil && errs[i] == nil {
					opts.Pace(time.Since(started))
				}
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
