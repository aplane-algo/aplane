// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package externalcheck

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/policy"
)

const (
	// StepDeadline bounds every lookup of one request together.
	StepDeadline = 10 * time.Second
	// MaxInFlightPerRequest is the most lookups one request makes at a time.
	MaxInFlightPerRequest = 4
)

// TokenFor returns the token set for a source under a policy selector, and
// false when none is set.
type TokenFor func(selector, source string) (string, bool)

// Runner runs a document's checks for a request.
type Runner struct {
	Fetcher *Fetcher
	// Tokens is nil when the node holds no tokens: a source that declares
	// one then has none.
	Tokens TokenFor
}

// Summary says what ran for a request that passed.
type Summary struct {
	CheckIDs []string
	Lookups  int
}

// Run plans, fetches and judges cfg's checks for req. It returns nil when
// every check passes for every unit it applies to, and the first refusal
// otherwise. A source that declares a token the governing document's selector
// lacks refuses before any connection is made. ctx should end when the
// request is canceled and when the node locks.
func (r *Runner) Run(ctx context.Context, cfg *policy.Config, req Request) (*Summary, *Refusal) {
	plan, refusal := BuildPlan(cfg.ExternalChecks, cfg.ExternalSources, req)
	if refusal != nil {
		return nil, refusal
	}
	tokens := make([]string, len(plan.Lookups))
	for i, lookup := range plan.Lookups {
		if lookup.Source.Token == nil {
			continue
		}
		token, ok := "", false
		if r.Tokens != nil {
			token, ok = r.Tokens(cfg.DocumentKey, lookup.SourceName)
		}
		if !ok {
			return nil, r.lookupRefusal(plan, i, policy.ExternalCheckTokenNotSetOutcome, errNoToken.Error())
		}
		tokens[i] = token
	}

	ctx, cancel := context.WithTimeout(ctx, StepDeadline)
	defer cancel()
	answers := make([]*Answer, len(plan.Lookups))
	failures := make([]error, len(plan.Lookups))
	places := make(chan struct{}, MaxInFlightPerRequest)
	var wg sync.WaitGroup
	for i := range plan.Lookups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case places <- struct{}{}:
				defer func() { <-places }()
			case <-ctx.Done():
				failures[i] = errCanceled
				return
			}
			answers[i], failures[i] = r.Fetcher.Get(ctx, plan.Lookups[i], tokens[i])
			if failures[i] != nil {
				// One failure refuses the request; the rest need not finish.
				cancel()
			}
		}()
	}
	wg.Wait()
	// Report the first failure in document order that is a cause, not the
	// echo of the cancel above. When every failure is a cancellation, the
	// request itself was canceled or the node locked.
	canceled := -1
	for i, err := range failures {
		switch {
		case err == nil:
		case !errors.Is(err, errCanceled):
			return nil, r.lookupRefusal(plan, i, policy.ExternalCheckUnavailableOutcome, err.Error())
		case canceled < 0:
			canceled = i
		}
	}
	if canceled >= 0 {
		return nil, r.lookupRefusal(plan, canceled, policy.ExternalCheckUnavailableOutcome, errCanceled.Error())
	}

	summary := &Summary{Lookups: len(plan.Lookups)}
	for _, j := range plan.Judgments {
		answer := answers[j.Lookup]
		lookup := plan.Lookups[j.Lookup]
		if ok, detail := Judge(j.Check, j.Facts, answer.Root, answer.RequestID); !ok {
			return nil, &Refusal{CheckID: j.Check.ID, Unit: j.Unit, Source: lookup.SourceName, Path: lookup.Path, Detail: detail}
		}
		if len(summary.CheckIDs) == 0 || summary.CheckIDs[len(summary.CheckIDs)-1] != j.Check.ID {
			summary.CheckIDs = append(summary.CheckIDs, j.Check.ID)
		}
	}
	return summary, nil
}

// lookupRefusal attributes a lookup's failure to the first judgment that
// needed it.
func (r *Runner) lookupRefusal(plan *Plan, lookupIndex int, outcome, detail string) *Refusal {
	lookup := plan.Lookups[lookupIndex]
	refusal := &Refusal{Outcome: outcome, Source: lookup.SourceName, Path: lookup.Path, Detail: detail, Unit: "the request"}
	for _, j := range plan.Judgments {
		if j.Lookup == lookupIndex {
			refusal.CheckID, refusal.Unit = j.Check.ID, j.Unit
			break
		}
	}
	return refusal
}
