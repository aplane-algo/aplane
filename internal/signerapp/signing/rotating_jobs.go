// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"errors"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

type stageJobKey struct {
	account    string
	credential uint64
	session    uint64
	from, to   uint64
}
type stageJob struct {
	done      chan struct{}
	addresses []types.Address
	err       error
}

// deriveJob coalesces simultaneous requests for the same credential, session
// and stage range. Results contain only public addresses. The initiating
// context owns the job; waiters can leave independently and retry an interrupted
// job. No account signing lock is held while waiting or deriving.
func (l *RotatingLocks) deriveJob(ctx context.Context, key stageJobKey, derive func() ([]types.Address, error)) ([]types.Address, error) {
	for {
		l.jobsMu.Lock()
		if l.jobs == nil {
			l.jobs = make(map[stageJobKey]*stageJob)
			l.slots = make(chan struct{}, 4)
		}
		if job := l.jobs[key]; job != nil {
			l.jobsMu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-job.done:
				// A foreground leader may have left while a background grant
				// still needs this probe. Retry under the waiter's own context;
				// do not consume its explicit hint cursor without doing work.
				if len(job.addresses) == 0 && ctx.Err() == nil && (job.err == nil || errors.Is(job.err, context.Canceled) || errors.Is(job.err, context.DeadlineExceeded)) {
					continue
				}
				return job.addresses, job.err
			}
		}
		job := &stageJob{done: make(chan struct{})}
		l.jobs[key] = job
		slots := l.slots
		l.jobsMu.Unlock()
		// The single background worker occupies at most one slot. Foreground work
		// therefore has capacity even during speculative lookahead.
		select {
		case slots <- struct{}{}:
			if ctx.Err() == nil {
				job.addresses, job.err = derive()
			} else {
				job.err = ctx.Err()
			}
			<-slots
		case <-ctx.Done():
			job.err = ctx.Err()
		}
		l.jobsMu.Lock()
		delete(l.jobs, key)
		close(job.done)
		l.jobsMu.Unlock()
		return job.addresses, job.err
	}
}
