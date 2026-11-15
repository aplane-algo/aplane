// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package chainread

import (
	"sync"
	"time"
)

// IndexerPauseAfterFailure is how long a network's Indexer is not asked
// after it failed to answer a lookup: it could not be reached, did not
// answer in time, answered outside 2xx, or sent headers too large or a body
// cut short. An answer refused for what its body holds does not count; it
// concerns one account. Lookups run inline in the stage table worker's
// single pass, one per unknown account, so an Indexer that accepts
// connections and stalls would otherwise hold the pass for the lookup
// timeout once per account; with the pause it costs a pass at most one
// timeout a minute. A lookup inside the pause asks nothing and is
// unavailable, and its search runs as it would without an Indexer.
const IndexerPauseAfterFailure = 60 * time.Second

// IndexerPause remembers, per network token, when its Indexer may next be
// asked. It is safe for concurrent use. The zero value is ready.
type IndexerPause struct {
	mu    sync.Mutex
	until map[string]time.Time
	// Now reads the clock; nil means time.Now. Tests set it.
	Now func() time.Time
}

func (p *IndexerPause) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// paused reports whether network's Indexer is paused, and until when.
func (p *IndexerPause) paused(network string) (time.Time, bool) {
	if p == nil {
		return time.Time{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	until, ok := p.until[network]
	if !ok || !p.now().Before(until) {
		return time.Time{}, false
	}
	return until, true
}

// fail pauses network's Indexer for IndexerPauseAfterFailure from now.
func (p *IndexerPause) fail(network string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.until == nil {
		p.until = make(map[string]time.Time)
	}
	p.until[network] = p.now().Add(IndexerPauseAfterFailure)
}
