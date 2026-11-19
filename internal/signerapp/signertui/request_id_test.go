// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"sync"
	"testing"
)

// Request IDs tie replies and failures to the request that is waiting, so no
// two may be equal, even when named within one tick of the clock: the same
// nanosecond on two cores, or a clock coarser than a nanosecond.
func TestRequestIDsAreDistinctWithinOneClockTick(t *testing.T) {
	const workers, each = 8, 20000
	ids := make([][]string, workers)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				ids[w] = append(ids[w], newRequestID("gen"))
			}
		}()
	}
	wg.Wait()
	seen := make(map[string]bool, workers*each)
	for _, batch := range ids {
		for _, id := range batch {
			if seen[id] {
				t.Fatalf("request ID %q named twice", id)
			}
			seen[id] = true
		}
	}
}
