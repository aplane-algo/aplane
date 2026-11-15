// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package chainread

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// fakeClock is a clock a test moves by hand.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// countingServer answers with handler and counts requests.
func countingServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

func stall(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }

// An Indexer that stalls costs one timeout, then is not asked for a minute:
// the lookups of the other accounts in the window ask nothing and come back
// unavailable at once, so each search runs without it. After the window a
// new lookup asks again.
func TestLookupPausesTheNetworkAfterAFailedRead(t *testing.T) {
	srv, requests := countingServer(t, stall)
	clock := &fakeClock{now: time.Unix(1_000_000, 0)}
	r := lookupReaderFor(srv)
	r.LookupTimeout = 100 * time.Millisecond
	r.Pause = &IndexerPause{Now: clock.Now}

	for i := 0; i < 5; i++ {
		account := types.Address{0xB0, byte(i), 31: 1}
		started := time.Now()
		got, err := r.LookupLastRotation(context.Background(), testnetGenesis, account, lookupAuthorizer)
		if err != nil || got.Outcome != LookupUnavailable {
			t.Fatalf("lookup %d = %+v, %v; want unavailable", i, got, err)
		}
		took := time.Since(started)
		switch {
		case i == 0 && !strings.Contains(got.Reason, "in time"):
			t.Fatalf("first lookup's reason = %q, want the timeout", got.Reason)
		case i > 0 && (!strings.Contains(got.Reason, "less than") || took > 50*time.Millisecond):
			t.Fatalf("lookup %d in the pause: %q after %v, want an answer at once", i, got.Reason, took)
		}
		assertNoToken(t, got)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("the Indexer saw %d requests in the pause, want 1", n)
	}
	clock.advance(IndexerPauseAfterFailure - time.Second)
	if got, _ := r.LookupLastRotation(context.Background(), testnetGenesis, lookupAccount, lookupAuthorizer); got.Outcome != LookupUnavailable || requests.Load() != 1 {
		t.Fatalf("just inside the pause: %+v after %d requests", got, requests.Load())
	}
	clock.advance(2 * time.Second)
	if got, _ := r.LookupLastRotation(context.Background(), testnetGenesis, lookupAccount, lookupAuthorizer); got.Outcome != LookupUnavailable || requests.Load() != 2 {
		t.Fatalf("after the pause: %+v after %d requests, want a new request", got, requests.Load())
	}
}

// Any unavailable answer pauses the network, a refused one included.
func TestLookupPausesAfterARefusedAnswer(t *testing.T) {
	srv, requests := countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	r := lookupReaderFor(srv)
	r.Pause = &IndexerPause{}
	for i := 0; i < 3; i++ {
		if got, _ := r.LookupLastRotation(context.Background(), testnetGenesis, lookupAccount, lookupAuthorizer); got.Outcome != LookupUnavailable {
			t.Fatalf("lookup %d = %+v", i, got)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("requests = %d, want 1", requests.Load())
	}
}

// A read the Indexer answered does not pause it, whatever the outcome.
func TestLookupAnsweredDoesNotPause(t *testing.T) {
	good := jsonBody(t, map[string]any{"transactions": []any{spend(lookupAccount, lookupAuthorizer, stageProgram(7, "x"), false)}})
	srv, requests := countingServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(good) })
	r := lookupReaderFor(srv)
	r.Pause = &IndexerPause{}
	if got, _ := r.LookupLastRotation(context.Background(), testnetGenesis, lookupAccount, lookupAuthorizer); got.Outcome != LookupCandidate {
		t.Fatalf("lookup = %+v", got)
	}
	// Another account: no outgoing rekey, still an answer.
	if got, _ := r.LookupLastRotation(context.Background(), testnetGenesis, otherAddress, lookupAuthorizer); got.Outcome != LookupNoOutgoingRekey {
		t.Fatalf("lookup = %+v", got)
	}
	if got, _ := r.LookupLastRotation(context.Background(), testnetGenesis, lookupAccount, lookupAuthorizer); got.Outcome != LookupCandidate {
		t.Fatalf("lookup = %+v", got)
	}
	if requests.Load() != 3 {
		t.Fatalf("requests = %d, want 3", requests.Load())
	}
}

// A lookup its caller cancels, as a lock does, does not pause the Indexer.
func TestLookupCancelledByItsCallerDoesNotPause(t *testing.T) {
	srv, requests := countingServer(t, stall)
	r := lookupReaderFor(srv)
	r.Pause = &IndexerPause{}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if got, _ := r.LookupLastRotation(ctx, testnetGenesis, lookupAccount, lookupAuthorizer); got.Outcome != LookupUnavailable {
		t.Fatalf("lookup = %+v", got)
	}
	r.LookupTimeout = 50 * time.Millisecond
	if got, _ := r.LookupLastRotation(context.Background(), testnetGenesis, lookupAccount, lookupAuthorizer); got.Outcome != LookupUnavailable || requests.Load() != 2 {
		t.Fatalf("after a cancelled lookup: %+v after %d requests, want a new request", got, requests.Load())
	}
}

func TestIndexerPauseIsPerNetwork(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_000_000, 0)}
	p := &IndexerPause{Now: clock.Now}
	if _, paused := p.paused("testnet"); paused {
		t.Fatal("paused before any failure")
	}
	p.fail("testnet")
	if _, paused := p.paused("testnet"); !paused {
		t.Fatal("testnet not paused after its failure")
	}
	if _, paused := p.paused("mainnet"); paused {
		t.Fatal("mainnet paused by testnet's failure")
	}
	clock.advance(IndexerPauseAfterFailure)
	if _, paused := p.paused("testnet"); paused {
		t.Fatal("still paused at the end of the window")
	}
	var none *IndexerPause
	none.fail("testnet")
	if _, paused := none.paused("testnet"); paused {
		t.Fatal("a nil pause paused")
	}
}
