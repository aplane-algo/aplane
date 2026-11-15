// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package chainread

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// rawAnswer writes head and body straight to the connection and closes it,
// so a test can send what net/http's server would not.
func rawAnswer(head string, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = buf.WriteString(head)
		_, _ = buf.Write(body)
		_ = buf.Flush()
		_ = conn.Close()
	}
}

func goodAnswer(t *testing.T) []byte {
	t.Helper()
	return jsonBody(t, map[string]any{"transactions": []any{spend(lookupAccount, lookupAuthorizer, stageProgram(7, "x"), false)}})
}

// truncations are answers the transport knows were cut short, each holding
// a whole, valid document that would otherwise give a candidate.
func truncations(t *testing.T) map[string]http.HandlerFunc {
	good := goodAnswer(t)
	return map[string]http.HandlerFunc{
		"Content-Length longer than the body": rawAnswer(
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "+strconv.Itoa(len(good)+100)+"\r\n\r\n", good),
		"chunked stream without its end": rawAnswer(
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"+strconv.FormatInt(int64(len(good)), 16)+"\r\n", append(append([]byte(nil), good...), "\r\n"...)),
	}
}

// A body the transport reports cut short is not decoded as complete, even
// when the part that arrived is a whole document.
func TestLookupRefusesABodyTheTransportReportsCutShort(t *testing.T) {
	for name, handler := range truncations(t) {
		t.Run(name, func(t *testing.T) {
			idx := &fakeIndexer{handler: handler}
			got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer)
			if got.Outcome != LookupUnavailable {
				t.Fatalf("lookup = %+v, want unavailable", got)
			}
		})
	}
}

// An answer refused for what its body holds concerns that account alone: the
// next account's lookup still asks the Indexer.
func TestLookupBodyRefusalsDoNotPause(t *testing.T) {
	good := goodAnswer(t)
	// Sent by the first account looked up, so its lookup reaches the check.
	unconfirmed := spend(otherAddress, lookupAuthorizer, stageProgram(7, "x"), false)
	delete(unconfirmed, "confirmed-round")
	var past []any
	for i := 0; i <= lookupLimit; i++ {
		past = append(past, clawback(lookupAccount))
	}
	for name, body := range map[string][]byte{
		"over the cap":              append(good, make([]byte, MaxIndexerResponseBytes)...),
		"invalid JSON":              []byte(`{"transactions":[`),
		"more results than asked":   jsonBody(t, map[string]any{"transactions": past}),
		"a repeated key":            []byte(`{"transactions":[],"transactions":[]}`),
		"a field over its bound":    []byte(`{"transactions":[{"sender":"` + strings.Repeat("A", addressLength+1) + `"}]}`),
		"no confirmed round":        jsonBody(t, map[string]any{"transactions": []any{unconfirmed}}),
		"a body in the wrong shape": []byte(`[]`),
	} {
		t.Run(name, func(t *testing.T) {
			first := body
			srv, requests := countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
				if first != nil {
					_, _ = w.Write(first)
					first = nil
					return
				}
				_, _ = w.Write(good)
			})
			r := lookupReaderFor(srv)
			r.Pause = &IndexerPause{}
			if got, _ := r.LookupLastRotation(context.Background(), testnetGenesis, otherAddress, lookupAuthorizer); got.Outcome != LookupUnavailable {
				t.Fatalf("first account's lookup = %+v, want unavailable", got)
			}
			got, _ := r.LookupLastRotation(context.Background(), testnetGenesis, lookupAccount, lookupAuthorizer)
			if got.Outcome != LookupCandidate || requests.Load() != 2 {
				t.Fatalf("next account's lookup = %+v after %d requests, want a candidate from its own request", got, requests.Load())
			}
		})
	}
}

// A failure to reach the Indexer or be answered by it pauses the network:
// the next account's lookup asks nothing.
func TestLookupAnswerFailuresPause(t *testing.T) {
	handlers := map[string]http.HandlerFunc{
		"HTTP 503": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "down", http.StatusServiceUnavailable)
		},
		"a redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://indexer.elsewhere.test/v2/transactions", http.StatusFound)
		},
		"oversized headers": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Pad", strings.Repeat("h", 1<<20))
			_, _ = w.Write([]byte(`{"transactions":[]}`))
		},
		"the lookup's timeout": stall,
		"a dropped connection": func(w http.ResponseWriter, _ *http.Request) {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}
		},
	}
	for name, handler := range truncations(t) {
		handlers[name] = handler
	}
	for name, handler := range handlers {
		t.Run(name, func(t *testing.T) {
			srv, requests := countingServer(t, handler)
			r := lookupReaderFor(srv)
			r.LookupTimeout = 100 * time.Millisecond
			r.Pause = &IndexerPause{}
			assertPausesAfterOne(t, r)
			if requests.Load() != 1 {
				t.Fatalf("requests = %d, want 1", requests.Load())
			}
		})
	}
	t.Run("connection refused", func(t *testing.T) {
		closed := httptest.NewServer(http.NotFoundHandler())
		closed.Close()
		r := lookupReaderFor(closed)
		r.Pause = &IndexerPause{}
		assertPausesAfterOne(t, r)
	})
	t.Run("a TLS error", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.NotFoundHandler())
		t.Cleanup(srv.Close)
		r := lookupReaderFor(srv)
		r.Pause = &IndexerPause{}
		assertPausesAfterOne(t, r)
	})
}

func assertPausesAfterOne(t *testing.T, r Reader) {
	t.Helper()
	if got, _ := r.LookupLastRotation(context.Background(), testnetGenesis, otherAddress, lookupAuthorizer); got.Outcome != LookupUnavailable || strings.Contains(got.Reason, "less than") {
		t.Fatalf("first lookup = %+v, want unavailable from its request", got)
	}
	if got, _ := r.LookupLastRotation(context.Background(), testnetGenesis, lookupAccount, lookupAuthorizer); got.Outcome != LookupUnavailable || !strings.Contains(got.Reason, "less than") {
		t.Fatalf("next lookup = %+v, want it paused", got)
	}
}
