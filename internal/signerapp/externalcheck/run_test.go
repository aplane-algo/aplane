// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package externalcheck

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/policy"
)

// source is a stub REST source: it answers each path with the JSON given for
// it and records what it was asked.
type source struct {
	*httptest.Server
	mu      sync.Mutex
	answers map[string]string
	paths   []string
	tokens  []string
	hits    atomic.Int32
}

func newSource(t *testing.T, answers map[string]string) *source {
	t.Helper()
	s := &source{answers: answers}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.RequestURI())
		s.tokens = append(s.tokens, r.Header.Get("X-Api-Key"))
		answer, ok := s.answers[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		if answer == "hang" {
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte(strings.ReplaceAll(answer, "$REQUEST_ID", r.Header.Get(RequestIDHeader))))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *source) sources(extra string) string {
	return fmt.Sprintf(`{"s": {"base_url": %q%s}}`, s.URL, extra)
}

const screenCheck = `{"id": "screen", "source": "s", "scope": "movement", "networks": ["*"],
  "movement_kinds": ["pay"], "path": "/screen/{destination}",
  "require": [{"pointer": "/sanctioned", "op": "eq", "bool": false}, {"pointer": "/score", "op": "le", "number": "30"}]}`

const switchCheck = `{"id": "switch", "source": "s", "scope": "request", "networks": ["*"], "path": "/switch",
  "require": [{"pointer": "/enabled", "op": "eq", "bool": true}]}`

func TestRunPassesWhenEveryCheckHolds(t *testing.T) {
	src := newSource(t, map[string]string{
		"/switch":                     `{"enabled": true}`,
		"/screen/" + addr(2).String(): `{"sanctioned": false, "score": 12}`,
		"/screen/" + addr(3).String(): `{"sanctioned": false, "score": 30}`,
	})
	cfg := compileChecks(t, src.sources(""), "["+switchCheck+","+screenCheck+"]")
	runner := &Runner{Fetcher: &Fetcher{}}
	summary, refusal := runner.Run(context.Background(), cfg, requestOf(payment(addr(1), addr(2), 5), payment(addr(1), addr(3), 5)))
	if refusal != nil {
		t.Fatalf("Run() refusal = %s", refusal.AuditReason())
	}
	if !slices.Equal(summary.CheckIDs, []string{"switch", "screen"}) || summary.Lookups != 3 {
		t.Fatalf("summary = %+v, want switch and screen over 3 lookups", summary)
	}
}

func TestRunRefusesWhenARuleDoesNotHold(t *testing.T) {
	src := newSource(t, map[string]string{
		"/switch":                     `{"enabled": true}`,
		"/screen/" + addr(2).String(): `{"sanctioned": false, "score": 12}`,
		"/screen/" + addr(3).String(): `{"sanctioned": false, "score": 72}`,
	})
	cfg := compileChecks(t, src.sources(""), "["+switchCheck+","+screenCheck+"]")
	_, refusal := (&Runner{Fetcher: &Fetcher{}}).Run(context.Background(), cfg,
		requestOf(payment(addr(1), addr(2), 5), payment(addr(1), addr(3), 5)))
	if refusal == nil {
		t.Fatal("Run() refusal = nil")
	}
	if refusal.RuleID() != "external_check:screen" || refusal.Unit != "the pay movement of transaction 1" ||
		refusal.Detail != "/score = 72, want le 30" || refusal.Source != "s" || refusal.Path != "/screen/"+addr(3).String() {
		t.Fatalf("refusal = %+v", refusal)
	}
}

func TestRunRefusesWhenALookupFails(t *testing.T) {
	// /switch is not served: one failed lookup refuses the request, under
	// the check that needed it, though the other lookups would pass.
	src := newSource(t, map[string]string{"/screen/" + addr(2).String(): `{"sanctioned": false, "score": 1}`})
	cfg := compileChecks(t, src.sources(""), "["+screenCheck+","+switchCheck+"]")
	_, refusal := (&Runner{Fetcher: &Fetcher{}}).Run(context.Background(), cfg, requestOf(payment(addr(1), addr(2), 5)))
	if refusal == nil || refusal.RuleID() != "external_check:switch:unavailable" || refusal.Detail != "status 404" {
		t.Fatalf("refusal = %+v, want switch unavailable with status 404", refusal)
	}
}

func TestRunTokens(t *testing.T) {
	src := newSource(t, map[string]string{"/switch": `{"enabled": true}`})
	cfg := compileChecks(t, src.sources(`, "token": {"header": "X-Api-Key"}`), "["+switchCheck+"]")
	req := requestOf(payment(addr(1), addr(2), 5))

	// No token: refused before any connection is made.
	for name, tokens := range map[string]TokenFor{
		"no token store":          nil,
		"no token for the source": func(string, string) (string, bool) { return "", false },
	} {
		_, refusal := (&Runner{Fetcher: &Fetcher{}, Tokens: tokens}).Run(context.Background(), cfg, req)
		if refusal == nil || refusal.RuleID() != "external_check:switch:token_not_set" || refusal.Detail != "no token set" {
			t.Fatalf("%s: refusal = %+v", name, refusal)
		}
	}
	if got := src.hits.Load(); got != 0 {
		t.Fatalf("%d requests reached the source without a token, want none", got)
	}

	// The token is looked up under the governing document's key.
	var asked []string
	tokens := func(selector, name string) (string, bool) {
		asked = append(asked, selector+"/"+name)
		return "s3cret", true
	}
	if _, refusal := (&Runner{Fetcher: &Fetcher{}, Tokens: tokens}).Run(context.Background(), cfg, req); refusal != nil {
		t.Fatalf("Run() refusal = %s", refusal.AuditReason())
	}
	if !slices.Equal(asked, []string{testWitnessKey + "/s"}) || !slices.Equal(src.tokens, []string{"s3cret"}) {
		t.Fatalf("token asked as %v and sent as %v", asked, src.tokens)
	}
	if strings.Contains((&Refusal{CheckID: "c", Detail: "x"}).AuditReason(), "s3cret") {
		t.Fatal("unreachable")
	}
}

// Two checks that render the same request share one lookup, and each keeps
// its own echo requirement.
func TestRunMergedLookupsKeepEachChecksEcho(t *testing.T) {
	checks := `[
	  {"id": "plain", "source": "s", "scope": "request", "networks": ["*"], "path": "/both",
	   "require": [{"pointer": "/ok", "op": "eq", "bool": true}]},
	  {"id": "echoing", "source": "s", "scope": "request", "networks": ["*"], "path": "/both",
	   "echo_pointer": "/request_id", "require": [{"pointer": "/ok", "op": "eq", "bool": true}]}]`
	req := requestOf(payment(addr(1), addr(2), 5))

	echo := newSource(t, map[string]string{"/both": `{"ok": true, "request_id": "$REQUEST_ID"}`})
	summary, refusal := (&Runner{Fetcher: &Fetcher{}}).Run(context.Background(), compileChecks(t, echo.sources(""), checks), req)
	if refusal != nil || summary.Lookups != 1 || echo.hits.Load() != 1 {
		t.Fatalf("summary = %+v, refusal = %+v, hits = %d; want one shared lookup that passes", summary, refusal, echo.hits.Load())
	}

	silent := newSource(t, map[string]string{"/both": `{"ok": true}`})
	_, refusal = (&Runner{Fetcher: &Fetcher{}}).Run(context.Background(), compileChecks(t, silent.sources(""), checks), req)
	if refusal == nil || refusal.CheckID != "echoing" || !strings.Contains(refusal.Detail, "echo mismatch") {
		t.Fatalf("refusal = %+v, want the echoing check's mismatch", refusal)
	}
}

// A canceled context, as when the node locks, ends the lookups at once.
func TestRunStopsWhenItsContextEnds(t *testing.T) {
	src := newSource(t, map[string]string{"/switch": "hang"})
	cfg := compileChecks(t, src.sources(`, "timeout_ms": 10000`), "["+switchCheck+"]")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *Refusal, 1)
	go func() {
		_, refusal := (&Runner{Fetcher: &Fetcher{}}).Run(ctx, cfg, requestOf(payment(addr(1), addr(2), 5)))
		done <- refusal
	}()
	deadline := time.Now().Add(2 * time.Second)
	for src.hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	start := time.Now()
	cancel()
	select {
	case refusal := <-done:
		if refusal == nil || refusal.Outcome != policy.ExternalCheckUnavailableOutcome || refusal.Detail != "canceled" {
			t.Fatalf("refusal = %+v, want unavailable: canceled", refusal)
		}
		if waited := time.Since(start); waited > time.Second {
			t.Fatalf("Run() returned %s after the cancel", waited)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run() did not return after its context ended")
	}

	// A context that has already ended makes no lookup.
	before := src.hits.Load()
	if _, refusal := (&Runner{Fetcher: &Fetcher{}}).Run(ctx, cfg, requestOf(payment(addr(1), addr(2), 5))); refusal == nil {
		t.Fatal("Run() passed under an ended context")
	}
	if src.hits.Load() != before {
		t.Fatal("a lookup was made under an ended context")
	}
}
