// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package externalcheck

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/strictjson"
)

// Offline, any string at the echo pointer stands for the request ID, and the
// echo is reported as taken on trust; a missing echo or one of another type
// still fails. Judge, which the cosigner runs, is not loosened by it.
func TestJudgeOfflineTakesTheEchoOnTrust(t *testing.T) {
	cfg := compileChecks(t, `{"s": {"base_url": "https://s.example"}}`, `[
	  {"id": "echoing", "source": "s", "scope": "request", "networks": ["*"], "path": "/x",
	   "echo_pointer": "/request_id", "require": [{"pointer": "/ok", "op": "eq", "bool": true}]},
	  {"id": "plain", "source": "s", "scope": "request", "networks": ["*"], "path": "/x",
	   "require": [{"pointer": "/ok", "op": "eq", "bool": true}]}]`)
	echoing, plain := cfg.ExternalChecks[0], cfg.ExternalChecks[1]
	parse := func(doc string) *strictjson.Node {
		root, err := strictjson.Parse([]byte(doc), judgeLimits)
		if err != nil {
			t.Fatal(err)
		}
		return root
	}
	for _, tt := range []struct {
		name, answer   string
		ok, unverified bool
		detail         string
	}{
		{"any string", `{"ok": true, "request_id": "anything"}`, true, true, ""},
		{"an empty string", `{"ok": true, "request_id": ""}`, true, true, ""},
		{"a rule still decides", `{"ok": false, "request_id": "x"}`, false, true, "/ok = false, want eq true"},
		{"no echo", `{"ok": true}`, false, false, "echo missing: /request_id holds no request ID"},
		{"a number", `{"ok": true, "request_id": 7}`, false, false, "echo missing: /request_id is a number, want the request ID as a string"},
		{"null", `{"ok": true, "request_id": null}`, false, false, "is null"},
	} {
		ok, detail, unverified := JudgeOffline(echoing, nil, parse(tt.answer))
		if ok != tt.ok || unverified != tt.unverified || !strings.Contains(detail, tt.detail) || (ok && detail != "") {
			t.Errorf("%s: JudgeOffline() = %v, %q, %v; want %v, %q, %v", tt.name, ok, detail, unverified, tt.ok, tt.detail, tt.unverified)
		}
	}
	if ok, _, unverified := JudgeOffline(plain, nil, parse(`{"ok": true}`)); !ok || unverified {
		t.Fatalf("a check without an echo: ok %v, unverified %v", ok, unverified)
	}
	// The cosigner's judge still wants the ID it sent.
	if ok, detail := Judge(echoing, nil, parse(`{"ok": true, "request_id": "anything"}`), "sent"); ok || !strings.Contains(detail, "echo mismatch") {
		t.Fatalf("Judge() = %v, %q; want an echo mismatch", ok, detail)
	}
	if ok, _ := Judge(echoing, nil, parse(`{"ok": true, "request_id": ""}`), ""); !ok {
		t.Fatal("Judge() refused an echo equal to the ID it was given")
	}
}

// An answer is accepted offline exactly as the fetcher accepts it.
func TestParseAnswerUsesTheFetchersBounds(t *testing.T) {
	cfg := compileChecks(t, `{"s": {"base_url": "https://s.example", "max_response_bytes": 64}}`,
		`[{"id": "c", "source": "s", "scope": "request", "networks": ["*"], "path": "/x", "require": [{"pointer": "", "op": "present"}]}]`)
	source := cfg.ExternalSources["s"]
	for _, tt := range []struct {
		name, body, want string
	}{
		{"over max_response_bytes", `{"a": "` + strings.Repeat("x", 64) + `"}`, "body over 64 bytes"},
		{"a duplicate key", `{"a": 1, "a": 2}`, "not acceptable JSON"},
		{"two values", `{} {}`, "not acceptable JSON"},
		{"not JSON", `<html>`, "not acceptable JSON"},
		{"empty", ``, "not acceptable JSON"},
		{"a large exponent", `[1e65]`, "not acceptable JSON"},
		{"invalid UTF-8", "[\"\xff\"]", "not acceptable JSON"},
	} {
		if _, err := ParseAnswer([]byte(tt.body), source); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: ParseAnswer() error = %v, want %q", tt.name, err, tt.want)
		}
	}
	// A value at most 64 levels below the root, and number literals of at
	// most 64 characters.
	wide := policy.ExternalSourceV1{MaxResponseBytes: 1 << 10}
	nested := func(levels int) []byte {
		return []byte(strings.Repeat("[", levels) + "1" + strings.Repeat("]", levels))
	}
	if _, err := ParseAnswer(nested(65), wide); err == nil {
		t.Error("a value 65 levels down was accepted")
	}
	if _, err := ParseAnswer(nested(64), wide); err != nil {
		t.Errorf("a value 64 levels down was refused: %v", err)
	}
	if _, err := ParseAnswer([]byte(`[`+strings.Repeat("1", 65)+`]`), wide); err == nil {
		t.Error("a 65-character number was accepted")
	}
	if _, err := ParseAnswer([]byte(`[`+strings.Repeat("1", 64)+`]`), wide); err != nil {
		t.Errorf("a 64-character number was refused: %v", err)
	}
	if root, err := ParseAnswer([]byte(`{"a": 1}`), source); err != nil || root.Kind != strictjson.Object {
		t.Fatalf("ParseAnswer() = %v, %v", root, err)
	}
}

// Each named failure refuses as the cosigner would, with its words, and a
// failure a source cannot have is refused.
func TestFailureOf(t *testing.T) {
	cfg := compileChecks(t, `{
	  "plain": {"base_url": "http://127.0.0.1:8650"},
	  "tokened": {"base_url": "https://t.example", "token": {"header": "X-Key"}, "timeout_ms": 1500, "max_response_bytes": 100},
	  "pinned": {"base_url": "https://p.example", "tls_spki_sha256": ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]}}`, `[
	  {"id": "a", "source": "plain", "scope": "request", "networks": ["*"], "path": "/x", "require": [{"pointer": "", "op": "present"}]},
	  {"id": "b", "source": "tokened", "scope": "request", "networks": ["*"], "path": "/x", "require": [{"pointer": "", "op": "present"}]},
	  {"id": "c", "source": "pinned", "scope": "request", "networks": ["*"], "path": "/x", "require": [{"pointer": "", "op": "present"}]}]`)
	plain, tokened, pinned := cfg.ExternalSources["plain"], cfg.ExternalSources["tokened"], cfg.ExternalSources["pinned"]
	unavailable, noToken := policy.ExternalCheckUnavailableOutcome, policy.ExternalCheckTokenNotSetOutcome
	for _, tt := range []struct {
		name    string
		source  policy.ExternalSourceV1
		outcome string
		detail  string
	}{
		{FailureTimeout, tokened, unavailable, "timeout after 1.5s"},
		{FailureTimeout, plain, unavailable, "timeout after 2s"},
		{FailureUnreachable, plain, unavailable, "the source could not be reached"},
		{FailureStatus, plain, unavailable, "status 503"},
		{FailureTooLarge, tokened, unavailable, "body over 100 bytes"},
		{FailureNotJSON, plain, unavailable, "the answer is not acceptable JSON"},
		{FailureCertificate, tokened, unavailable, "the server's certificate was not accepted"},
		{FailurePinMismatch, pinned, unavailable, "TLS pin mismatch"},
		{FailureTokenNotSet, tokened, noToken, "no token set"},
	} {
		outcome, detail, err := FailureOf(tt.name, tt.source)
		if err != nil || outcome != tt.outcome || detail != tt.detail {
			t.Errorf("FailureOf(%s) = %q, %q, %v; want %q, %q", tt.name, outcome, detail, err, tt.outcome, tt.detail)
		}
	}
	for _, tt := range []struct {
		name   string
		source policy.ExternalSourceV1
	}{
		{FailureCertificate, plain},
		{FailurePinMismatch, tokened},
		{FailureTokenNotSet, plain},
		{"slow", plain},
	} {
		if _, _, err := FailureOf(tt.name, tt.source); err == nil {
			t.Errorf("FailureOf(%s) accepted a failure the source cannot have", tt.name)
		}
	}
	if len(Failures) != 8 {
		t.Fatalf("Failures = %v", Failures)
	}
}
