// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
)

const externalFixtureKey = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"

// externalFixture returns the external-checks contract fixture as a JSON
// tree a test can change before decoding.
func externalFixture(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "contracts", "policy", "v1", "cosigner_key_external_checks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func decodeExternalDoc(t *testing.T, doc map[string]any) (*PolicyV1, error) {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return DecodePolicyV1(data, externalFixtureKey, noderole.RoleCosigner)
}

func externalCheckAt(doc map[string]any, i int) map[string]any {
	return doc["external_checks"].([]any)[i].(map[string]any)
}

func externalRuleAt(doc map[string]any, check, rule int) map[string]any {
	return externalCheckAt(doc, check)["require"].([]any)[rule].(map[string]any)
}

func externalSourceNamed(doc map[string]any, name string) map[string]any {
	return doc["external_sources"].(map[string]any)[name].(map[string]any)
}

func TestExternalChecksDecode(t *testing.T) {
	doc, err := decodeExternalDoc(t, externalFixture(t))
	if err != nil {
		t.Fatalf("DecodePolicyV1() error = %v", err)
	}
	if got := doc.ExternalSourceNames(); !slices.Equal(got, []string{"ops", "screening", "treasury"}) {
		t.Fatalf("source names = %v", got)
	}
	ops := doc.ExternalSources["ops"]
	if ops.Token != nil || ops.TimeoutMS != DefaultExternalTimeoutMS || ops.MaxResponseBytes != DefaultExternalRespBytes {
		t.Fatalf("ops source = %+v, want no token and the defaults", ops)
	}
	screening := doc.ExternalSources["screening"]
	if screening.Token == nil || screening.Token.Header != "Authorization" || screening.Token.Prefix != "Bearer " {
		t.Fatalf("screening token = %+v", screening.Token)
	}
	if pins := doc.ExternalSources["treasury"].TLSPins; len(pins) != 1 || pins[0] != [32]byte{} {
		t.Fatalf("treasury pins = %v, want one all-zero pin", pins)
	}
	if len(doc.ExternalChecks) != 3 {
		t.Fatalf("decoded %d checks, want 3", len(doc.ExternalChecks))
	}
	screen := doc.ExternalChecks[1]
	if screen.ID != "screen-destination" || screen.Scope != ExternalScopeMovement || screen.Source != "screening" {
		t.Fatalf("check = %+v", screen)
	}
	if !screen.CoversNetwork("mainnet") || screen.CoversNetwork("testnet") {
		t.Fatal("screen-destination must cover mainnet only")
	}
	if !screen.CoversMovementKind(TransferMovementPay) || screen.CoversMovementKind(TransferMovementPayClose) {
		t.Fatal("screen-destination must cover pay and not pay_close")
	}
	wantParts := []ExternalTemplatePart{{Literal: "/v2/addresses/"}, {Fact: "destination"}}
	if !slices.Equal(screen.Path.Parts, wantParts) {
		t.Fatalf("path parts = %+v, want %+v", screen.Path.Parts, wantParts)
	}
	if len(screen.Query) != 1 || screen.Query[0].Name != "chain" || screen.Query[0].Value.Text != "algorand" {
		t.Fatalf("query = %+v", screen.Query)
	}
	if got := *screen.Require[1].Number; screen.Require[1].Op != ExternalOpLe || got != "30" {
		t.Fatalf("rule = %+v", screen.Require[1])
	}
	allowance := doc.ExternalChecks[2]
	if allowance.EchoPointer == nil || *allowance.EchoPointer != "/request_id" {
		t.Fatalf("echo pointer = %v", allowance.EchoPointer)
	}
	if got := allowance.UsedFacts(); !slices.Equal(got, []string{"source", "asset", "amount"}) {
		t.Fatalf("used facts = %v", got)
	}
	if allowance.Require[1].Op != ExternalOpAbsent {
		t.Fatalf("rule = %+v", allowance.Require[1])
	}
	if !doc.ExternalChecks[0].CoversNetwork("anything") || !doc.ExternalChecks[0].CoversMovementKind(TransferMovementClawback) {
		t.Fatal("a wildcard check with no movement_kinds covers every network and kind")
	}
}

// Every rejection names the JSON Pointer of the value an author would change.
func TestExternalChecksRejections(t *testing.T) {
	for _, tt := range []struct {
		name    string
		change  func(doc map[string]any)
		pointer string
		msg     string
	}{
		{"sources without checks", func(d map[string]any) { delete(d, "external_checks") },
			"/external_sources", "needs external_checks"},
		{"checks without sources", func(d map[string]any) { delete(d, "external_sources") },
			"/external_checks", "needs external_sources"},
		{"unused source", func(d map[string]any) {
			d["external_sources"].(map[string]any)["spare"] = map[string]any{"base_url": "https://spare.example"}
		}, "/external_sources/spare", "no check uses"},
		{"unknown source", func(d map[string]any) { externalCheckAt(d, 0)["source"] = "nowhere" },
			"/external_checks/0/source", "unknown external source"},
		{"duplicate id", func(d map[string]any) { externalCheckAt(d, 1)["id"] = "ops-switch" },
			"/external_checks/1/id", "duplicate check id"},
		{"bad source name", func(d map[string]any) {
			sources := d["external_sources"].(map[string]any)
			sources["Ops"] = sources["ops"]
		}, "/external_sources/Ops", "source name"},
		{"http to a remote host", func(d map[string]any) { externalSourceNamed(d, "ops")["base_url"] = "http://ops.example.com" },
			"/external_sources/ops/base_url", "loopback"},
		{"scheme", func(d map[string]any) { externalSourceNamed(d, "ops")["base_url"] = "ftp://127.0.0.1" },
			"/external_sources/ops/base_url", "https URL"},
		{"user info", func(d map[string]any) {
			externalSourceNamed(d, "screening")["base_url"] = "https://u:p@screen.example.com"
		},
			"/external_sources/screening/base_url", "user info"},
		{"query in base url", func(d map[string]any) {
			externalSourceNamed(d, "screening")["base_url"] = "https://screen.example.com/api?x=1"
		},
			"/external_sources/screening/base_url", "query or a fragment"},
		{"percent in base url", func(d map[string]any) {
			externalSourceNamed(d, "screening")["base_url"] = "https://screen.example.com/a%2Fb"
		},
			"/external_sources/screening/base_url", "percent-encoding"},
		{"pins on http", func(d map[string]any) {
			externalSourceNamed(d, "ops")["tls_spki_sha256"] = []any{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
		}, "/external_sources/ops/tls_spki_sha256", "no TLS key"},
		{"unpadded pin", func(d map[string]any) {
			externalSourceNamed(d, "treasury")["tls_spki_sha256"] = []any{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
		}, "/external_sources/treasury/tls_spki_sha256/0", "padded standard base64"},
		{"short pin", func(d map[string]any) {
			externalSourceNamed(d, "treasury")["tls_spki_sha256"] = []any{"AAAA"}
		}, "/external_sources/treasury/tls_spki_sha256/0", "32-byte"},
		{"reserved token header", func(d map[string]any) {
			externalSourceNamed(d, "screening")["token"] = map[string]any{"header": "X-Aplane-Request-ID"}
		}, "/external_sources/screening/token/header", "set by the cosigner"},
		{"token header with a space", func(d map[string]any) {
			externalSourceNamed(d, "screening")["token"] = map[string]any{"header": "X Key"}
		}, "/external_sources/screening/token/header", "not a header name"},
		{"token value in the document", func(d map[string]any) {
			externalSourceNamed(d, "screening")["token"] = map[string]any{"header": "X-Key", "value": "secret"}
		}, "/external_sources/screening/token/value", "unknown field"},
		{"prefix with a newline", func(d map[string]any) {
			externalSourceNamed(d, "screening")["token"] = map[string]any{"header": "X-Key", "prefix": "a\nb"}
		}, "/external_sources/screening/token/prefix", "printable ASCII"},
		{"timeout too short", func(d map[string]any) { externalSourceNamed(d, "screening")["timeout_ms"] = 50 },
			"/external_sources/screening/timeout_ms", "100 through 10000"},
		{"timeout as a string", func(d map[string]any) { externalSourceNamed(d, "screening")["timeout_ms"] = "2000" },
			"/external_sources/screening/timeout_ms", "whole number"},
		{"answer cap too large", func(d map[string]any) { externalSourceNamed(d, "screening")["max_response_bytes"] = 1<<20 + 1 },
			"/external_sources/screening/max_response_bytes", "1 through 1048576"},
		{"scope", func(d map[string]any) { externalCheckAt(d, 0)["scope"] = "group" },
			"/external_checks/0/scope", "request, transaction, movement"},
		{"movement kinds off a movement check", func(d map[string]any) { externalCheckAt(d, 0)["movement_kinds"] = []any{"pay"} },
			"/external_checks/0/movement_kinds", "only for a check of scope movement"},
		{"unknown movement kind", func(d map[string]any) { externalCheckAt(d, 1)["movement_kinds"] = []any{"swap"} },
			"/external_checks/1/movement_kinds/0", "unknown movement kind"},
		{"path without a leading slash", func(d map[string]any) { externalCheckAt(d, 0)["path"] = "signing" },
			"/external_checks/0/path", "must start with"},
		{"percent in a path", func(d map[string]any) { externalCheckAt(d, 0)["path"] = "/a/%2e%2e/b" },
			"/external_checks/0/path", "percent-encoding"},
		{"dot segment", func(d map[string]any) { externalCheckAt(d, 0)["path"] = "/a/../b" },
			"/external_checks/0/path", `".." segment`},
		{"empty segment", func(d map[string]any) { externalCheckAt(d, 0)["path"] = "/a//b" },
			"/external_checks/0/path", "empty segment"},
		{"query mark in a path", func(d map[string]any) { externalCheckAt(d, 0)["path"] = "/a?b=1" },
			"/external_checks/0/path", `must not contain "?"`},
		{"fact of a deeper scope", func(d map[string]any) { externalCheckAt(d, 0)["path"] = "/signing/{destination}" },
			"/external_checks/0/path", "belongs to scope movement"},
		{"unknown fact", func(d map[string]any) { externalCheckAt(d, 1)["path"] = "/x/{note}" },
			"/external_checks/1/path", `unknown fact "note"`},
		{"unclosed placeholder", func(d map[string]any) { externalCheckAt(d, 1)["path"] = "/x/{destination" },
			"/external_checks/1/path", `without a matching "}"`},
		{"stray closing brace", func(d map[string]any) { externalCheckAt(d, 1)["path"] = "/x/destination}" },
			"/external_checks/1/path", `without a matching "{"`},
		{"empty query name", func(d map[string]any) { externalCheckAt(d, 1)["query"] = map[string]any{"": "x"} },
			"/external_checks/1/query/", "query parameter name"},
		{"fact of a deeper scope in a query", func(d map[string]any) { externalCheckAt(d, 0)["query"] = map[string]any{"a": "{amount}"} },
			"/external_checks/0/query/a", "belongs to scope movement"},
		{"pointer without a slash", func(d map[string]any) { externalRuleAt(d, 0, 0)["pointer"] = "enabled" },
			"/external_checks/0/require/0/pointer", "starts with"},
		{"pointer with a bare tilde", func(d map[string]any) { externalRuleAt(d, 0, 0)["pointer"] = "/a~b" },
			"/external_checks/0/require/0/pointer", "~0"},
		{"echo pointer", func(d map[string]any) { externalCheckAt(d, 2)["echo_pointer"] = "id" },
			"/external_checks/2/echo_pointer", "starts with"},
		{"unknown op", func(d map[string]any) { externalRuleAt(d, 0, 0)["op"] = "matches" },
			"/external_checks/0/require/0/op", "must be one of"},
		{"no operand", func(d map[string]any) { delete(externalRuleAt(d, 0, 0), "bool") },
			"/external_checks/0/require/0", "needs exactly one of"},
		{"two operands", func(d map[string]any) { externalRuleAt(d, 0, 0)["string"] = "x" },
			"/external_checks/0/require/0", "needs exactly one of"},
		{"operand on absent", func(d map[string]any) { externalRuleAt(d, 2, 1)["bool"] = true },
			"/external_checks/2/require/1/bool", "takes no operand"},
		{"ordering a string", func(d map[string]any) {
			rule := externalRuleAt(d, 1, 1)
			delete(rule, "number")
			rule["string"] = "30"
		}, "/external_checks/1/require/1/string", "takes number, fact"},
		{"list on eq", func(d map[string]any) { externalRuleAt(d, 1, 2)["op"] = "eq" },
			"/external_checks/1/require/2/strings", "takes number, string, bool, fact"},
		{"number as a JSON number", func(d map[string]any) { externalRuleAt(d, 1, 1)["number"] = 30 },
			"/external_checks/1/require/1/number", "decimal string"},
		{"number with an exponent", func(d map[string]any) { externalRuleAt(d, 1, 1)["number"] = "3e1" },
			"/external_checks/1/require/1/number", "plain decimal"},
		{"number with a leading zero", func(d map[string]any) { externalRuleAt(d, 1, 1)["number"] = "030" },
			"/external_checks/1/require/1/number", "plain decimal"},
		{"number too long", func(d map[string]any) { externalRuleAt(d, 1, 1)["number"] = strings.Repeat("9", 41) },
			"/external_checks/1/require/1/number", "at most 40 digits"},
		{"ordering by a text fact", func(d map[string]any) { externalRuleAt(d, 2, 0)["fact"] = "destination" },
			"/external_checks/2/require/0/fact", "is not a number"},
		{"fact operand of a deeper scope", func(d map[string]any) {
			rule := externalRuleAt(d, 0, 0)
			delete(rule, "bool")
			rule["fact"] = "amount"
		}, "/external_checks/0/require/0/fact", "belongs to scope movement"},
		{"unknown rule field", func(d map[string]any) { externalRuleAt(d, 0, 0)["regex"] = "x" },
			"/external_checks/0/require/0/regex", "unknown field"},
		{"too many rules", func(d map[string]any) {
			check := externalCheckAt(d, 0)
			rule := check["require"].([]any)[0]
			check["require"] = slices.Repeat([]any{rule}, MaxExternalRules+1)
		}, "/external_checks/0/require", "at most 8 rules"},
		{"too many checks", func(d map[string]any) {
			d["external_checks"] = slices.Repeat([]any{externalCheckAt(d, 0)}, MaxExternalChecks+1)
		}, "/external_checks", "at most 8 external checks"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			doc := externalFixture(t)
			tt.change(doc)
			_, err := decodeExternalDoc(t, doc)
			var docErr *DocumentError
			if !errors.As(err, &docErr) {
				t.Fatalf("error = %v, want a DocumentError", err)
			}
			if docErr.Pointer != tt.pointer || !strings.Contains(docErr.Msg, tt.msg) {
				t.Fatalf("error = %q at %q, want %q at %q", docErr.Msg, docErr.Pointer, tt.msg, tt.pointer)
			}
		})
	}
}

// A signer document carries neither field.
func TestExternalChecksAreCosignerOnly(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "contracts", "policy", "v1", "invalid", "signer_external_checks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var head struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		t.Fatal(err)
	}
	_, err = DecodePolicyV1(data, head.Key, noderole.RoleSigner)
	var docErr *DocumentError
	if !errors.As(err, &docErr) || docErr.Pointer != "/external_sources" || !strings.Contains(docErr.Msg, "not accepted in a signer document") {
		t.Fatalf("error = %v, want external_sources refused on a signer", err)
	}
}

func TestExternalLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost": true, "127.0.0.1": true, "127.0.0.2": true, "::1": true,
		"example.com": false, "10.0.0.1": false, "localhost.example.com": false, "": false,
	} {
		if got := IsExternalLoopbackHost(host); got != want {
			t.Errorf("IsExternalLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestExternalFactScopes(t *testing.T) {
	for _, tt := range []struct {
		scope ExternalCheckScope
		name  string
		ok    bool
	}{
		{ExternalScopeRequest, "network", true},
		{ExternalScopeRequest, "sender", false},
		{ExternalScopeTransaction, "witness_key", true},
		{ExternalScopeTransaction, "rekey_to", true},
		{ExternalScopeTransaction, "amount", false},
		{ExternalScopeMovement, "fee", true},
		{ExternalScopeMovement, "amount", true},
		{ExternalScopeMovement, "note", false},
		{"group", "network", false},
	} {
		if _, ok := LookupExternalFact(tt.scope, tt.name); ok != tt.ok {
			t.Errorf("LookupExternalFact(%s, %s) = %v, want %v", tt.scope, tt.name, ok, tt.ok)
		}
	}
}

// A compiled document keeps its sources and checks, and a clone shares them.
func TestExternalChecksCompile(t *testing.T) {
	doc, err := decodeExternalDoc(t, externalFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := doc.Compile(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Config{cfg, cfg.Clone()} {
		if len(c.ExternalChecks) != 3 || len(c.ExternalSources) != 3 {
			t.Fatalf("compiled %d checks and %d sources, want 3 and 3", len(c.ExternalChecks), len(c.ExternalSources))
		}
	}
	if got := ExternalCheckRuleID("a", ""); got != "external_check:a" {
		t.Fatalf("rule ID = %q", got)
	}
	if got := ExternalCheckRuleID("a", ExternalCheckTokenNotSetOutcome); got != "external_check:a:token_not_set" {
		t.Fatalf("rule ID = %q", got)
	}
}
