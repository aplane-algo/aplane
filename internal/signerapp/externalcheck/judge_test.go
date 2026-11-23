// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package externalcheck

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/strictjson"
)

var judgeLimits = strictjson.Limits{MaxBytes: 1 << 16, MaxDepth: 64, MaxNumberLiteral: 64, MaxExponent: 64}

// judgeOne compiles one movement-scope rule and judges answer with it.
func judgeOne(t *testing.T, rule, answer string, facts Facts) (bool, string) {
	t.Helper()
	cfg := compileChecks(t, `{"s": {"base_url": "https://s.example"}}`,
		`[{"id": "c", "source": "s", "scope": "movement", "networks": ["*"], "path": "/x", "require": [`+rule+`]}]`)
	root, err := strictjson.Parse([]byte(answer), judgeLimits)
	if err != nil {
		t.Fatalf("answer does not parse: %v", err)
	}
	return Judge(cfg.ExternalChecks[0], facts, root, "")
}

func TestJudgeRules(t *testing.T) {
	facts := Facts{"amount": "100", "destination": "DEST", "asset_id": "0"}
	for _, tt := range []struct {
		name, rule, answer string
		holds              bool
		detail             string
	}{
		{"bool eq", `{"pointer": "/a", "op": "eq", "bool": true}`, `{"a": true}`, true, ""},
		{"bool eq fails", `{"pointer": "/a", "op": "eq", "bool": true}`, `{"a": false}`, false, `/a = false, want eq true`},
		{"bool ne", `{"pointer": "/a", "op": "ne", "bool": true}`, `{"a": false}`, true, ""},
		{"bool on a string", `{"pointer": "/a", "op": "eq", "bool": true}`, `{"a": "true"}`, false, `/a is a string, want a boolean`},
		{"string eq", `{"pointer": "/a", "op": "eq", "string": "ok"}`, `{"a": "ok"}`, true, ""},
		{"string eq is exact", `{"pointer": "/a", "op": "eq", "string": "ok"}`, `{"a": "OK"}`, false, `/a = "OK", want eq "ok"`},
		{"string ne", `{"pointer": "/a", "op": "ne", "string": "blocked"}`, `{"a": "ok"}`, true, ""},
		{"string on a number", `{"pointer": "/a", "op": "eq", "string": "1"}`, `{"a": 1}`, false, "is a number, want a string"},

		{"number le", `{"pointer": "/a", "op": "le", "number": "30"}`, `{"a": 30}`, true, ""},
		{"number le fails", `{"pointer": "/a", "op": "le", "number": "30"}`, `{"a": 72}`, false, `/a = 72, want le 30`},
		{"number lt at the bound", `{"pointer": "/a", "op": "lt", "number": "30"}`, `{"a": 30}`, false, "want lt 30"},
		{"number gt", `{"pointer": "/a", "op": "gt", "number": "0.5"}`, `{"a": 0.51}`, true, ""},
		{"number ge", `{"pointer": "/a", "op": "ge", "number": "-1"}`, `{"a": -1.0}`, true, ""},
		{"equal decimals written differently", `{"pointer": "/a", "op": "eq", "number": "1"}`, `{"a": 1.0}`, true, ""},
		{"an exponent form is equal", `{"pointer": "/a", "op": "eq", "number": "100"}`, `{"a": 1e2}`, true, ""},
		{"minus zero is zero", `{"pointer": "/a", "op": "eq", "number": "0"}`, `{"a": -0}`, true, ""},
		{"exact beyond float64", `{"pointer": "/a", "op": "gt", "number": "9007199254740993"}`, `{"a": 9007199254740994}`, true, ""},
		{"exact beyond float64, equal", `{"pointer": "/a", "op": "gt", "number": "9007199254740993"}`, `{"a": 9007199254740993}`, false, "want gt"},
		{"small difference", `{"pointer": "/a", "op": "ne", "number": "0.1"}`, `{"a": 0.10000000000000001}`, true, ""},
		{"number ne fails on equal", `{"pointer": "/a", "op": "ne", "number": "1"}`, `{"a": 1.00}`, false, "want ne 1"},
		{"number on a string", `{"pointer": "/a", "op": "le", "number": "30"}`, `{"a": "20"}`, false, `/a is a string, want a number`},

		{"in strings", `{"pointer": "/a", "op": "in", "strings": ["low", "medium"]}`, `{"a": "low"}`, true, ""},
		{"in strings fails", `{"pointer": "/a", "op": "in", "strings": ["low", "medium"]}`, `{"a": "high"}`, false, `/a = "high", want in the listed strings`},
		{"not_in strings", `{"pointer": "/a", "op": "not_in", "strings": ["high"]}`, `{"a": "low"}`, true, ""},
		{"not_in strings fails", `{"pointer": "/a", "op": "not_in", "strings": ["high"]}`, `{"a": "high"}`, false, "want not_in"},
		{"in numbers by value", `{"pointer": "/a", "op": "in", "numbers": ["1", "2"]}`, `{"a": 2.0}`, true, ""},
		{"not_in numbers", `{"pointer": "/a", "op": "not_in", "numbers": ["1", "2"]}`, `{"a": 3}`, true, ""},
		{"in numbers on a string", `{"pointer": "/a", "op": "in", "numbers": ["1"]}`, `{"a": "1"}`, false, "want a number"},

		{"present", `{"pointer": "/a", "op": "present"}`, `{"a": null}`, true, ""},
		{"present fails", `{"pointer": "/a", "op": "present"}`, `{}`, false, `/a missing`},
		{"absent", `{"pointer": "/a", "op": "absent"}`, `{}`, true, ""},
		{"absent fails on null", `{"pointer": "/a", "op": "absent"}`, `{"a": null}`, false, "is present, want it absent"},
		{"the whole answer", `{"pointer": "", "op": "eq", "bool": true}`, `true`, true, ""},

		// A rule holds only on a value of the right type: the negations too.
		{"ne on a missing value", `{"pointer": "/a", "op": "ne", "string": "x"}`, `{}`, false, `/a missing`},
		{"ne on null", `{"pointer": "/a", "op": "ne", "string": "x"}`, `{"a": null}`, false, `/a is null, want a string`},
		{"not_in on a missing value", `{"pointer": "/a", "op": "not_in", "strings": ["x"]}`, `{}`, false, "missing"},
		{"not_in on another type", `{"pointer": "/a", "op": "not_in", "strings": ["x"]}`, `{"a": 1}`, false, "want a string"},
		{"ne number on an object", `{"pointer": "/a", "op": "ne", "number": "1"}`, `{"a": {}}`, false, "is an object, want a number"},

		{"fact as a number", `{"pointer": "/remaining", "op": "ge", "fact": "amount"}`, `{"remaining": 100}`, true, ""},
		{"fact as a number fails", `{"pointer": "/remaining", "op": "ge", "fact": "amount"}`, `{"remaining": 99.99}`, false, `/remaining = 99.99, want ge 100`},
		{"fact as a string", `{"pointer": "/to", "op": "eq", "fact": "destination"}`, `{"to": "DEST"}`, true, ""},
		{"fact as a string fails", `{"pointer": "/to", "op": "eq", "fact": "destination"}`, `{"to": "OTHER"}`, false, `want eq "DEST"`},
		{"numeric fact against a string", `{"pointer": "/id", "op": "eq", "fact": "asset_id"}`, `{"id": "0"}`, false, "want a number"},

		{"array index", `{"pointer": "/a/1", "op": "eq", "number": "20"}`, `{"a": [10, 20]}`, true, ""},
		{"array index with a leading zero", `{"pointer": "/a/01", "op": "present"}`, `{"a": [10, 20]}`, false, "missing"},
		{"escaped name", `{"pointer": "/a~1b", "op": "eq", "bool": true}`, `{"a/b": true}`, true, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			holds, detail := judgeOne(t, tt.rule, tt.answer, facts)
			if holds != tt.holds || !strings.Contains(detail, tt.detail) || (tt.holds && detail != "") {
				t.Fatalf("Judge() = %v, %q; want %v, %q", holds, detail, tt.holds, tt.detail)
			}
		})
	}
}

func TestJudgeMissingFactAndLongValues(t *testing.T) {
	holds, detail := judgeOne(t, `{"pointer": "/remaining", "op": "ge", "fact": "amount"}`, `{"remaining": 1}`, Facts{})
	if holds || detail != "the unit has no amount" {
		t.Fatalf("Judge() = %v, %q", holds, detail)
	}
	long := strings.Repeat("a", 200)
	holds, detail = judgeOne(t, `{"pointer": "/a", "op": "eq", "string": "x"}`, `{"a": "`+long+`\n"}`, Facts{})
	if holds || strings.Contains(detail, long) || !strings.Contains(detail, strings.Repeat("a", 64)+"...") {
		t.Fatalf("a long value must be cut in the detail: %q", detail)
	}
	_, detail = judgeOne(t, `{"pointer": "/a", "op": "eq", "string": "x"}`, `{"a": "line\nbreak caf\u00e9"}`, Facts{})
	if strings.ContainsAny(detail, "\n\u00e9") || !strings.Contains(detail, `line\u000abreak caf\u00e9`) {
		t.Fatalf("control and non-ASCII characters must be escaped: %q", detail)
	}
}

func TestQuoteBareUTF8BoundaryAndSupplementaryRunes(t *testing.T) {
	// Plain ASCII within the limit stays unchanged, and quotes/backslashes stay escaped.
	if got := quoteBare(`hello "world" \ok`); got != `hello \"world\" \\ok` {
		t.Fatalf("quoteBare(ascii+escapes) = %q", got)
	}

	// Exactly maxQuotedValue runes (63 ASCII + 1 two-byte UTF-8 rune = 65 bytes)
	// must neither truncate nor split the final multi-byte character into \ufffd.
	exact := strings.Repeat("a", maxQuotedValue-1) + "é"
	wantExact := strings.Repeat("a", maxQuotedValue-1) + `\u00e9`
	if got := quoteBare(exact); got != wantExact {
		t.Fatalf("quoteBare(exact %d runes) = %q, want %q", maxQuotedValue, got, wantExact)
	}

	// Exceeding maxQuotedValue with a multi-byte rune straddling byte 64 must
	// cut cleanly on a rune boundary with no replacement character.
	over := strings.Repeat("a", maxQuotedValue-1) + "é" + "z"
	wantOver := strings.Repeat("a", maxQuotedValue-1) + `\u00e9...`
	if got := quoteBare(over); got != wantOver || strings.Contains(got, `\ufffd`) {
		t.Fatalf("quoteBare(over rune boundary) = %q, want %q", got, wantOver)
	}

	// Multi-byte strings made entirely of non-ASCII runes count characters, not bytes.
	multi := strings.Repeat("é", maxQuotedValue+2)
	wantMulti := strings.Repeat(`\u00e9`, maxQuotedValue) + "..."
	if got := quoteBare(multi); got != wantMulti {
		t.Fatalf("quoteBare(multi-byte) = %q, want %q", got, wantMulti)
	}

	// Supplementary runes (> U+FFFF) encode as a 4-hex-digit UTF-16 surrogate
	// pair so following hex digits remain unambiguous.
	if got := quoteBare("😀0"); got != `\ud83d\ude000` {
		t.Fatalf("quoteBare(supplementary+hex) = %q, want %q", got, `\ud83d\ude000`)
	}
}

func TestJudgeEchoIsPerCheck(t *testing.T) {
	cfg := compileChecks(t, `{"s": {"base_url": "https://s.example"}}`, `[
	  {"id": "echoing", "source": "s", "scope": "request", "networks": ["*"], "path": "/x",
	   "echo_pointer": "/request_id", "require": [{"pointer": "/ok", "op": "eq", "bool": true}]},
	  {"id": "plain", "source": "s", "scope": "request", "networks": ["*"], "path": "/x",
	   "require": [{"pointer": "/ok", "op": "eq", "bool": true}]}]`)
	parse := func(doc string) *strictjson.Node {
		root, err := strictjson.Parse([]byte(doc), judgeLimits)
		if err != nil {
			t.Fatal(err)
		}
		return root
	}
	echoing, plain := cfg.ExternalChecks[0], cfg.ExternalChecks[1]
	if ok, detail := Judge(echoing, nil, parse(`{"ok": true, "request_id": "abc"}`), "abc"); !ok {
		t.Fatalf("matching echo refused: %s", detail)
	}
	for name, answer := range map[string]string{
		"another ID":   `{"ok": true, "request_id": "other"}`,
		"no echo":      `{"ok": true}`,
		"not a string": `{"ok": true, "request_id": 5}`,
	} {
		if ok, detail := Judge(echoing, nil, parse(answer), "abc"); ok || !strings.Contains(detail, "echo mismatch") {
			t.Errorf("%s: Judge() = %v, %q, want an echo mismatch", name, ok, detail)
		}
		// The same answer satisfies the check that asks for no echo.
		if ok, detail := Judge(plain, nil, parse(answer), "abc"); !ok {
			t.Errorf("%s: the check without an echo refused: %s", name, detail)
		}
	}
	_ = policy.ExternalOpEq
}
