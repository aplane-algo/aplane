// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const externalFixture = "cosigner_key_external_checks.json"

// TestExternalChecksCheckAndFmt: check accepts a document with external
// checks and reports its plain-http source; fmt finds it canonical and leaves
// it as it is.
func TestExternalChecksCheckAndFmt(t *testing.T) {
	dir := t.TempDir()
	path := put(t, dir, "cosigner.json", fixture(t, externalFixture))
	before := tree(t, dir)
	code, out, errOut := appolicy("check", path)
	if code != exitOK || !strings.Contains(out, "1 file(s), 0 error(s), 1 warning(s)") ||
		!strings.Contains(out, "/external_sources/ops/base_url: warning: source ops is reached over plain http") {
		t.Fatalf("check: exit %d\n%s\n%s", code, out, errOut)
	}
	code, out, _ = appolicy("check", "--json", path)
	var report checkReport
	if err := json.Unmarshal([]byte(out), &report); err != nil || code != exitOK || report.Errors != 0 || len(report.Problems) != 1 ||
		report.Problems[0].RuleID != "external_check:plain_http_source" {
		t.Fatalf("check --json: exit %d, %v, %+v", code, err, report)
	}
	if code, out, errOut := appolicy("fmt", "--check", path); code != exitOK || out != "" {
		t.Fatalf("fmt --check: exit %d\n%s\n%s", code, out, errOut)
	}
	if code, out, errOut := appolicy("fmt", path); code != exitOK || out != "" {
		t.Fatalf("fmt: exit %d\n%s\n%s", code, out, errOut)
	}
	if after := tree(t, dir); after != before {
		t.Fatal("check or fmt changed a canonical document")
	}

	// A copy with every object's fields sorted by name is put back in the
	// canonical field order. (Members of a map, such as the sources, keep
	// their order.)
	var doc map[string]any
	if err := json.Unmarshal(fixture(t, externalFixture), &doc); err != nil {
		t.Fatal(err)
	}
	sorted, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	other := put(t, t.TempDir(), "sorted.json", sorted)
	if code, out, errOut := appolicy("fmt", other); code != exitOK || !strings.Contains(out, "formatted") {
		t.Fatalf("fmt of a sorted copy: exit %d\n%s\n%s", code, out, errOut)
	}
	got, _ := os.ReadFile(other)
	for _, want := range []string{
		"  },\n  \"external_sources\": {",
		"  },\n  \"external_checks\": [",
		"\"base_url\": \"https://screen.example.com/api\",\n      \"token\": {\n        \"header\": \"Authorization\",\n        \"prefix\": \"Bearer \"\n      },\n      \"timeout_ms\": 2000,\n      \"max_response_bytes\": 65536\n",
		"\"id\": \"screen-destination\",\n      \"description\": \"Screening for every payment out on mainnet\",\n      \"source\": \"screening\",\n      \"scope\": \"movement\",\n",
		"\"path\": \"/allowance/{source}/{asset}\",\n      \"echo_pointer\": \"/request_id\",\n      \"require\": [\n        {\n          \"pointer\": \"/remaining\",\n          \"op\": \"ge\",\n          \"fact\": \"amount\"\n",
	} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("formatted copy lacks %q:\n%s", want, got)
		}
	}
	if strings.Index(string(got), "\"external_sources\"") > strings.Index(string(got), "\"external_checks\"") {
		t.Fatalf("external_checks comes before external_sources:\n%s", got)
	}
	if code, _, _ := appolicy("fmt", "--check", other); code != exitOK {
		t.Fatal("a formatted copy is not canonical")
	}
}

func TestExternalChecksExplain(t *testing.T) {
	path := put(t, t.TempDir(), "cosigner.json", fixture(t, externalFixture))
	code, out, errOut := appolicy("explain", path)
	if code != exitOK {
		t.Fatalf("explain: exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"  treasury: https://treasury.internal.example:8443, with a token, pinned to 1 server key",
		"    asks screening: GET /api/v2/addresses/{destination}?chain=algorand",
		"      /remaining is at least the movement's amount",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("explain lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "cannot keep") {
		t.Fatalf("explain says a token cannot be kept:\n%s", out)
	}
}

func TestExternalChecksTry(t *testing.T) {
	path := put(t, t.TempDir(), "cosigner.json", fixture(t, externalFixture))
	args := []string{"try", path, "--from", treasuryAddr, "--to", opsMainnet, "--amount", "5", "--network", "mainnet"}
	code, out, errOut := appolicy(append(args, "--json")...)
	if code != exitOK {
		t.Fatalf("try: exit %d: %s", code, errOut)
	}
	var report tryReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("try --json output: %v\n%s", err, out)
	}
	x := report.ExternalChecks
	if report.Outcome != "conditional_approve" || x == nil || strings.Join(x.Apply, ",") != "ops-switch,screen-destination,daily-allowance" ||
		!strings.Contains(report.Summary, "then external checks") || strings.Contains(out, `"refusal"`) {
		t.Fatalf("report = %+v, external %+v\n%s", report, x, out)
	}
	code, out, _ = appolicy(args...)
	if code != exitOK || !strings.Contains(out, "permits the supplied transaction; then external checks ops-switch, screen-destination and daily-allowance decide\n") {
		t.Fatalf("try text output: exit %d\n%s", code, out)
	}

	// A rejection lists no checks.
	code, out, _ = appolicy(append(args, "--fee", "9000", "--json")...)
	report = tryReport{}
	if err := json.Unmarshal([]byte(out), &report); err != nil || code != exitOK || report.Outcome != "reject" || report.ExternalChecks != nil {
		t.Fatalf("rejected try: exit %d, %v, %+v", code, err, report)
	}
}

// tryJSON runs a try with --json and decodes its report.
func tryJSON(t *testing.T, args ...string) (int, tryReport, string) {
	t.Helper()
	code, out, errOut := appolicy(append(args, "--json")...)
	var report tryReport
	if code == exitOK {
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("try --json output: %v\n%s", err, out)
		}
	}
	return code, report, errOut
}

// TestExternalChecksTryWithAnswers: --answer judges a check on a canned
// answer, through the cosigner's own plan and judge, and the report says what
// was asked, what passed, what refused and why, and what still decides.
func TestExternalChecksTryWithAnswers(t *testing.T) {
	dir := t.TempDir()
	path := put(t, dir, "cosigner.json", fixture(t, externalFixture))
	ops := put(t, dir, "ops.json", []byte(`{"enabled": true}`))
	pass := put(t, dir, "pass.json", []byte(`{"sanctioned": false, "risk": {"score": 12, "level": "low"}}`))
	fail := put(t, dir, "fail.json", []byte(`{"sanctioned": false, "risk": {"score": 72, "level": "low"}}`))
	allowance := put(t, dir, "allowance.json", []byte(`{"remaining": 5, "request_id": "r"}`))
	dup := put(t, dir, "dup.json", []byte(`{"enabled": true, "enabled": true}`))
	args := []string{"try", path, "--from", treasuryAddr, "--to", opsMainnet, "--amount", "5", "--network", "mainnet"}
	screening := "/api/v2/addresses/" + opsMainnet + "?chain=algorand"

	// Some answered: the rest still decide.
	code, report, errOut := tryJSON(t, append(args, "--answer", "ops-switch="+ops, "--answer", "screen-destination="+pass)...)
	x := report.ExternalChecks
	if code != exitOK || report.Outcome != "conditional_approve" || x == nil || len(x.Lookups) != 3 || len(x.Judged) != 2 ||
		len(x.Pending) != 1 || x.Pending[0].Check != "daily-allowance" || x.Refusal != nil {
		t.Fatalf("partial: exit %d %s, report %+v", code, errOut, x)
	}
	if l := x.Lookups[1]; l.Source != "screening" || l.Path != screening || strings.Join(l.Checks, ",") != "screen-destination" {
		t.Fatalf("lookup = %+v", l)
	}
	if j := x.Judged[1]; j.Check != "screen-destination" || j.Result != "pass" || j.Path != screening || j.RuleID != "" {
		t.Fatalf("judged = %+v", j)
	}

	// All answered and passing: approve.
	code, report, _ = tryJSON(t, append(args, "--answer", "ops-switch="+ops, "--answer", "screen-destination="+pass, "--answer", "daily-allowance="+allowance)...)
	if code != exitOK || report.Outcome != "approve" || len(report.ExternalChecks.Pending) != 0 || !report.ExternalChecks.Judged[2].EchoUnverified {
		t.Fatalf("all pass: exit %d, %+v", code, report.ExternalChecks)
	}

	// One fails: reject, with the rule, the detail and the request.
	code, report, _ = tryJSON(t, append(args, "--answer", "screen-destination="+fail)...)
	r := report.ExternalChecks.Refusal
	if code != exitOK || report.Outcome != "reject" || r == nil || r.RuleID != "external_check:screen-destination" ||
		r.Detail != "/risk/score = 72, want le 30" || r.Path != screening || r.Source != "screening" ||
		len(report.Violations) != 1 || report.Violations[0].RuleID != r.RuleID {
		t.Fatalf("failing: exit %d, %+v, violations %+v", code, r, report.Violations)
	}
	code, out, _ := appolicy(append(args, "--answer", "screen-destination="+fail)...)
	for _, want := range []string{
		"permits the supplied transaction, but external check screen-destination refuses it\n",
		"  [external_check:screen-destination] external check screen-destination refused the pay movement of transaction 0; source screening, GET " + screening + ": /risk/score = 72, want le 30\n",
		"lookups the cosigner would make:\n",
		"  screening: GET " + screening + ", for screen-destination\n",
		"  screen-destination, the pay movement of transaction 0: refuses (external_check:screen-destination): /risk/score = 72, want le 30\n",
		"still to decide, with no answer given:\n  ops-switch, the request: ops GET /signing/MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ\n",
	} {
		if code != exitOK || !strings.Contains(out, want) {
			t.Fatalf("text output lacks %q (exit %d):\n%s", want, code, out)
		}
	}

	// An answer the cosigner would not read is a failed lookup.
	code, report, _ = tryJSON(t, append(args, "--answer", "ops-switch="+dup)...)
	if r := report.ExternalChecks.Refusal; code != exitOK || report.Outcome != "reject" || r == nil || r.RuleID != "external_check:ops-switch:unavailable" ||
		!strings.Contains(r.Detail, "duplicate key") {
		t.Fatalf("duplicate key: exit %d, %+v", code, r)
	}

	// An answer that cannot apply is a usage error.
	for _, tt := range []struct {
		extra []string
		want  string
	}{
		{[]string{"--answer", "nope=" + ops}, "this document has no external check nope"},
		{[]string{"--answer", "screen-destination=" + pass, "--network", "testnet"}, "external check screen-destination does not apply to this transaction"},
		{[]string{"--answer", "ops-switch"}, `answer "ops-switch" is not check-id=FILE`},
		{[]string{"--answer", "ops-switch=" + ops, "--answer", "ops-switch=" + ops}, "answered twice"},
		{[]string{"--answer", "ops-switch=" + filepath.Join(dir, "missing.json")}, "missing.json"},
	} {
		code, out, errOut := appolicy(append(args, tt.extra...)...)
		if code != exitUsage || out != "" || !strings.Contains(errOut, tt.want) {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit 2 naming %q", tt.extra, code, out, errOut, tt.want)
		}
	}
}

// TestExternalChecksPlanRefusalNeedsNoAnswer: a unit that lacks a fact its
// check uses refuses before any lookup, and try reports it without answers.
func TestExternalChecksPlanRefusalNeedsNoAnswer(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(fixture(t, externalFixture), &doc); err != nil {
		t.Fatal(err)
	}
	var check any
	_ = json.Unmarshal([]byte(`{"id": "rekey-target", "source": "ops", "scope": "transaction", "networks": ["*"], "path": "/rekey/{rekey_to}", "require": [{"pointer": "/ok", "op": "eq", "bool": true}]}`), &check)
	doc["external_checks"] = append(doc["external_checks"].([]any), check)
	data, _ := json.Marshal(doc)
	path := put(t, t.TempDir(), "cosigner.json", data)
	code, report, errOut := tryJSON(t, "try", path, "--from", treasuryAddr, "--to", opsMainnet, "--amount", "5", "--network", "mainnet")
	x := report.ExternalChecks
	if code != exitOK || report.Outcome != "reject" || x == nil || x.Refusal == nil || x.Refusal.RuleID != "external_check:rekey-target:missing_fact" ||
		x.Refusal.Detail != "it has no rekey_to" || len(x.Lookups) != 0 || len(x.Judged) != 0 || len(x.Pending) != 0 {
		t.Fatalf("exit %d %s, report %+v", code, errOut, x)
	}
}

// TestTestRunsCasesWithAnswers: saved cases carry answers and failures, and
// test runs them through the same try.
func TestTestRunsCasesWithAnswers(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, "cosigner.json", fixture(t, externalFixture))
	if err := os.Mkdir(filepath.Join(dir, ".appolicy"), 0o700); err != nil {
		t.Fatal(err)
	}
	txn := `"txn": {"network": "mainnet", "sender": "` + treasuryAddr + `", "receiver": "` + opsMainnet + `", "amount": 5}`
	write := func(cases ...string) {
		put(t, filepath.Join(dir, ".appolicy"), "cases.json", []byte(`{"format": "aplane.policy-cases.v1", "cases": [`+strings.Join(cases, ",")+`]}`))
	}
	write(
		`{"name": "screened", "document": "cosigner.json", `+txn+`,
		  "answers": {"ops-switch": {"answer": {"enabled": true}},
		              "screen-destination": {"by_path": {"/api/v2/addresses/`+opsMainnet+`?chain=algorand": {"sanctioned": false, "risk": {"score": 1, "level": "low"}}}},
		              "daily-allowance": {"answer": {"remaining": 9, "request_id": "r"}}},
		  "expect": {"outcome": "approve"}}`,
		`{"name": "screening is down", "document": "cosigner.json", `+txn+`,
		  "failures": {"screen-destination": "status"}, "expect": {"outcome": "reject", "rule_id": "external_check:screen-destination:unavailable"}}`,
		`{"name": "pin mismatch", "document": "cosigner.json", `+txn+`,
		  "failures": {"daily-allowance": "pin_mismatch"}, "expect": {"outcome": "reject", "rule_id": "external_check:daily-allowance:unavailable"}}`,
		`{"name": "no token", "document": "cosigner.json", `+txn+`,
		  "failures": {"screen-destination": "token_not_set"}, "expect": {"outcome": "reject", "rule_id": "external_check:screen-destination:token_not_set"}}`,
		`{"name": "undecided", "document": "cosigner.json", `+txn+`, "expect": {"outcome": "conditional_approve"}}`,
	)
	code, out, errOut := appolicy("test", dir)
	if code != exitOK || !strings.Contains(out, "5 case(s), 0 failed, 0 could not run") {
		t.Fatalf("test: exit %d\n%s\n%s", code, out, errOut)
	}

	write(`{"name": "wrong", "document": "cosigner.json", ` + txn + `, "failures": {"ops-switch": "timeout"}, "expect": {"outcome": "approve"}}`)
	if code, out, _ := appolicy("test", dir); code != exitProblems || !strings.Contains(out, "FAIL  wrong: got reject (rule external_check:ops-switch:unavailable), want approve") {
		t.Fatalf("a failing case: exit %d\n%s", code, out)
	}
	// A failure the source cannot have, or an answer for no check, cannot run.
	write(`{"name": "bad", "document": "cosigner.json", ` + txn + `, "failures": {"ops-switch": "pin_mismatch"}, "expect": {"outcome": "reject"}}`)
	if code, out, _ := appolicy("test", dir); code != exitUsage || !strings.Contains(out, "ERROR bad: external check ops-switch: failure pin_mismatch") {
		t.Fatalf("an impossible failure: exit %d\n%s", code, out)
	}
	write(`{"name": "bad", "document": "cosigner.json", ` + txn + `, "answers": {"nope": {"answer": {}}}, "expect": {"outcome": "reject"}}`)
	if code, out, _ := appolicy("test", dir); code != exitUsage || !strings.Contains(out, "ERROR bad: this document has no external check nope") {
		t.Fatalf("an unknown check: exit %d\n%s", code, out)
	}
	// A malformed cases file is refused whole.
	write(`{"name": "bad", "document": "cosigner.json", ` + txn + `, "answers": {"ops-switch": {"answer": {}}}, "failures": {"ops-switch": "timeout"}, "expect": {"outcome": "reject"}}`)
	if code, _, errOut := appolicy("test", dir); code != exitUsage || !strings.Contains(errOut, "external check ops-switch has both an answer and a failure") {
		t.Fatalf("both an answer and a failure: exit %d\n%s", code, errOut)
	}
}
