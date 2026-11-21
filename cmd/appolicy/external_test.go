// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"os"
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
	if report.Outcome != "approve" || x == nil || strings.Join(x.Apply, ",") != "ops-switch,screen-destination,daily-allowance" ||
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
