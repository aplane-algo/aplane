// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "contracts", "policy", "v1", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func put(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func appolicy(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// tree lists every path under dir with its size, mode and modification time.
func tree(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		lines = append(lines, fmt.Sprintf("%s %d %v %d", rel, info.Size(), info.Mode(), info.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return fmt.Sprint(lines)
}

func TestCheckExitCodesAndOutput(t *testing.T) {
	clean := t.TempDir()
	put(t, clean, "default.json", fixture(t, "signer_default.json"))
	put(t, clean, "ops.json", fixture(t, "signer_key_full.json"))
	before := tree(t, clean)
	code, out, _ := appolicy("check", clean)
	if code != exitOK || !strings.Contains(out, "2 file(s), 0 error(s), 1 warning(s)") || !strings.Contains(out, "/reject_clawback: warning:") {
		t.Fatalf("clean workspace: exit %d\n%s", code, out)
	}
	if after := tree(t, clean); after != before {
		t.Fatal("check changed the workspace")
	}

	bad := put(t, t.TempDir(), "bad.json", fixture(t, "semantic_invalid/signer_route_unknown_address_set.json"))
	code, out, _ = appolicy("check", bad)
	if code != exitProblems || !strings.Contains(out, "/transfer_policy/routes/0/sources/0: error: unknown address set") {
		t.Fatalf("invalid file: exit %d\n%s", code, out)
	}

	if code, _, errOut := appolicy("check", filepath.Join(clean, "missing")); code != exitUsage || errOut == "" {
		t.Fatalf("missing path: exit %d", code)
	}
	if code, _, _ := appolicy("check"); code != exitUsage {
		t.Fatalf("no path: exit %d", code)
	}
}

func TestCheckJSON(t *testing.T) {
	path := put(t, t.TempDir(), "bad.json", []byte(`{"format": "aplane.policy.v1", "format": "x"}`))
	code, out, _ := appolicy("check", "--json", path)
	var report checkReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if code != exitProblems || report.Errors != 1 || report.Files[0].State != "unparsable" || report.Problems[0].Pointer != "/format" {
		t.Fatalf("exit %d, report %+v", code, report)
	}
}

func TestFmt(t *testing.T) {
	dir := t.TempDir()
	canonical := fixture(t, "signer_default.json")
	reordered := put(t, dir, "max.json", fixture(t, "signer_uint64_max.json"))
	put(t, dir, "ok.json", canonical)
	commented := put(t, dir, "commented.json", append([]byte("// note\n"), fixture(t, "signer_key_minimal.json")...))
	broken := put(t, dir, "broken.json", []byte(`{"format":`))
	brokenBefore, _ := os.ReadFile(broken)

	// --check reports and writes nothing.
	before := tree(t, dir)
	code, out, _ := appolicy("fmt", "--check", dir)
	if code != exitProblems || !strings.Contains(out, "max.json: not canonical") || strings.Contains(out, "ok.json") {
		t.Fatalf("fmt --check: exit %d\n%s", code, out)
	}
	if after := tree(t, dir); after != before {
		t.Fatal("fmt --check changed files")
	}

	// fmt rewrites the non-canonical file, refuses the commented one, and leaves
	// the unparsable one untouched.
	code, out, errOut := appolicy("fmt", dir)
	if code != exitProblems || !strings.Contains(out, "max.json: formatted") ||
		!strings.Contains(errOut, "commented.json: not formatted: it has comments") ||
		!strings.Contains(errOut, "broken.json: not formatted, left untouched") {
		t.Fatalf("fmt: exit %d\nstdout %s\nstderr %s", code, out, errOut)
	}
	if after, _ := os.ReadFile(broken); !bytes.Equal(after, brokenBefore) {
		t.Fatal("an unparsable file was changed")
	}
	if again, _, _ := appolicy("fmt", "--check", reordered); again != exitOK {
		t.Fatal("a formatted file is not canonical")
	}

	// --strip-comments formats the commented file.
	if code, _, errOut := appolicy("fmt", "--strip-comments", commented); code != exitOK {
		t.Fatalf("fmt --strip-comments: exit %d: %s", code, errOut)
	}
	if after, _ := os.ReadFile(commented); bytes.Contains(after, []byte("//")) {
		t.Fatal("comments survived --strip-comments")
	}
}

func TestExplain(t *testing.T) {
	path := put(t, t.TempDir(), "ops.json", fixture(t, "signer_key_full.json"))
	signerData := t.TempDir()
	before := tree(t, signerData)
	code, out, errOut := appolicy("explain", "--signer-data", signerData, path)
	if code != exitOK || !strings.Contains(out, "Signer key document for") || !strings.Contains(out, "1000 USDC") {
		t.Fatalf("explain: exit %d\n%s\n%s", code, out, errOut)
	}
	if after := tree(t, signerData); after != before {
		t.Fatalf("explain wrote to the signer data directory:\nbefore %s\nafter  %s", before, after)
	}

	bad := put(t, t.TempDir(), "bad.json", []byte("{"))
	if code, _, errOut := appolicy("explain", bad); code != exitProblems || !strings.Contains(errOut, "appolicy check") {
		t.Fatalf("explain of an invalid file: exit %d: %s", code, errOut)
	}
}

const (
	treasuryAddr = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"
	opsMainnet   = "EIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDOHSEZI"
)

func TestTry(t *testing.T) {
	path := put(t, t.TempDir(), "treasury.json", fixture(t, "signer_key_full.json"))
	signerData := t.TempDir()
	before := tree(t, signerData)
	tests := []struct {
		name    string
		args    []string
		outcome string
		ruleID  string
	}{
		{name: "within the route and the limits", args: []string{"--amount", "100000000"}, outcome: "default"},
		// The document's own limit asks first, before the route's 500 ALGO.
		{name: "above the document's review limit", args: []string{"--amount", "100000001"}, outcome: "review", ruleID: "review_algo_payment_exceeded"},
		{name: "above the document's reject limit", args: []string{"--amount", "1000000001"}, outcome: "reject"},
		{name: "no route on testnet", args: []string{"--amount", "1", "--network", "testnet"}, outcome: "reject"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Flags may follow the file.
			args := append([]string{"try", path, "--json", "--signer-data", signerData, "--from", treasuryAddr, "--to", opsMainnet, "--network", "mainnet"}, tc.args...)
			code, out, errOut := appolicy(args...)
			if code != exitOK {
				t.Fatalf("try: exit %d: %s", code, errOut)
			}
			var report tryReport
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatalf("try --json output: %v\n%s", err, out)
			}
			if report.Outcome != tc.outcome || report.RuleID != tc.ruleID || report.Role != "signer" {
				t.Fatalf("report = %+v, want outcome %q rule %q", report, tc.outcome, tc.ruleID)
			}
			if tc.outcome == "reject" && len(report.Violations) == 0 {
				t.Fatal("a rejection lists no violations")
			}
			if !strings.Contains(strings.Join(report.Assumes, "\n"), "no config.yaml in "+signerData) {
				t.Fatalf("assumptions = %q, want the network source", report.Assumes)
			}
		})
	}
	if after := tree(t, signerData); after != before {
		t.Fatalf("try wrote to the signer data directory:\nbefore %s\nafter  %s", before, after)
	}

	code, out, _ := appolicy("try", "--signer-data", "", "--from", treasuryAddr, "--to", "self", path)
	if code != exitOK || !strings.Contains(out, "treasury.json (signer document") || !strings.Contains(out, "assumed:\n  - built-in networks only") {
		t.Fatalf("try text output: exit %d\n%s", code, out)
	}
}

func TestTryRefusesBadInput(t *testing.T) {
	path := put(t, t.TempDir(), "treasury.json", fixture(t, "signer_key_full.json"))
	bad := put(t, t.TempDir(), "bad.json", []byte("{"))
	for name, args := range map[string][]string{
		"no file":              {"try", "--from", treasuryAddr, "--to", "self"},
		"two files":            {"try", path, path, "--from", treasuryAddr, "--to", "self"},
		"invalid document":     {"try", bad, "--from", treasuryAddr, "--to", "self"},
		"no sender":            {"try", path, "--to", opsMainnet},
		"held without a rekey": {"try", path, "--from", treasuryAddr, "--to", "self", "--rekey-held"},
		"unknown network":      {"try", path, "--from", treasuryAddr, "--to", "self", "--network", "nowhere"},
		"unknown flag":         {"try", path, "--bogus"},
	} {
		if code, _, _ := appolicy(append(args, "--signer-data", "")...); code != exitUsage {
			t.Errorf("%s: exit %d, want %d", name, code, exitUsage)
		}
	}
}

func TestRetiredAndUnknownInvocations(t *testing.T) {
	for _, args := range [][]string{{"-online"}, {"--check", "x.json"}, {"-yaml"}, {"-save"}, {"-to-sentry"}} {
		code, _, errOut := appolicy(args...)
		if code != exitUsage || !strings.Contains(errOut, "retired appolicy") {
			t.Fatalf("%v: exit %d: %s", args, code, errOut)
		}
	}
	if code, _, errOut := appolicy("missing.json"); code != exitUsage || !strings.Contains(errOut, "is not a command or a file") {
		t.Fatalf("missing bare file: exit %d: %s", code, errOut)
	}
	if code, _, _ := appolicy("frobnicate"); code != exitUsage {
		t.Fatalf("unknown command: exit %d", code)
	}
	if code, _, _ := appolicy(); code != exitUsage {
		t.Fatalf("no arguments: exit %d", code)
	}
	if code, out, _ := appolicy("help"); code != exitOK || !strings.Contains(out, "appolicy check") {
		t.Fatalf("help: exit %d", code)
	}
}

// TestCheckValidatesNamedFilesTogether: "appolicy check policy/*.json" applies
// the same rules across files as "appolicy check policy/".
func TestCheckValidatesNamedFilesTogether(t *testing.T) {
	dir := t.TempDir()
	a := put(t, dir, "a.json", fixture(t, "signer_default.json"))
	b := put(t, dir, "b.json", fixture(t, "signer_default.json"))
	for _, args := range [][]string{{"check", dir}, {"check", a, b}} {
		code, out, _ := appolicy(args...)
		if code != exitProblems || strings.Count(out, "at most one default") != 2 {
			t.Fatalf("%v: exit %d\n%s", args, code, out)
		}
	}
	c := put(t, t.TempDir(), "c.json", fixture(t, "cosigner_key_minimal.json"))
	if code, out, _ := appolicy("check", a, c); code != exitProblems || !strings.Contains(out, "for a cosigner node") {
		t.Fatalf("mixed roles named as files: exit %d\n%s", code, out)
	}
}

// TestOpenRunsTheTUIOnTheWorkspace: open, or a path in place of a command,
// runs the TUI on every named path as one workspace.
func TestOpenRunsTheTUIOnTheWorkspace(t *testing.T) {
	dir := t.TempDir()
	a := put(t, dir, "a.json", fixture(t, "signer_default.json"))
	b := put(t, dir, "b.json", fixture(t, "signer_key_full.json"))
	var ran []tea.Model
	saved := runProgram
	runProgram = func(m tea.Model) error { ran = append(ran, m); return nil }
	t.Cleanup(func() { runProgram = saved })

	for _, args := range [][]string{{"open", a, b}, {dir}, {"open", "--signer-data", t.TempDir(), dir}} {
		if code, _, errOut := appolicy(args...); code != exitOK {
			t.Fatalf("%v: exit %d: %s", args, code, errOut)
		}
	}
	if len(ran) != 3 {
		t.Fatalf("the TUI ran %d times, want 3", len(ran))
	}
	for _, m := range ran {
		if view := m.View(); !strings.Contains(view, "a.json") || !strings.Contains(view, "b.json") {
			t.Fatalf("the TUI does not list both files:\n%s", view)
		}
	}
	if code, _, _ := appolicy("open"); code != exitUsage {
		t.Fatalf("open with no path: exit %d", code)
	}
}
