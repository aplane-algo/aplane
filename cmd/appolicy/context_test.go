// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/policycontext"
	"github.com/aplane-algo/aplane/internal/policyexport"
)

const privateDevHash = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

// writeNodeContext writes the context of a signer node into dir's .appolicy
// as an export would, and returns its path. The node knows mainnet and
// testnet, and private-dev when privateDev is set, and no assets, so
// nothing built in is merged into what it says.
func writeNodeContext(t *testing.T, dir string, privateDev bool) string {
	t.Helper()
	networks := map[string]asaset.GenesisHash{}
	for hash, token := range apconfig.BuiltinGenesisHashNetworks() {
		if token == "mainnet" || token == "testnet" {
			g, err := asaset.ParseGenesisHash(hash)
			if err != nil {
				t.Fatal(err)
			}
			networks[token] = g
		}
	}
	if privateDev {
		g, err := asaset.ParseGenesisHash(privateDevHash)
		if err != nil {
			t.Fatal(err)
		}
		networks["private-dev"] = g
	}
	table, err := asaset.NewTable(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := policycontext.FromParts(noderole.RoleSigner, networks, table, policycontext.AdmissionRulesVersion)
	if err != nil {
		t.Fatal(err)
	}
	export, err := policycontext.NewExport(ctx, []policy.DocumentDigest{{Key: policy.DefaultKey, SHA256: strings.Repeat("a", 64)}}, time.Now().Add(-3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	data, err := export.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, policyexport.ContextDir), 0o700); err != nil {
		t.Fatal(err)
	}
	return put(t, filepath.Join(dir, policyexport.ContextDir), policyexport.ContextFile, data)
}

func TestSignerDataIsRemoved(t *testing.T) {
	for _, args := range [][]string{
		{"check", "--signer-data", "x", "f.json"},
		{"open", "--signer-data=x", "f.json"},
		{"try", "f.json", "-signer-data", "x"},
		{"explain", "--signer-data", "", "f.json"},
	} {
		code, _, errOut := appolicy(args...)
		if code != exitUsage || !strings.Contains(errOut, "--signer-data is removed") || !strings.Contains(errOut, "apadmin policy export --all") {
			t.Errorf("%v: exit %d: %s", args, code, errOut)
		}
	}
}

// checkJSON runs check --json and returns the exit code and the report.
func checkJSON(t *testing.T, args ...string) (int, checkReport) {
	t.Helper()
	code, out, errOut := appolicy(append([]string{"check", "--json"}, args...)...)
	var report checkReport
	if code != exitUsage {
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("check --json: %v\n%s\n%s", err, out, errOut)
		}
	}
	return code, report
}

// ruleSeverity is the severity a report gives ruleID, or "" when it does
// not report it.
func ruleSeverity(report checkReport, ruleID string) string {
	for _, p := range report.Problems {
		if p.RuleID == ruleID {
			return string(p.Severity)
		}
	}
	return ""
}

// What a node refuses to admit is an error against its export, and a
// warning against the built-in tables alone.
func TestCheckAgainstTheNodeOfAnExport(t *testing.T) {
	doc := []byte(policytest.MustDocument(noderole.RoleSigner, policy.DefaultKey, `{"limits": {"private-dev": {"algo": {"reject_above": "1"}}}}`))
	const rule = "admission:unknown_network"

	bare := t.TempDir()
	put(t, bare, "default.json", doc)
	code, report := checkJSON(t, bare)
	if code != exitOK || ruleSeverity(report, rule) != "warning" || !strings.Contains(report.Context, "built-in networks and assets only") {
		t.Fatalf("no export: exit %d, %s %q, context %q", code, ruleSeverity(report, rule), rule, report.Context)
	}

	without := t.TempDir()
	put(t, without, "default.json", doc)
	writeNodeContext(t, without, false)
	code, report = checkJSON(t, without)
	if code != exitProblems || ruleSeverity(report, rule) != "error" || !strings.Contains(report.Context, "the signer node exported to") ||
		!strings.Contains(report.Context, "3 hour(s) ago (an offline snapshot)") {
		t.Fatalf("an export without the network: exit %d, %s, context %q", code, ruleSeverity(report, rule), report.Context)
	}

	with := t.TempDir()
	put(t, with, "default.json", doc)
	writeNodeContext(t, with, true)
	if code, report = checkJSON(t, with); code != exitOK || ruleSeverity(report, rule) != "" {
		t.Fatalf("an export with the network: exit %d, %+v", code, report.Problems)
	}

	// --node-context names the context for files outside an export.
	if code, report = checkJSON(t, "--node-context", writeNodeContext(t, t.TempDir(), true), bare); code != exitOK || ruleSeverity(report, rule) != "" {
		t.Fatalf("--node-context: exit %d, %+v", code, report.Problems)
	}

	// An unfinished export is refused, never checked as if it had no context.
	put(t, filepath.Join(with, policyexport.ContextDir), policyexport.InProgressFile, nil)
	if code, out, errOut := appolicy("check", with); code != exitUsage || !strings.Contains(errOut, "did not finish") {
		t.Fatalf("an unfinished export: exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestADocumentForAnotherRoleThanTheExport(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, "c.json", fixture(t, "cosigner_key_minimal.json"))
	writeNodeContext(t, dir, false)
	code, out, _ := appolicy("check", dir)
	if code != exitProblems || !strings.Contains(out, "the export is of a signer node") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}
