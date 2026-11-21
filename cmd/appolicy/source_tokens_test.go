// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policycontext"
	"github.com/aplane-algo/aplane/internal/policyexport"
)

// tokenFixtureKey is the key of the external checks fixture, whose
// screening and treasury sources take a token and ops takes none.
const tokenFixtureKey = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"

// writeCosignerExport writes, into dir, the external checks fixture and the
// context of the cosigner node it was exported from, with the built-in
// networks. names are the token names the export recorded; nil records none.
func writeCosignerExport(t *testing.T, dir string, names map[string][]string) string {
	t.Helper()
	doc := put(t, dir, "cosigner.json", fixture(t, externalFixture))
	ctx, err := policycontext.New(noderole.RoleCosigner, apconfig.DefaultGenesisHashNetworkResolver(), asaset.Empty())
	if err != nil {
		t.Fatal(err)
	}
	export, err := policycontext.NewExport(ctx, []policy.DocumentDigest{
		{Key: policy.DefaultKey, SHA256: strings.Repeat("a", 64)},
		{Key: tokenFixtureKey, SHA256: strings.Repeat("b", 64)},
	}, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if names != nil {
		if err := export.RecordSourceTokens(names); err != nil {
			t.Fatal(err)
		}
	}
	data, err := export.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, policyexport.ContextDir), 0o700); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(dir, policyexport.ContextDir), policyexport.ContextFile, data)
	return doc
}

// tokenAdvisories are the token_not_set warnings of a report, by pointer.
func tokenAdvisories(report checkReport) []string {
	var out []string
	for _, p := range report.Problems {
		if p.RuleID == policy.ConfigAdvisoryExternalTokenNotSet {
			out = append(out, string(p.Severity)+" "+p.Pointer)
		}
	}
	return out
}

// check warns of a source that takes a token the export's node did not have
// for the document's key, and only when the export recorded the node's token
// names: without them, or without an export, it says nothing of tokens.
func TestCheckWarnsOfATokenTheExportLacks(t *testing.T) {
	dir := t.TempDir()
	doc := writeCosignerExport(t, dir, map[string][]string{tokenFixtureKey: {"screening"}, policy.DefaultKey: {"treasury"}})
	code, report := checkJSON(t, doc)
	if code != exitOK || report.Errors != 0 {
		t.Fatalf("check: exit %d, %+v", code, report)
	}
	if got := strings.Join(tokenAdvisories(report), ","); got != "warning /external_sources/treasury/token" {
		t.Fatalf("token advisories = %q, want treasury's only: the key has screening's, and the default's do not count", got)
	}
	code, out, _ := appolicy("check", doc)
	want := "/external_sources/treasury/token: warning: source treasury takes a token and " + tokenFixtureKey + " has none set"
	if code != exitOK || !strings.Contains(out, want) || strings.Contains(out, "source screening takes a token") {
		t.Fatalf("check: exit %d\n%s", code, out)
	}

	// Every token the document needs: no advisory.
	all := writeCosignerExport(t, t.TempDir(), map[string][]string{tokenFixtureKey: {"screening", "treasury"}})
	if _, report := checkJSON(t, all); len(tokenAdvisories(report)) != 0 {
		t.Fatalf("token advisories with every token set: %v", tokenAdvisories(report))
	}
	// None set: both sources that take one.
	none := writeCosignerExport(t, t.TempDir(), map[string][]string{})
	if _, report := checkJSON(t, none); strings.Join(tokenAdvisories(report), ",") != "warning /external_sources/screening/token,warning /external_sources/treasury/token" {
		t.Fatalf("token advisories with no token set: %v", tokenAdvisories(report))
	}
	// An export that recorded no names, and a file from no export, say
	// nothing of tokens.
	unrecorded := writeCosignerExport(t, t.TempDir(), nil)
	bare := put(t, t.TempDir(), "cosigner.json", fixture(t, externalFixture))
	for _, path := range []string{unrecorded, bare} {
		if _, report := checkJSON(t, path); len(tokenAdvisories(report)) != 0 {
			t.Fatalf("%s: token advisories without recorded names: %v", path, tokenAdvisories(report))
		}
	}
}
