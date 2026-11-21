// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policyexport"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
)

// An export of an unlocked cosigner records the source names every selector
// with a token has one for; one from a node that did not know them records
// none. A token set after the export does not make an apply from it stale:
// tokens are not policy.
func TestExportAllRecordsSourceTokenNames(t *testing.T) {
	onlineEnv(t)
	session := newFakeSession("cosigner", protocol.PolicyDocumentWire{Key: testKeyA, Document: testCosignerDoc(testKeyA)})
	session.makeReal(t, nil)
	session.tokens = map[string][]string{testKeyA: {"screening"}}
	dir := filepath.Join(t.TempDir(), "export")
	if err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbExport, ExportDir: dir}, Streams{Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatal(err)
	}
	selected, err := policyexport.Discover([]string{filepath.Join(dir, policy.DefaultKey+".json")}, "")
	if err != nil || selected == nil {
		t.Fatalf("Discover() = %v, %v", selected, err)
	}
	if got := fmt.Sprint(selected.Export.SourceTokens); got != fmt.Sprint(map[string][]string{testKeyA: {"screening"}}) {
		t.Fatalf("recorded names = %s", got)
	}

	session.tokens[testKeyA] = []string{"screening", "treasury"}
	edited := filepath.Join(dir, testKeyA+".json")
	if err := os.WriteFile(edited, []byte(editedCosignerDoc()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbApply, Args: []string{edited}, Yes: true},
		Streams{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}); err != nil || len(session.applies) != 1 {
		t.Fatalf("apply after a token was set = %v, %d applies", err, len(session.applies))
	}

	session.tokens = nil
	unknown := filepath.Join(t.TempDir(), "export")
	if err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbExport, ExportDir: unknown}, Streams{Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatal(err)
	}
	selected, err = policyexport.Discover([]string{filepath.Join(unknown, policy.DefaultKey+".json")}, "")
	if err != nil || selected == nil || selected.Export.SourceTokens != nil {
		t.Fatalf("an export from a node that did not know its tokens = %+v, %v", selected, err)
	}
}

// fixtureForKey is the external checks fixture as key's own document: its
// screening and treasury sources take a token, ops takes none.
func fixtureForKey(t *testing.T, key string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "contracts", "policy", "v1", "cosigner_key_external_checks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["key"] = key
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// offlineTokenWarnings checks file as appolicy check does, against the export
// it was written into, and returns its token_not_set warnings by pointer.
func offlineTokenWarnings(t *testing.T, exportDir, file string) []string {
	t.Helper()
	selected, err := policyexport.Discover([]string{file}, "")
	if err != nil || selected == nil {
		t.Fatalf("Discover(%s) = %v, %v", exportDir, selected, err)
	}
	w, err := policyauthor.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	w = w.WithNode(&policyauthor.NodeContext{Context: selected.Export.Context, ExportedAt: selected.Export.ExportedAt,
		Path: selected.Path, SourceTokens: selected.Export.SourceTokens})
	var out []string
	for _, p := range w.AllProblems() {
		if p.RuleID == policy.ConfigAdvisoryExternalTokenNotSet {
			out = append(out, p.Pointer)
		}
	}
	slices.Sort(out)
	return out
}

// A key that follows the node default has no document of its own, but may
// have tokens set already. The export records them, so a new document
// written for the key from the export warns only of the tokens it truly
// lacks, and of every one when the key has none.
func TestAnExportKnowsTheTokensOfAKeyWithoutADocument(t *testing.T) {
	onlineEnv(t)
	for _, tt := range []struct {
		name   string
		tokens map[string][]string
		want   string
	}{
		{"both tokens set", map[string][]string{testKeyA: {"screening", "treasury"}}, ""},
		{"one token set", map[string][]string{testKeyA: {"screening"}}, "/external_sources/treasury/token"},
		{"no token set", map[string][]string{}, "/external_sources/screening/token,/external_sources/treasury/token"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			session := newFakeSession("cosigner")
			session.makeReal(t, nil)
			session.tokens = tt.tokens
			dir := filepath.Join(t.TempDir(), "export")
			if err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbExport, ExportDir: dir},
				Streams{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, testKeyA+".json")
			if err := os.WriteFile(file, []byte(fixtureForKey(t, testKeyA)), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(offlineTokenWarnings(t, dir, file), ","); got != tt.want {
				t.Fatalf("token warnings = %q, want %q", got, tt.want)
			}
		})
	}
}

// The export reads the node's token listing a page at a time, until no
// selector is left out.
func TestExportReadsEveryPageOfTheTokenListing(t *testing.T) {
	onlineEnv(t)
	session := newFakeSession("cosigner")
	session.makeReal(t, nil)
	session.tokens = map[string][]string{policy.DefaultKey: {"ops"}, testKeyA: {"screening"}, testKeyB: {"treasury"}}
	session.tokenPage = 1
	dir := filepath.Join(t.TempDir(), "export")
	if err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbExport, ExportDir: dir},
		Streams{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}); err != nil {
		t.Fatal(err)
	}
	selected, err := policyexport.Discover([]string{filepath.Join(dir, policy.DefaultKey+".json")}, "")
	if err != nil || selected == nil {
		t.Fatalf("Discover() = %v, %v", selected, err)
	}
	if got := fmt.Sprint(selected.Export.SourceTokens); got != fmt.Sprint(session.tokens) || session.tokenLists != 3 {
		t.Fatalf("recorded names = %s over %d requests, want every selector's over 3", got, session.tokenLists)
	}
}

// A session the node will not tell token names to, one without
// policy.update, still exports the documents; the export records no names
// and says so, and appolicy check then says nothing of tokens.
func TestAnExportWithoutPolicyUpdateRecordsNoTokenNames(t *testing.T) {
	onlineEnv(t)
	session := newFakeSession("cosigner")
	session.makeReal(t, nil)
	session.tokens = map[string][]string{testKeyA: {"screening"}}
	session.tokensDenied = true
	dir := filepath.Join(t.TempDir(), "export")
	var stderr bytes.Buffer
	if err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbExport, ExportDir: dir},
		Streams{Stdout: &bytes.Buffer{}, Stderr: &stderr}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "the export records no source token names") || !strings.Contains(stderr.String(), "authorization denied") {
		t.Fatalf("stderr = %q, want a note that no names were recorded", stderr.String())
	}
	file := filepath.Join(dir, testKeyA+".json")
	if err := os.WriteFile(file, []byte(fixtureForKey(t, testKeyA)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := offlineTokenWarnings(t, dir, file); len(got) != 0 {
		t.Fatalf("token warnings from an export without names: %v", got)
	}
}
