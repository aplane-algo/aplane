// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policyexport"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// An export of an unlocked cosigner records the source names each document's
// selector has a token for; one from a node that did not know them records
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
	if got := fmt.Sprint(selected.Export.SourceTokens); got != fmt.Sprint(map[string][]string{policy.DefaultKey: {}, testKeyA: {"screening"}}) {
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
