// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyexport

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policycontext"
)

func knownTokens(doc Document, names ...string) Document {
	doc.SourceTokens, doc.SourceTokensKnown = names, true
	return doc
}

// readExport reads back the context an export wrote.
func readExport(t *testing.T, paths []string) *Selected {
	t.Helper()
	selected, err := Discover(paths, "")
	if err != nil || selected == nil {
		t.Fatalf("Discover() = %v, %v", selected, err)
	}
	return selected
}

// A cosigner export records the source names each document's selector has a
// token for when the node knew them for every document, and none otherwise.
func TestWriteRecordsSourceTokenNamesOnlyWhenEveryDocumentKnew(t *testing.T) {
	def, key := exportDoc(policy.DefaultKey, "{}"), exportDoc(exportTestKey, "{\"k\":1}")
	view := contextView(t, exportSet(def, key))

	paths, err := view.write(filepath.Join(t.TempDir(), "export"), []Document{knownTokens(def), knownTokens(key, "treasury", "screening")})
	if err != nil {
		t.Fatal(err)
	}
	got := readExport(t, paths).Export.SourceTokens
	if fmt.Sprint(got) != fmt.Sprint(map[string][]string{policy.DefaultKey: {}, exportTestKey: {"screening", "treasury"}}) {
		t.Fatalf("SourceTokens = %v", got)
	}

	// The node locked part way through: one document came without them.
	paths, err = view.write(filepath.Join(t.TempDir(), "export"), []Document{knownTokens(def), key})
	if err != nil {
		t.Fatal(err)
	}
	if got := readExport(t, paths).Export.SourceTokens; got != nil {
		t.Fatalf("a partly known export recorded %v", got)
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(paths[0]), ContextDir, ContextFile))
	if err != nil || strings.Contains(string(data), "source_tokens") {
		t.Fatalf("context file of a partly known export:\n%s (%v)", data, err)
	}
}

// A signer has no source tokens, so its export records none whatever its
// documents claim.
func TestASignerExportRecordsNoSourceTokenNames(t *testing.T) {
	ctx, err := policycontext.New(noderole.RoleSigner, apconfig.DefaultGenesisHashNetworkResolver(), asaset.Empty())
	if err != nil {
		t.Fatal(err)
	}
	def := exportDoc(policy.DefaultKey, "{}")
	set := exportSet(def)
	paths, err := Write(filepath.Join(t.TempDir(), "export"), []Document{knownTokens(def, "ops")}, ctx, set,
		policycontext.SnapshotSHA256(ctx.SHA256(), set), exportTime)
	if err != nil {
		t.Fatal(err)
	}
	if got := readExport(t, paths).Export.SourceTokens; got != nil {
		t.Fatalf("a signer export recorded %v", got)
	}
}

// Token names sit beside the digests: an export whose recorded names differ
// from the node's tokens now is still the node's snapshot, so a token set or
// removed after the export does not make an apply from it stale.
func TestSourceTokenNamesDoNotMakeAnExportStale(t *testing.T) {
	def, key := exportDoc(policy.DefaultKey, "{}"), exportDoc(exportTestKey, "{\"k\":1}")
	view := contextView(t, exportSet(def, key))
	withNames, err := view.write(filepath.Join(t.TempDir(), "export"), []Document{knownTokens(def), knownTokens(key, "screening")})
	if err != nil {
		t.Fatal(err)
	}
	withOthers, err := view.write(filepath.Join(t.TempDir(), "export"), []Document{knownTokens(def, "ops"), knownTokens(key)})
	if err != nil {
		t.Fatal(err)
	}
	without, err := view.write(filepath.Join(t.TempDir(), "export"), []Document{def, key})
	if err != nil {
		t.Fatal(err)
	}
	for _, paths := range [][]string{withNames, withOthers, without} {
		selected := readExport(t, paths)
		if err := selected.Compare(view.ctx.SHA256(), view.set, view.snapshot); err != nil {
			t.Fatalf("Compare() with the node unchanged but for its tokens: %v", err)
		}
	}
}
