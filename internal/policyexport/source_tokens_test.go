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

// followerKey is a cosigner key with no document of its own.
const followerKey = "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ"

// readExport reads back the context an export wrote.
func readExport(t *testing.T, paths []string) *Selected {
	t.Helper()
	selected, err := Discover(paths, "")
	if err != nil || selected == nil {
		t.Fatalf("Discover() = %v, %v", selected, err)
	}
	return selected
}

// A cosigner export records the source names every selector with a token has
// one for, a key without a document of its own included; a selector it does
// not list had none. Without names it records none, and then nothing is
// known of tokens.
func TestWriteRecordsTheSourceTokenNamesOfEverySelector(t *testing.T) {
	def, key := exportDoc(policy.DefaultKey, "{}"), exportDoc(exportTestKey, "{\"k\":1}")
	view := contextView(t, exportSet(def, key))

	paths, err := view.writeWithTokens(filepath.Join(t.TempDir(), "export"), []Document{def, key},
		map[string][]string{exportTestKey: {"treasury", "screening"}, followerKey: {"ops"}})
	if err != nil {
		t.Fatal(err)
	}
	export := readExport(t, paths).Export
	if fmt.Sprint(export.SourceTokens) != fmt.Sprint(map[string][]string{exportTestKey: {"screening", "treasury"}, followerKey: {"ops"}}) {
		t.Fatalf("SourceTokens = %v", export.SourceTokens)
	}
	for selector, want := range map[string]string{followerKey: "[ops]", policy.DefaultKey: "[]", exportTestKey: "[screening treasury]"} {
		if names, known := export.SourceTokenNames(selector); !known || fmt.Sprint(names) != want {
			t.Fatalf("SourceTokenNames(%s) = %v, %v; want %s, known", selector, names, known, want)
		}
	}

	paths, err = view.write(filepath.Join(t.TempDir(), "export"), []Document{def, key})
	if err != nil {
		t.Fatal(err)
	}
	if export := readExport(t, paths).Export; export.SourceTokens != nil {
		t.Fatalf("an export without names recorded %v", export.SourceTokens)
	} else if _, known := export.SourceTokenNames(followerKey); known {
		t.Fatal("an export without names claims to know a selector's")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(paths[0]), ContextDir, ContextFile))
	if err != nil || strings.Contains(string(data), "source_tokens") {
		t.Fatalf("context file of an export without names:\n%s (%v)", data, err)
	}
}

// A signer has no source tokens: its export records none, and one given
// names is refused.
func TestASignerExportRecordsNoSourceTokenNames(t *testing.T) {
	ctx, err := policycontext.New(noderole.RoleSigner, apconfig.DefaultGenesisHashNetworkResolver(), asaset.Empty())
	if err != nil {
		t.Fatal(err)
	}
	def := exportDoc(policy.DefaultKey, "{}")
	set := exportSet(def)
	snapshot := policycontext.SnapshotSHA256(ctx.SHA256(), set)
	paths, err := Write(filepath.Join(t.TempDir(), "export"), []Document{def}, ctx, set, snapshot, nil, exportTime)
	if err != nil {
		t.Fatal(err)
	}
	if got := readExport(t, paths).Export.SourceTokens; got != nil {
		t.Fatalf("a signer export recorded %v", got)
	}
	if _, err := Write(filepath.Join(t.TempDir(), "export"), []Document{def}, ctx, set, snapshot,
		map[string][]string{policy.DefaultKey: {"ops"}}, exportTime); err == nil {
		t.Fatal("a signer export recorded source token names")
	}
}

// Token names sit beside the digests: an export whose recorded names differ
// from the node's tokens now is still the node's snapshot, so a token set or
// removed after the export does not make an apply from it stale.
func TestSourceTokenNamesDoNotMakeAnExportStale(t *testing.T) {
	def, key := exportDoc(policy.DefaultKey, "{}"), exportDoc(exportTestKey, "{\"k\":1}")
	view := contextView(t, exportSet(def, key))
	var exports [][]string
	for _, tokens := range []map[string][]string{{exportTestKey: {"screening"}}, {policy.DefaultKey: {"ops"}}, {}, nil} {
		paths, err := view.writeWithTokens(filepath.Join(t.TempDir(), "export"), []Document{def, key}, tokens)
		if err != nil {
			t.Fatal(err)
		}
		exports = append(exports, paths)
	}
	for _, paths := range exports {
		selected := readExport(t, paths)
		if err := selected.Compare(view.ctx.SHA256(), view.set, view.snapshot); err != nil {
			t.Fatalf("Compare() with the node unchanged but for its tokens: %v", err)
		}
	}
}
