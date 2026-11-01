// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyexport

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policycontext"
)

const exportTestKey = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"

var exportTime = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func exportDoc(key, text string) Document {
	sum := sha256.Sum256([]byte(text))
	return Document{Key: key, Document: text, SHA256: hex.EncodeToString(sum[:])}
}

func exportSet(docs ...Document) string {
	stored := make([]policy.StoredDocument, 0, len(docs))
	for _, d := range docs {
		stored = append(stored, policy.StoredDocument{Key: d.Key, Bytes: []byte(d.Document)})
	}
	return policy.PolicySetSHA256(stored)
}

// contextView is what a cosigner node with the built-in networks and
// tables, plus private-dev, sends for the policy set setSHA256.
func contextView(t *testing.T, setSHA256 string) adminproto.PolicyContextView {
	t.Helper()
	networks, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=": "private-dev"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := policycontext.New(noderole.RoleCosigner, networks, asaset.Empty())
	if err != nil {
		t.Fatal(err)
	}
	view := adminproto.PolicyContextView{
		Success: true, NodeRole: string(ctx.Role()), RulesVersion: ctx.RulesVersion(),
		ContextSHA256: ctx.SHA256(), PolicySetSHA256: setSHA256,
		SnapshotSHA256: policycontext.SnapshotSHA256(ctx.SHA256(), setSHA256),
	}
	for token, genesis := range ctx.Networks() {
		view.Networks = append(view.Networks, adminproto.PolicyNetwork{Network: token, GenesisHash: genesis.String()})
	}
	for _, a := range ctx.Assets().Assets() {
		view.Assets = append(view.Assets, adminproto.ASAInfo{
			GenesisHash: a.Genesis.String(), AssetID: a.AssetID, Name: a.Name, UnitName: a.UnitName, Decimals: a.Decimals, Origin: string(a.Origin),
		})
	}
	return view
}

func TestWriteExportsExactBytesAndTheContextLast(t *testing.T) {
	docs := []Document{exportDoc(policy.DefaultKey, "{\"key\": \"default\"}\n"), exportDoc(exportTestKey, "{\"key\": \""+exportTestKey+"\"}")}
	view := contextView(t, exportSet(docs...))
	for name, dir := range map[string]string{
		"new directory":   filepath.Join(t.TempDir(), "export"),
		"empty directory": t.TempDir(),
	} {
		t.Run(name, func(t *testing.T) {
			var order []string
			fsutil.TestHook = func(op fsutil.HookOp, path string) error {
				if op == fsutil.OpRename {
					order = append(order, filepath.Base(path))
				}
				return nil
			}
			defer func() { fsutil.TestHook = nil }()
			paths, err := Write(dir, docs, view, exportTime)
			fsutil.TestHook = nil
			if err != nil {
				t.Fatal(err)
			}
			want := []string{filepath.Join(dir, "default.json"), filepath.Join(dir, exportTestKey+".json")}
			if len(paths) != 2 || paths[0] != want[0] || paths[1] != want[1] {
				t.Fatalf("paths = %v, want %v", paths, want)
			}
			for i, path := range paths {
				data, err := os.ReadFile(path)
				info, _ := os.Stat(path)
				if err != nil || string(data) != docs[i].Document || info.Mode().Perm() != 0o600 {
					t.Fatalf("%s: %q mode %v err %v", path, data, info.Mode().Perm(), err)
				}
			}
			if info, err := os.Stat(filepath.Join(dir, ContextDir)); err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("context directory: %v %v", info, err)
			}
			if _, err := os.Stat(filepath.Join(dir, ContextDir, InProgressFile)); !os.IsNotExist(err) {
				t.Fatal("a finished export kept its in-progress marker")
			}
			if len(order) != 4 || !strings.HasPrefix(order[0], InProgressFile) || !strings.HasPrefix(order[3], ContextFile) {
				t.Fatalf("publication order %v, want the marker first and the context last", order)
			}

			selected, err := Discover([]string{paths[0], paths[1]}, "")
			if err != nil || selected == nil {
				t.Fatalf("Discover() = %v, %v", selected, err)
			}
			if selected.Export.Baseline.SnapshotSHA256 != view.SnapshotSHA256 || !selected.Export.ExportedAt.Equal(exportTime) {
				t.Fatalf("baseline %+v, want the node's snapshot", selected.Export.Baseline)
			}
		})
	}
}

func TestWriteRefusesBeforeWriting(t *testing.T) {
	good := exportDoc(policy.DefaultKey, "{}")
	altered := good
	altered.Document = "{ }"
	notEmpty := t.TempDir()
	if err := os.WriteFile(filepath.Join(notEmpty, "old.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	view := contextView(t, exportSet(good))
	tampered := view
	tampered.Assets = append([]adminproto.ASAInfo(nil), view.Assets...)
	tampered.Assets[0].Decimals++
	staleSnapshot := view
	staleSnapshot.SnapshotSHA256 = strings.Repeat("0", 64)
	noDefault := exportDoc(exportTestKey, "{}")

	for _, tt := range []struct {
		name string
		dir  string
		docs []Document
		view adminproto.PolicyContextView
		want error
	}{
		{"document changed", "", []Document{altered}, view, ErrPolicyChanged},
		{"set changed", "", []Document{good}, contextView(t, exportSet(good, exportDoc(exportTestKey, "{}"))), ErrPolicyChanged},
		{"context not its digest", "", []Document{good}, tampered, nil},
		{"snapshot not the context's", "", []Document{good}, staleSnapshot, nil},
		{"context unavailable", "", []Document{good}, adminproto.PolicyContextView{Code: "policy_unavailable"}, nil},
		{"no default", "", []Document{noDefault}, contextView(t, exportSet(noDefault)), nil},
		{"key not a file name", "", []Document{exportDoc("../escape", "{}")}, view, nil},
		{"key twice", "", []Document{good, good}, view, nil},
		{"directory not empty", notEmpty, []Document{good}, view, nil},
		{"path is a file", file, []Document{good}, view, nil},
		{"path is a symlink", link, []Document{good}, view, nil},
		{"no directory", "-", []Document{good}, view, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.dir
			switch dir {
			case "":
				dir = filepath.Join(t.TempDir(), "export")
			case "-":
				dir = ""
			}
			paths, err := Write(dir, tt.docs, tt.view, exportTime)
			if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) || len(paths) != 0 {
				t.Fatalf("err = %v, paths %v; want a refusal (%v)", err, paths, tt.want)
			}
			if tt.dir == "" {
				if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
					t.Fatal("a refused export created its directory")
				}
			}
			if tt.dir == notEmpty {
				if entries, _ := os.ReadDir(notEmpty); len(entries) != 1 {
					t.Fatal("a refused export wrote into a non-empty directory")
				}
			}
		})
	}
}

// An export that fails after it started leaves its marker, and reading it
// back is refused rather than taken as a workspace without context.
func TestAFailedExportIsNeverReadAsComplete(t *testing.T) {
	docs := []Document{exportDoc(policy.DefaultKey, "{}"), exportDoc(exportTestKey, "{\"k\":1}")}
	dir := filepath.Join(t.TempDir(), "export")
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && strings.HasPrefix(filepath.Base(path), exportTestKey) {
			return errors.New("disk full")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()
	paths, err := Write(dir, docs, contextView(t, exportSet(docs...)), exportTime)
	fsutil.TestHook = nil
	if err == nil || len(paths) != 1 {
		t.Fatalf("Write() = %v, %v; want the second document's failure", paths, err)
	}
	if _, err := Discover(paths, ""); err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("Discover() error = %v, want the unfinished export refused", err)
	}
}
