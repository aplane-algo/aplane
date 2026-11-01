// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
)

const exportTestKey = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"

func exportDoc(key, text string) ExportedPolicyDocument {
	sum := sha256.Sum256([]byte(text))
	return ExportedPolicyDocument{Key: key, Document: text, SHA256: hex.EncodeToString(sum[:])}
}

func exportSet(docs ...ExportedPolicyDocument) string {
	stored := make([]policy.StoredDocument, 0, len(docs))
	for _, d := range docs {
		stored = append(stored, policy.StoredDocument{Key: d.Key, Bytes: []byte(d.Document)})
	}
	return policy.PolicySetSHA256(stored)
}

func TestExportPolicyDocumentsWritesExactBytes(t *testing.T) {
	docs := []ExportedPolicyDocument{exportDoc(policy.DefaultKey, "{\"key\": \"default\"}\n"), exportDoc(exportTestKey, "{\"key\": \""+exportTestKey+"\"}")}
	for name, dir := range map[string]string{
		"new directory":   filepath.Join(t.TempDir(), "export"),
		"empty directory": t.TempDir(),
	} {
		t.Run(name, func(t *testing.T) {
			paths, err := ExportPolicyDocuments(dir, docs, exportSet(docs...))
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
		})
	}
}

func TestExportPolicyDocumentsRefusesBeforeWriting(t *testing.T) {
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

	for _, tt := range []struct {
		name string
		dir  string
		docs []ExportedPolicyDocument
		set  string
		want error
	}{
		{"document changed", "", []ExportedPolicyDocument{altered}, exportSet(good), ErrPolicyChangedDuringExport},
		{"set changed", "", []ExportedPolicyDocument{good}, exportSet(good, exportDoc(exportTestKey, "{}")), ErrPolicyChangedDuringExport},
		{"key not a file name", "", []ExportedPolicyDocument{exportDoc("../escape", "{}")}, "", nil},
		{"key twice", "", []ExportedPolicyDocument{good, good}, "", nil},
		{"directory not empty", notEmpty, []ExportedPolicyDocument{good}, exportSet(good), nil},
		{"path is a file", file, []ExportedPolicyDocument{good}, exportSet(good), nil},
		{"path is a symlink", link, []ExportedPolicyDocument{good}, exportSet(good), nil},
		{"no directory", "-", []ExportedPolicyDocument{good}, exportSet(good), nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.dir
			switch dir {
			case "":
				dir = filepath.Join(t.TempDir(), "export")
			case "-":
				dir = ""
			}
			paths, err := ExportPolicyDocuments(dir, tt.docs, tt.set)
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
