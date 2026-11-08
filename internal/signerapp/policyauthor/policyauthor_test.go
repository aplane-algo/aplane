// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
)

const testWitnessKeyID = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"

var (
	testSignerKey  = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"
	testSignerKey2 = "GMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZ6LH5CFA"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "contracts", "policy", "v1", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// snapshot lists every path under dir with its size, mode and modification
// time, so a test can show that loading changed nothing.
func snapshot(t *testing.T, dir string) string {
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

func TestLoadFileStates(t *testing.T) {
	dir := t.TempDir()
	valid := fixture(t, "signer_key_full.json")
	commented := append([]byte("// treasury\n"), valid...)
	for _, tt := range []struct {
		name     string
		data     []byte
		state    State
		pointer  string
		comments bool
	}{
		{"valid", valid, StateValid, "", false},
		{"valid with comments", commented, StateValid, "", true},
		{"semantic error", fixture(t, "semantic_invalid/signer_bad_address_checksum.json"), StateInvalid, "/", false},
		{"missing field", []byte(`{"format": "aplane.policy.v1", "role": "signer", "key": "default"}`), StateInvalid, "", false},
		{"duplicate key", []byte(`{"format": "aplane.policy.v1", "format": "aplane.policy.v1"}`), StateUnparsable, "/format", false},
		{"truncated", valid[:len(valid)/2], StateUnparsable, "", false},
		{"unterminated comment", append(append([]byte(nil), valid...), "/* open"...), StateUnparsable, "", false},
		{"only comments", []byte("// nothing\n"), StateUnparsable, "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := writeFile(t, dir, strings.ReplaceAll(tt.name, " ", "_")+".json", tt.data)
			f := LoadFile(path)
			if f.State != tt.state {
				t.Fatalf("state = %s, want %s (problems %+v)", f.State, tt.state, f.Problems)
			}
			if !bytes.Equal(f.Loaded, tt.data) || !f.Exists || f.LoadedSHA256 == "" {
				t.Fatal("the loaded bytes were not kept exactly")
			}
			if f.HadComments != tt.comments {
				t.Fatalf("HadComments = %v, want %v", f.HadComments, tt.comments)
			}
			if (f.Draft == nil) != (tt.state == StateUnparsable) || (f.Document == nil) != (tt.state != StateValid) {
				t.Fatalf("draft %v / document %v do not match state %s", f.Draft != nil, f.Document != nil, f.State)
			}
			if tt.state == StateValid {
				if f.Errors() || f.Key != testSignerKey || f.Role != noderole.RoleSigner {
					t.Fatalf("valid file: errors %v key %q role %q", f.Problems, f.Key, f.Role)
				}
				return
			}
			if !f.Errors() {
				t.Fatal("an invalid file reports no error")
			}
			if tt.pointer != "" && !strings.HasPrefix(f.Problems[0].Pointer, tt.pointer) {
				t.Fatalf("problem pointer = %q, want it under %q", f.Problems[0].Pointer, tt.pointer)
			}
		})
	}
	if f := LoadFile(filepath.Join(dir, "missing.json")); f.State != StateUnreadable || f.Exists || !f.Errors() {
		t.Fatalf("missing file: %+v", f)
	}
}

// TestLoadFileReportsWhatTheDecoderReports keeps the editor's errors and the
// node's identical: a semantic fixture gets the decoder's own pointer and text.
func TestLoadFileReportsWhatTheDecoderReports(t *testing.T) {
	data := fixture(t, "semantic_invalid/signer_route_unknown_address_set.json")
	path := writeFile(t, t.TempDir(), "doc.json", data)
	f := LoadFile(path)
	_, decodeErr := policy.DecodePolicyV1(data, f.Key, noderole.RoleSigner)
	var docErr *policy.DocumentError
	if !errors.As(decodeErr, &docErr) {
		t.Fatalf("fixture decodes: %v", decodeErr)
	}
	if len(f.Problems) != 1 || f.Problems[0].Pointer != docErr.Pointer || f.Problems[0].Message != docErr.Msg {
		t.Fatalf("problems = %+v, want the decoder's %q at %q", f.Problems, docErr.Msg, docErr.Pointer)
	}
}

func TestLoadFileReportsAdvisoriesAsWarnings(t *testing.T) {
	doc := policytest.Cosigner(t, testWitnessKeyID, `{"transaction_types": {"*": "reject", "pay": "allow", "axfer": "allow"},
  "transfer_policy": {"routes": [{"id": "r", "networks": ["testnet"], "sources": ["*"], "assets": ["algo"], "destinations": ["self"]}]}}`)
	f := LoadFile(writeFile(t, t.TempDir(), "k.json", []byte(doc)))
	if f.State != StateValid || f.Errors() || len(f.Problems) != 1 {
		t.Fatalf("problems = %+v", f.Problems)
	}
	if p := f.Problems[0]; p.Severity != SeverityWarning || p.Pointer != "/max_fee_microalgos" || p.RuleID != policy.ConfigAdvisoryCosignerNoFeeCap {
		t.Fatalf("warning = %+v", p)
	}
}

func TestLoadFileRefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := writeFile(t, dir, "real.json", fixture(t, "signer_default.json"))
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	if f := LoadFile(link); f.State != StateUnreadable || f.Exists {
		t.Fatalf("symlink loaded: state %s", f.State)
	}
}

func TestOpenWorkspaceRules(t *testing.T) {
	signerDefault := fixture(t, "signer_default.json")
	keyDoc := func(key string) []byte { return []byte(policytest.Signer(t, key, "")) }
	cosigner := fixture(t, "cosigner_key_minimal.json")

	for _, tt := range []struct {
		name  string
		files map[string][]byte
		want  map[string]string // file name -> substring of its workspace problem
	}{
		{"default and key files", map[string][]byte{"default.json": signerDefault, "treasury.json": keyDoc(testSignerKey), "ops.json": keyDoc(testSignerKey2)}, nil},
		{"key files only", map[string][]byte{"treasury.json": keyDoc(testSignerKey)}, nil},
		{"two defaults", map[string][]byte{"a.json": signerDefault, "b.json": signerDefault},
			map[string]string{"a.json": "at most one default", "b.json": "at most one default"}},
		{"one key in two files", map[string][]byte{"a.json": keyDoc(testSignerKey), "b.json": keyDoc(testSignerKey)},
			map[string]string{"a.json": "also in b.json", "b.json": "also in a.json"}},
		{"mixed roles", map[string][]byte{"a.json": signerDefault, "b.json": cosigner},
			map[string]string{"b.json": "for a cosigner node"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, data := range tt.files {
				writeFile(t, dir, name, data)
			}
			if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(dir, "sub"), "ignored.json", []byte("{"))
			writeFile(t, dir, "notes.txt", []byte("not policy"))
			before := snapshot(t, dir)

			w, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if after := snapshot(t, dir); after != before {
				t.Fatalf("Open changed the directory:\nbefore %s\nafter  %s", before, after)
			}
			if len(w.Files) != len(tt.files) {
				t.Fatalf("loaded %d files, want %d (subdirectories and non-JSON files are skipped)", len(w.Files), len(tt.files))
			}
			got := map[string]string{}
			for _, p := range w.Problems {
				got[filepath.Base(p.Path)] = p.Message
			}
			if len(got) != len(tt.want) {
				t.Fatalf("workspace problems = %+v, want %v", w.Problems, tt.want)
			}
			for name, sub := range tt.want {
				if !strings.Contains(got[name], sub) {
					t.Fatalf("%s: problem %q, want %q", name, got[name], sub)
				}
			}
			if tt.want == nil && w.Errors() {
				t.Fatalf("unexpected errors: %+v", w.AllProblems())
			}
		})
	}
}

// TestOpenWorkspaceKeepsAFileWithNoValidRole: a file whose role is not a
// valid string reports it at /role, takes no part in the mixed-role rule, and
// stays loaded.
func TestOpenWorkspaceKeepsAFileWithNoValidRole(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.json", fixture(t, "cosigner_default.json"))
	broken := strings.Replace(string(fixture(t, "cosigner_key_minimal.json")), `"role": "cosigner"`, `"role": 5`, 1)
	writeFile(t, dir, "b.json", []byte(broken))
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if w.Role != noderole.RoleCosigner || len(w.Files) != 2 || len(w.Problems) != 0 {
		t.Fatalf("workspace role %q, %d files, problems %+v", w.Role, len(w.Files), w.Problems)
	}
	b := w.Files[1]
	if b.State != StateInvalid || b.Role != "" || b.Problems[0].Pointer != "/role" {
		t.Fatalf("b.json: state %s role %q problems %+v", b.State, b.Role, b.Problems)
	}
}

func TestDiskStateAndCosignedWrite(t *testing.T) {
	dir := t.TempDir()
	original := fixture(t, "signer_default.json")
	path := writeFile(t, dir, "default.json", original)
	f := LoadFile(path)
	edited, err := f.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	edited = bytes.Replace(edited, []byte(`"max_fee_microalgos": "0"`), []byte(`"max_fee_microalgos": "5000"`), 1)

	if c, _, err := f.DiskState(); c != ConflictNone || err != nil {
		t.Fatalf("unchanged file: %s, %v", c, err)
	}

	// Another editor changes the file: the write is refused with the disk bytes.
	if err := os.WriteFile(path, append(original, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	var conflict *ConflictError
	if err := f.Write(edited, false); !errors.As(err, &conflict) || conflict.Kind != ConflictModified || !bytes.Equal(conflict.Disk, append(original, ' ')) {
		t.Fatalf("write over a changed file: %v", err)
	}
	if !bytes.Equal(f.Loaded, original) {
		t.Fatal("a refused write moved the baseline")
	}

	// Overwrite, after the caller showed the disk version: written, baseline moves.
	if err := f.Write(edited, true); err != nil {
		t.Fatal(err)
	}
	disk, _ := os.ReadFile(path)
	info, _ := os.Stat(path)
	if !bytes.Equal(disk, edited) || info.Mode().Perm() != 0o600 || !bytes.Equal(f.Loaded, edited) || f.Document.MaxFeeMicroAlgos != 5000 {
		t.Fatalf("after overwrite: disk equal %v, mode %v, baseline equal %v", bytes.Equal(disk, edited), info.Mode().Perm(), bytes.Equal(f.Loaded, edited))
	}
	if c, _, _ := f.DiskState(); c != ConflictNone {
		t.Fatalf("after own write: %s", c)
	}

	// Deleted on disk.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := f.Write(edited, false); !errors.As(err, &conflict) || conflict.Kind != ConflictDeleted || conflict.Disk != nil {
		t.Fatalf("write over a deleted file: %v", err)
	}

	// A file that did not exist at load, created meanwhile.
	fresh := LoadFile(filepath.Join(dir, "new.json"))
	writeFile(t, dir, "new.json", original)
	if err := fresh.Write(edited, false); !errors.As(err, &conflict) || conflict.Kind != ConflictCreated {
		t.Fatalf("write over a created file: %v", err)
	}
	// And one that is still absent is written.
	absent := LoadFile(filepath.Join(dir, "absent.json"))
	if err := absent.Write(edited, false); err != nil || !absent.Exists || absent.State != StateValid {
		t.Fatalf("write of a new file: %v, state %s", err, absent.State)
	}
}

func TestCanonicalNeedsADraft(t *testing.T) {
	f := LoadFile(writeFile(t, t.TempDir(), "bad.json", []byte("{")))
	if _, err := f.Canonical(); err == nil {
		t.Fatal("an unparsable file has a canonical form")
	}
}

// TestOpenTreatsNamedFilesAsOneBundle: the rules across files hold however
// the files are named, and a file named twice is loaded once.
func TestOpenTreatsNamedFilesAsOneBundle(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.json", fixture(t, "signer_default.json"))
	b := writeFile(t, dir, "b.json", fixture(t, "signer_default.json"))

	w, err := Open(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Problems) != 2 || !strings.Contains(w.Problems[0].Message, "at most one default") {
		t.Fatalf("two defaults named as files: problems %+v", w.Problems)
	}

	w, err = Open(a, dir, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Files) != 2 {
		t.Fatalf("loaded %d files, want each file once", len(w.Files))
	}
}
