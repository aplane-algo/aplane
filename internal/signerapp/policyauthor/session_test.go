// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
)

func set(pointer, value string) func(*policy.Draft) (*policy.Draft, error) {
	return func(d *policy.Draft) (*policy.Draft, error) { return d.Set(pointer, []byte(value)) }
}

func TestSessionEditUndoRedo(t *testing.T) {
	f := LoadFile(writeFile(t, t.TempDir(), "ops.json", fixture(t, "signer_key_full.json")))
	s, err := NewSession(f)
	if err != nil {
		t.Fatal(err)
	}
	if s.Modified() || s.Current().State != StateValid {
		t.Fatalf("fresh session: modified %v state %s", s.Modified(), s.Current().State)
	}
	if err := s.Apply(set("/max_fee_microalgos", `"5000"`)); err != nil {
		t.Fatal(err)
	}
	if !s.Modified() || s.Current().Document.MaxFeeMicroAlgos != 5000 {
		t.Fatal("edit not applied")
	}
	if err := s.Apply(set("/reject_clawback", `"no"`)); err != nil {
		t.Fatal(err)
	}
	if s.Current().State != StateInvalid || !s.Current().Errors() {
		t.Fatal("an invalid edit was not re-checked")
	}
	if !s.Undo() || s.Current().State != StateValid || s.Current().Document.MaxFeeMicroAlgos != 5000 {
		t.Fatal("undo did not restore the previous edit")
	}
	if !s.Redo() || s.Current().State != StateInvalid {
		t.Fatal("redo did not reapply")
	}
	s.Undo()
	s.Undo()
	if s.Modified() || s.Undo() {
		t.Fatal("undoing every edit left the session modified or with more to undo")
	}
	if err := s.Apply(set("/nope/x", `1`)); err == nil || len(s.undo) != 0 {
		t.Fatal("a failed edit changed the session")
	}
	// A new edit clears redo.
	s.Redo()
	if err := s.Apply(set("/description", `"x"`)); err != nil || s.Redo() {
		t.Fatalf("redo survived a new edit (err %v)", err)
	}
	if !bytes.Equal(f.Loaded, fixture(t, "signer_key_full.json")) {
		t.Fatal("editing changed the loaded file")
	}
}

func TestSessionFormattingAloneIsNotAChange(t *testing.T) {
	spaced := bytes.ReplaceAll(fixture(t, "signer_default.json"), []byte("  "), []byte("    "))
	s, err := NewSession(LoadFile(writeFile(t, t.TempDir(), "d.json", spaced)))
	if err != nil {
		t.Fatal(err)
	}
	if s.Modified() || !s.Review().Identical {
		t.Fatalf("an unedited non-canonical file is modified: %+v", s.Review())
	}
}

func TestSessionReviewAndSave(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "ops.json", fixture(t, "signer_key_full.json"))
	s, err := NewSession(LoadFile(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(set("/max_fee_microalgos", `"50000"`)); err != nil {
		t.Fatal(err)
	}
	review := s.Review()
	if review.Mode != ComparePolicy || !strings.Contains(changeText(review), "loosened /max_fee_microalgos") {
		t.Fatalf("review: %+v", review)
	}

	// Another editor changes the file: the save is refused, then forced.
	if err := os.WriteFile(path, append(fixture(t, "signer_key_full.json"), ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	var conflict *ConflictError
	if err := s.Save(false); !errors.As(err, &conflict) || conflict.Kind != ConflictModified {
		t.Fatalf("save over a changed file: %v", err)
	}
	if err := s.Save(true); err != nil {
		t.Fatal(err)
	}
	disk, _ := os.ReadFile(path)
	canonical, _ := s.draft.Canonical()
	if !bytes.Equal(disk, canonical) || s.Modified() || !bytes.Equal(s.Loaded.Loaded, canonical) {
		t.Fatal("after save: disk, baseline or modified flag is wrong")
	}
	if !s.Undo() || !s.Modified() {
		t.Fatal("undo after save did not make the session modified again")
	}

	// Save as: a new file becomes the session's; an existing one is refused.
	other := filepath.Join(dir, "copy.json")
	if err := s.SaveAs(other); err != nil || s.Loaded.Path != other || s.Modified() {
		t.Fatalf("save as: %v, path %s", err, s.Loaded.Path)
	}
	if err := s.SaveAs(path); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("save as onto an existing file: %v", err)
	}
}

func TestNewDocumentSession(t *testing.T) {
	draft, err := policy.ParseDraft(fixture(t, "signer_default.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "new.json")
	s, err := NewDocumentSession(path, draft)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Modified() || s.Current().State != StateValid {
		t.Fatalf("new document: modified %v state %s", s.Modified(), s.Current().State)
	}
	if err := s.Save(false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil || s.Modified() {
		t.Fatalf("new document not created (%v) or still modified", err)
	}

	clash := filepath.Join(t.TempDir(), "clash.json")
	s, _ = NewDocumentSession(clash, draft)
	writeFile(t, filepath.Dir(clash), "clash.json", []byte("{}"))
	var conflict *ConflictError
	if err := s.Save(false); !errors.As(err, &conflict) || conflict.Kind != ConflictCreated {
		t.Fatalf("new document over a file that appeared: %v", err)
	}
}

func TestUnparsableFileIsNotEditable(t *testing.T) {
	if _, err := NewSession(LoadFile(writeFile(t, t.TempDir(), "bad.json", []byte("{")))); !errors.Is(err, ErrNotEditable) {
		t.Fatalf("err = %v", err)
	}
}

func TestWorkspaceWithChecksTheEditedFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.json", fixture(t, "signer_default.json"))
	writeFile(t, dir, "b.json", fixture(t, "signer_key_full.json"))
	w, _ := Open(dir)
	s, _ := NewSession(w.Files[1])
	if err := s.Apply(set("/key", `"default"`)); err != nil {
		t.Fatal(err)
	}
	edited := w.With(1, s.Current())
	if len(edited.Problems) != 2 || len(w.Problems) != 0 {
		t.Fatalf("edited workspace problems %+v, original %+v", edited.Problems, w.Problems)
	}
}
