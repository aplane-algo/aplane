// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/policy"
)

// ErrNotEditable reports a file whose bytes are not JSON: it has no draft to
// edit, and is repaired outside the editor.
var ErrNotEditable = errors.New("the file is not valid JSON and cannot be edited here; repair it in a text editor and reload")

// Session is one file being edited: the file as loaded, the draft as it
// stands, and the drafts before and after it for undo and redo. Every edit is
// re-checked at once, the same way a loaded file is.
type Session struct {
	// Loaded is the file as it was loaded or last saved; its bytes and hash
	// are the baseline the review diffs against and the save checks the disk
	// against.
	Loaded *File

	draft      *policy.Draft
	current    *File
	undo, redo []*policy.Draft
}

// NewSession starts editing f. A file that is not JSON cannot be edited.
func NewSession(f *File) (*Session, error) {
	if f.Draft == nil {
		return nil, ErrNotEditable
	}
	s := &Session{Loaded: f, draft: f.Draft}
	if err := s.refresh(); err != nil {
		return nil, err
	}
	return s, nil
}

// NewDocumentSession starts editing a document that is not yet on disk at
// path. Saving it creates the file, and is refused if a file appears there
// first.
func NewDocumentSession(path string, draft *policy.Draft) (*Session, error) {
	return NewSession(&File{Path: path, State: StateInvalid, Draft: draft})
}

// refresh analyzes the current draft.
func (s *Session) refresh() error {
	data, err := s.draft.Canonical()
	if err != nil {
		return err
	}
	f := &File{Path: s.Loaded.Path}
	f.analyze(data)
	s.current = f
	return nil
}

// Current is the edited document as a File: its draft, state, decoded
// document and problems, for laying out and comparing. Its Loaded bytes are
// the canonical form the save would write.
func (s *Session) Current() *File {
	c := *s.current
	data, _ := s.draft.Canonical()
	c.Loaded = data
	c.Exists = s.Loaded.Exists
	return &c
}

// Apply makes one edit. A failed edit changes nothing. A successful one can
// be undone, and clears what could be redone.
func (s *Session) Apply(edit func(*policy.Draft) (*policy.Draft, error)) error {
	next, err := edit(s.draft)
	if err != nil {
		return err
	}
	prev := s.draft
	s.draft = next
	if err := s.refresh(); err != nil {
		s.draft = prev
		return err
	}
	s.undo = append(s.undo, prev)
	s.redo = nil
	return nil
}

// Undo reverts the last edit, reporting false when there is none.
func (s *Session) Undo() bool {
	if len(s.undo) == 0 {
		return false
	}
	s.redo = append(s.redo, s.draft)
	s.draft = s.undo[len(s.undo)-1]
	s.undo = s.undo[:len(s.undo)-1]
	_ = s.refresh()
	return true
}

// Redo reapplies the last undone edit, reporting false when there is none.
func (s *Session) Redo() bool {
	if len(s.redo) == 0 {
		return false
	}
	s.undo = append(s.undo, s.draft)
	s.draft = s.redo[len(s.redo)-1]
	s.redo = s.redo[:len(s.redo)-1]
	_ = s.refresh()
	return true
}

// Modified reports whether saving would write something other than what was
// loaded: the edited document differs from the loaded one, or nothing is on
// disk yet. Formatting alone is not a change.
func (s *Session) Modified() bool {
	if !s.Loaded.Exists {
		return true
	}
	current, err := s.draft.Canonical()
	if err != nil {
		return true
	}
	loaded, err := s.Loaded.Draft.Canonical()
	return err != nil || !bytes.Equal(current, loaded)
}

// Review is how the edited document differs from the one loaded.
func (s *Session) Review() Comparison {
	return Compare(s.Loaded, s.Current())
}

// Save writes the edited document in canonical form. Unless overwrite is set
// it first checks the disk and returns a *ConflictError when the file is not
// what was loaded (see File.Write). After a successful save the written file
// is the new baseline; undo history is kept.
func (s *Session) Save(overwrite bool) error {
	data, err := s.draft.Canonical()
	if err != nil {
		return err
	}
	if err := s.Loaded.Write(data, overwrite); err != nil {
		return err
	}
	return s.refresh()
}

// SaveAs writes the edited document to a new path and makes that the
// session's file. It is refused when a file already exists there.
func (s *Session) SaveAs(path string) error {
	data, err := s.draft.Canonical()
	if err != nil {
		return err
	}
	target := &File{Path: path}
	if err := target.Write(data, false); err != nil {
		var conflict *ConflictError
		if errors.As(err, &conflict) {
			return fmt.Errorf("%s already exists", path)
		}
		return err
	}
	s.Loaded = target
	return s.refresh()
}

// With returns a copy of the workspace with file i replaced by f and the
// rules across files checked again, so an edit's effect on them (a key
// changed to one another file holds) shows before it is saved.
func (w *Workspace) With(i int, f *File) *Workspace {
	c := *w
	c.Files = append([]*File(nil), w.Files...)
	c.Files[i] = f
	c.Check()
	return &c
}
