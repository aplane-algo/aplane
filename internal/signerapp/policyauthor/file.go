// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policyauthor is the core of the files-only policy editor: it loads
// policy files, reports their problems by JSON Pointer, keeps what each file
// held when it was loaded, and writes a file back only when it has not
// changed on disk since. It has no user interface and never touches a node,
// a store, a passphrase or the admin protocol; its output is files that
// apadmin policy check and apply accept.
package policyauthor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policytext"
)

// maxFileBytes is the largest policy file read, comments included. It is the
// limit apadmin applies to a policy file it reads.
const maxFileBytes = 1 << 20

// Severity says whether a problem blocks check (an error) or only reports a
// surprising shape (a warning, which never blocks an apply).
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Problem is one thing check reports about a file. Pointer is a JSON Pointer
// into the document, "" for the file as a whole. RuleID names the advisory a
// warning comes from, and is empty for errors.
type Problem struct {
	Path     string   `json:"path"`
	Pointer  string   `json:"pointer"`
	Severity Severity `json:"severity"`
	RuleID   string   `json:"rule_id,omitempty"`
	Message  string   `json:"message"`
}

// State is how far a file got: read, parsed as JSON, and decoded as policy.
type State int

const (
	// StateUnreadable: the file could not be read (missing, not a regular
	// file, a symlink, or over the size limit). Nothing was loaded.
	StateUnreadable State = iota
	// StateUnparsable: the bytes are not strict JSON, so there is no draft.
	// The bytes are kept exactly; the file can only be repaired outside the
	// editor.
	StateUnparsable
	// StateInvalid: the draft parses but is not valid policy.
	StateInvalid
	// StateValid: the draft decodes and compiles.
	StateValid
)

func (s State) String() string {
	return [...]string{"unreadable", "unparsable", "invalid", "valid"}[s]
}

// File is one policy file as loaded. Its identity is its Path: a broken
// document may have no usable key, and two drafts may share one, so Key and
// Role are only what the document says.
type File struct {
	Path string
	// Exists reports whether the file existed when it was loaded or last
	// written; Loaded and LoadedSHA256 are its bytes then.
	Exists       bool
	Loaded       []byte
	LoadedSHA256 string
	// HadComments reports that the loaded bytes held // or /* */ comments,
	// which were removed before parsing and are not written back.
	HadComments bool

	State State
	// Draft is the parsed document, nil when the file is unreadable or
	// unparsable. Document is its decoded policy, nil unless State is
	// StateValid.
	Draft    *policy.Draft
	Document *policy.PolicyV1
	// Key and Role are the document's "key" and "role" when they are strings
	// ("" otherwise). Role is set only for "signer" or "cosigner".
	Key  string
	Role noderole.Role

	Problems []Problem
}

// LoadFile reads and analyzes one policy file. A failure is recorded in the
// File's State and Problems, not returned.
func LoadFile(path string) *File {
	f := &File{Path: path}
	data, _, err := fsutil.ReadRegularFileLimited(path, maxFileBytes)
	if err != nil {
		f.problem("", SeverityError, "", fmt.Sprintf("cannot read the file: %v", err))
		return f
	}
	f.setLoaded(data)
	f.analyze(data)
	return f
}

func (f *File) setLoaded(data []byte) {
	sum := sha256.Sum256(data)
	f.Exists = true
	f.Loaded = append([]byte(nil), data...)
	f.LoadedSHA256 = hex.EncodeToString(sum[:])
}

func (f *File) problem(pointer string, severity Severity, ruleID, message string) {
	f.Problems = append(f.Problems, Problem{Path: f.Path, Pointer: pointer, Severity: severity, RuleID: ruleID, Message: message})
}

// documentProblem records err at its JSON Pointer when it carries one.
func (f *File) documentProblem(err error) {
	var docErr *policy.DocumentError
	if errors.As(err, &docErr) {
		f.problem(docErr.Pointer, SeverityError, "", docErr.Msg)
		return
	}
	f.problem("", SeverityError, "", err.Error())
}

// analyze derives the state, draft, document and problems from data.
func (f *File) analyze(data []byte) {
	f.State, f.Draft, f.Document, f.Key, f.Role, f.Problems = StateUnparsable, nil, nil, "", "", nil
	stripped, err := policytext.StripComments(data)
	if err != nil {
		f.problem("", SeverityError, "", err.Error())
		return
	}
	f.HadComments = !bytes.Equal(stripped, data)
	if len(bytes.TrimSpace(stripped)) == 0 {
		f.problem("", SeverityError, "", "the file holds no document")
		return
	}
	draft, err := policy.ParseDraft(stripped)
	if err != nil {
		f.documentProblem(err)
		return
	}
	f.State, f.Draft = StateInvalid, draft
	f.Key, _ = draft.TopLevelString("key")
	if role, ok := draft.TopLevelString("role"); ok && (role == string(noderole.RoleSigner) || role == string(noderole.RoleCosigner)) {
		f.Role = noderole.Role(role)
	}

	// The decoder reads "role" right after "format", so a document without a
	// valid role fails there whatever role it is decoded as.
	role := f.Role
	if role == "" {
		role = noderole.RoleSigner
	}
	doc, err := policy.DecodePolicyV1(stripped, f.Key, role)
	if err != nil {
		f.documentProblem(err)
		return
	}
	if _, err := doc.Compile(policy.DefaultConfig()); err != nil {
		f.documentProblem(err)
		return
	}
	f.State, f.Document = StateValid, doc
	for _, a := range doc.Advisories() {
		f.problem(a.Pointer, SeverityWarning, a.RuleID, a.Message)
	}
}

// Canonical returns the file's document in canonical form. A file with no
// draft (unreadable or unparsable) has no canonical form.
func (f *File) Canonical() ([]byte, error) {
	if f.Draft == nil {
		return nil, fmt.Errorf("%s is %s and has no canonical form", f.Path, f.State)
	}
	return f.Draft.Canonical()
}

// Errors reports whether the file has any error-severity problem.
func (f *File) Errors() bool {
	for _, p := range f.Problems {
		if p.Severity == SeverityError {
			return true
		}
	}
	return false
}
