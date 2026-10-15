// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policyreview owns what an operator reviews before a policy change
// is applied: reading candidate policy files, diffing them against the
// documents that govern the keys now, and rendering problems and diffs. The
// apadmin policy commands and the apadmin TUI share it so both surfaces show
// the same review. The rules for checking and committing policy live in
// policyapply.
package policyreview

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"unicode/utf8"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
)

// maxPolicyFileBytes bounds what a policy file read accepts; the node
// rejects larger documents.
const maxPolicyFileBytes = 1 << 20

// MaxPolicyBytes is the largest policy document a review accepts, for callers
// that collect a document some other way than reading a file.
const MaxPolicyBytes = maxPolicyFileBytes

// ReadDocuments reads policy files. Each file names the document it is in
// its "key" field: "default" or a key selector. names maps a document's key
// to the file it came from, for messages. The file "-" reads from stdin.
func ReadDocuments(files []string, stdin io.Reader) ([]adminproto.PolicyDocument, map[string]string, error) {
	return readDocuments(files, func(file string) ([]byte, error) { return readPolicyFile(file, stdin) })
}

// ReadRegularDocuments is ReadDocuments for callers that must not block on
// what a path names, such as an interactive UI reading inside its event loop:
// every path must be a regular file, not a symlink, FIFO, or device, and
// there is no stdin form.
func ReadRegularDocuments(files []string) ([]adminproto.PolicyDocument, map[string]string, error) {
	return readDocuments(files, func(file string) ([]byte, error) {
		data, _, err := fsutil.ReadRegularFileLimited(file, maxPolicyFileBytes)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", file, err)
		}
		return validPolicyBytes(file, data)
	})
}

func readDocuments(files []string, read func(file string) ([]byte, error)) ([]adminproto.PolicyDocument, map[string]string, error) {
	docs := make([]adminproto.PolicyDocument, 0, len(files))
	names := make(map[string]string, len(files))
	for _, file := range files {
		data, err := read(file)
		if err != nil {
			return nil, nil, err
		}
		doc, err := documentFromBytes(file, data)
		if err != nil {
			return nil, nil, err
		}
		if other, dup := names[doc.Key]; dup {
			return nil, nil, fmt.Errorf("%s and %s are both policies for %s", other, file, doc.Key)
		}
		names[doc.Key] = file
		docs = append(docs, doc)
	}
	return docs, names, nil
}

// documentFromBytes turns one candidate's bytes into the document sent to the
// node. The document names its key in its "key" field.
func documentFromBytes(label string, data []byte) (adminproto.PolicyDocument, error) {
	var head struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(data, &head); err != nil || head.Key == "" {
		return adminproto.PolicyDocument{}, fmt.Errorf("%s: a policy file must be a JSON object with a \"key\" field (\"default\" or the key it governs)", label)
	}
	return adminproto.PolicyDocument{Key: head.Key, Document: string(data)}, nil
}

// DocumentFromText builds the candidate document for text that did not come
// from a file, such as an edit made in the apadmin TUI. label names it in
// messages. The same emptiness, UTF-8, size, and key rules apply as for files.
func DocumentFromText(label, text string) (adminproto.PolicyDocument, error) {
	if len(text) > MaxPolicyBytes {
		return adminproto.PolicyDocument{}, fmt.Errorf("%s is larger than %d bytes", label, MaxPolicyBytes)
	}
	data, err := validPolicyBytes(label, []byte(text))
	if err != nil {
		return adminproto.PolicyDocument{}, err
	}
	return documentFromBytes(label, data)
}

func readPolicyFile(file string, stdin io.Reader) ([]byte, error) {
	r := stdin
	if file != "-" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxPolicyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}
	return validPolicyBytes(file, data)
}

// validPolicyBytes applies the rules every candidate meets before it is sent:
// not empty, valid UTF-8, and free of comments. Comments are a convenience of
// the producer tools; the node stores the exact bytes it receives, so they
// are removed here and never reach it.
func validPolicyBytes(file string, data []byte) ([]byte, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("%s is empty", file)
	}
	// JSON encoding would replace invalid UTF-8, so the node would not
	// receive the file's exact bytes.
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%s is not valid UTF-8", file)
	}
	stripped, err := StripComments(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if len(bytes.TrimSpace(stripped)) == 0 {
		return nil, fmt.Errorf("%s holds only comments", file)
	}
	return stripped, nil
}

// PrintProblems writes one line per validation problem. names maps a
// document's key to the file it came from.
func PrintProblems(w io.Writer, label string, problems []adminproto.PolicyProblem, names map[string]string) {
	for _, problem := range problems {
		where := names[problem.Key]
		if where == "" {
			where = problem.Key
		}
		if problem.Pointer != "" {
			where += " " + problem.Pointer
		}
		if where != "" {
			where += ": "
		}
		_, _ = fmt.Fprintf(w, "%s: %s%s\n", label, where, problem.Message)
	}
}

// DocumentDiff is the reviewed change to one policy document. Identical
// means the key already has a document of its own and the candidate decodes
// equal to it, so applying changes nothing.
type DocumentDiff struct {
	Label     string
	Changes   []policy.PolicyChange
	Identical bool
}

// DiffCandidate compares the candidate document for key with the document
// that governs the key now: its own when ownCurrent is true, otherwise the
// node default. A key gaining its first document of its own is a change even
// when the text equals the default, since the key stops following the default.
func DiffCandidate(role noderole.Role, key string, current, next string, ownCurrent bool) ([]policy.PolicyChange, bool, error) {
	nextDoc, err := policy.DecodePolicyV1([]byte(next), key, role)
	if err != nil {
		return nil, false, err
	}
	currentKey := key
	if !ownCurrent {
		currentKey = policy.DefaultKey
	}
	currentDoc, err := policy.DecodePolicyV1([]byte(current), currentKey, role)
	if err != nil {
		return nil, false, fmt.Errorf("active policy: %w", err)
	}
	changes := policy.DiffPolicyV1(currentDoc, nextDoc)
	if !ownCurrent && key != policy.DefaultKey {
		changes = append([]policy.PolicyChange{{Path: "/", Effect: policy.PolicyChangeNeutral,
			Summary: "the key gets a policy of its own; compared with the node default it followed"}}, changes...)
		return changes, false, nil
	}
	return changes, reflect.DeepEqual(currentDoc, nextDoc), nil
}

// DiffRemoval describes a key losing its own document: it will follow
// nextDefault, the default in force after the change.
func DiffRemoval(role noderole.Role, key string, own, nextDefault string) ([]policy.PolicyChange, error) {
	ownDoc, err := policy.DecodePolicyV1([]byte(own), key, role)
	if err != nil {
		return nil, fmt.Errorf("active policy for %s: %w", key, err)
	}
	defaultDoc, err := policy.DecodePolicyV1([]byte(nextDefault), policy.DefaultKey, role)
	if err != nil {
		return nil, fmt.Errorf("default policy: %w", err)
	}
	changes := policy.DiffPolicyV1(ownDoc, defaultDoc)
	return append([]policy.PolicyChange{{Path: "/", Effect: policy.PolicyChangeNeutral,
		Summary: "policy of its own removed; the key follows the node default"}}, changes...), nil
}

// Unchanged reports whether applying would change no document: every
// submitted document decodes equal to the active one and nothing is removed.
func Unchanged(diffs []DocumentDiff) bool {
	for _, d := range diffs {
		if !d.Identical {
			return false
		}
	}
	return true
}

// PrintDiffs writes each document's changes, marked tightened, loosened, or
// changed. There is no closing total: every change already carries its own
// mark, so a count would only repeat the lines above it.
func PrintDiffs(w io.Writer, diffs []DocumentDiff) {
	if len(diffs) == 0 {
		_, _ = fmt.Fprintln(w, "no changes")
		return
	}
	for _, d := range diffs {
		if len(d.Changes) == 0 {
			if d.Identical {
				_, _ = fmt.Fprintf(w, "%s: no changes\n", d.Label)
			} else {
				_, _ = fmt.Fprintf(w, "%s: the document differs, but effective permissions are unchanged\n", d.Label)
			}
			continue
		}
		_, _ = fmt.Fprintf(w, "%s:\n", d.Label)
		for _, c := range d.Changes {
			_, _ = fmt.Fprintf(w, "  %-9s  %s: %s\n", c.Effect, c.Path, c.Summary)
		}
	}
}
