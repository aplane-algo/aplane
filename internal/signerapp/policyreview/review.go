// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policyreview owns what an operator reviews before a policy change
// is applied: reading candidate policy files, diffing them against the active
// documents, and rendering problems and diffs. The apadmin policy commands and
// the apadmin TUI share it so both surfaces show the same review. The rules
// for checking and committing policy live in policyapply.
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
	"github.com/aplane-algo/aplane/internal/policy"
)

// maxPolicyFileBytes bounds what a policy file read accepts; the node
// rejects larger documents.
const maxPolicyFileBytes = 1 << 20

// MaxPolicyBytes is the largest policy document a review accepts, for callers
// that collect a document some other way than reading a file.
const MaxPolicyBytes = maxPolicyFileBytes

// ReadDocuments reads policy files for the node's role. A signer node takes
// one file; each cosigner file names its key in its "key" field. names maps a
// document's key to the file it came from, for messages. The file "-" reads
// from stdin.
func ReadDocuments(files []string, role string, stdin io.Reader) ([]adminproto.PolicyDocument, map[string]string, error) {
	return readDocuments(files, role, func(file string) ([]byte, error) { return readPolicyFile(file, stdin) })
}

// ReadRegularDocuments is ReadDocuments for callers that must not block on
// what a path names, such as an interactive UI reading inside its event loop:
// every path must be a regular file, not a symlink, FIFO, or device, and
// there is no stdin form.
func ReadRegularDocuments(files []string, role string) ([]adminproto.PolicyDocument, map[string]string, error) {
	return readDocuments(files, role, func(file string) ([]byte, error) {
		data, _, err := fsutil.ReadRegularFileLimited(file, maxPolicyFileBytes)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", file, err)
		}
		return validPolicyBytes(file, data)
	})
}

func readDocuments(files []string, role string, read func(file string) ([]byte, error)) ([]adminproto.PolicyDocument, map[string]string, error) {
	if role == "signer" && len(files) != 1 {
		return nil, nil, fmt.Errorf("a signer node takes exactly one policy file")
	}
	docs := make([]adminproto.PolicyDocument, 0, len(files))
	names := make(map[string]string, len(files))
	for _, file := range files {
		data, err := read(file)
		if err != nil {
			return nil, nil, err
		}
		doc, err := documentFromBytes(file, role, data)
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
// node. A cosigner document names its key in its "key" field.
func documentFromBytes(label, role string, data []byte) (adminproto.PolicyDocument, error) {
	doc := adminproto.PolicyDocument{Document: string(data)}
	if role == "cosigner" {
		var head struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal(data, &head); err != nil || head.Key == "" {
			return adminproto.PolicyDocument{}, fmt.Errorf("%s: a cosigner policy file must be a JSON object with a \"key\" field", label)
		}
		doc.Key = head.Key
	}
	return doc, nil
}

// DocumentFromText builds the candidate document for text that did not come
// from a file, such as an edit made in the apadmin TUI. label names it in
// messages. The same emptiness, UTF-8, size, and key rules apply as for files.
func DocumentFromText(role, label, text string) (adminproto.PolicyDocument, error) {
	if len(text) > MaxPolicyBytes {
		return adminproto.PolicyDocument{}, fmt.Errorf("%s is larger than %d bytes", label, MaxPolicyBytes)
	}
	data, err := validPolicyBytes(label, []byte(text))
	if err != nil {
		return adminproto.PolicyDocument{}, err
	}
	return documentFromBytes(label, role, data)
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

func validPolicyBytes(file string, data []byte) ([]byte, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("%s is empty", file)
	}
	// JSON encoding would replace invalid UTF-8, so the node would not
	// receive the file's exact bytes.
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%s is not valid UTF-8", file)
	}
	return data, nil
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
// means the decoded documents are equal, so applying changes nothing.
type DocumentDiff struct {
	Label     string
	Changes   []policy.PolicyChange
	Identical bool
}

// DiffDocument compares a candidate document with the node's active document
// for the same key. hasCurrent is false when the key has no active document.
func DiffDocument(role, key string, hasCurrent bool, current, next string) ([]policy.PolicyChange, bool, error) {
	if role == "cosigner" {
		nextDoc, err := policy.DecodeCosignerPolicyV1([]byte(next), key)
		if err != nil {
			return nil, false, err
		}
		if !hasCurrent {
			return policy.DiffCosignerPolicyV1(nil, nextDoc), false, nil
		}
		currentDoc, err := policy.DecodeCosignerPolicyV1([]byte(current), key)
		if err != nil {
			return nil, false, fmt.Errorf("active policy: %w", err)
		}
		return policy.DiffCosignerPolicyV1(currentDoc, nextDoc), reflect.DeepEqual(currentDoc, nextDoc), nil
	}
	nextDoc, err := policy.DecodeSignerPolicyV1([]byte(next))
	if err != nil {
		return nil, false, err
	}
	if !hasCurrent {
		return nil, false, fmt.Errorf("the node has no active signer policy")
	}
	currentDoc, err := policy.DecodeSignerPolicyV1([]byte(current))
	if err != nil {
		return nil, false, fmt.Errorf("active policy: %w", err)
	}
	return policy.DiffSignerPolicyV1(currentDoc, nextDoc), reflect.DeepEqual(currentDoc, nextDoc), nil
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
				_, _ = fmt.Fprintf(w, "%s: no change to what the policy allows; the document differs only in order\n", d.Label)
			}
			continue
		}
		_, _ = fmt.Fprintf(w, "%s:\n", d.Label)
		for _, c := range d.Changes {
			_, _ = fmt.Fprintf(w, "  %-9s  %s: %s\n", c.Effect, c.Path, c.Summary)
		}
	}
}
