// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"
)

// Saved cases are tries kept with the answer expected, re-run after edits so
// a change that alters a decision already made is seen before the document
// is installed. They live in .appolicy/cases.json under the workspace
// directory: discovery loads only the directory's own *.json files, so the
// cases file is never taken for a policy document.

// CasesFormat is the saved-cases file format.
const CasesFormat = "aplane.policy-cases.v1"

// CasesPath is where a workspace directory keeps its saved cases.
func CasesPath(dir string) string { return filepath.Join(dir, ".appolicy", "cases.json") }

// CaseFile is a workspace's saved cases.
type CaseFile struct {
	Format string `json:"format"`
	Cases  []Case `json:"cases"`
}

// Case is one saved try: the document, by its path relative to the
// workspace directory, the transaction, and the answer expected.
type Case struct {
	Name     string     `json:"name"`
	Document string     `json:"document"`
	Txn      CaseTxn    `json:"txn"`
	Expect   CaseExpect `json:"expect"`
}

// CaseTxn is a try's transaction as saved. Amounts are base units; a nonzero
// asset makes it an asset transfer. An omitted network is testnet and an
// omitted fee 1000 microAlgos, as appolicy try takes them.
type CaseTxn struct {
	Network         string  `json:"network,omitempty"`
	Sender          string  `json:"sender"`
	Receiver        string  `json:"receiver"`
	Amount          uint64  `json:"amount,omitempty"`
	Asset           uint64  `json:"asset,omitempty"`
	Fee             *uint64 `json:"fee,omitempty"`
	CloseTo         string  `json:"close_to,omitempty"`
	ClawbackFrom    string  `json:"clawback_from,omitempty"`
	RekeyTo         string  `json:"rekey_to,omitempty"`
	RekeyTargetHeld bool    `json:"rekey_target_held,omitempty"`
}

// CaseExpect is the answer a case expects: the outcome's word and its rule.
// For a review or approval the rule is the deciding one; for a rejection it
// is the first violation's. An empty rule expects none (review, approve) or
// does not check it (reject).
type CaseExpect struct {
	Outcome string `json:"outcome"`
	RuleID  string `json:"rule_id,omitempty"`
}

// TryTxn is the transaction the case describes.
func (t CaseTxn) TryTxn() TryTxn {
	fee := uint64(1000)
	if t.Fee != nil {
		fee = *t.Fee
	}
	return TryTxn{
		Network:         t.Network,
		Sender:          t.Sender,
		Receiver:        t.Receiver,
		Amount:          t.Amount,
		Asset:           t.Asset,
		Fee:             fee,
		CloseTo:         t.CloseTo,
		ClawbackFrom:    t.ClawbackFrom,
		RekeyTo:         t.RekeyTo,
		RekeyTargetHeld: t.RekeyTargetHeld,
	}
}

// CaseTxnOf is the saved form of a try's transaction.
func CaseTxnOf(t TryTxn) CaseTxn {
	c := CaseTxn{
		Network:         t.Network,
		Sender:          t.Sender,
		Receiver:        t.Receiver,
		Amount:          t.Amount,
		Asset:           t.Asset,
		CloseTo:         t.CloseTo,
		ClawbackFrom:    t.ClawbackFrom,
		RekeyTo:         t.RekeyTo,
		RekeyTargetHeld: t.RekeyTargetHeld,
	}
	if c.Network == "testnet" {
		c.Network = ""
	}
	if t.Fee != 1000 {
		fee := t.Fee
		c.Fee = &fee
	}
	return c
}

// ExpectOf is the answer a try gave, as a case would expect it.
func ExpectOf(r TryResult) CaseExpect {
	e := CaseExpect{Outcome: r.Outcome.String(), RuleID: r.RuleID}
	if r.Outcome == policyeval.Reject && len(r.Violations) > 0 {
		e.RuleID = r.Violations[0].RuleID
	}
	return e
}

// LoadCases reads a workspace directory's saved cases. A directory with none
// returns an error satisfying errors.Is(err, os.ErrNotExist).
func LoadCases(dir string) (*CaseFile, error) {
	path := CasesPath(dir)
	data, _, err := fsutil.ReadRegularFileLimited(path, maxFileBytes)
	if err != nil {
		return nil, err
	}
	var cf CaseFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// A second value after the first would be ignored, silently skipping
	// its cases and losing them on the next save.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: unexpected content after the cases object", path)
	}
	if err := cf.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cf, nil
}

func (cf *CaseFile) validate() error {
	if cf.Format != CasesFormat {
		return fmt.Errorf("format is %q, want %q", cf.Format, CasesFormat)
	}
	seen := map[string]bool{}
	for i, c := range cf.Cases {
		switch {
		case strings.TrimSpace(c.Name) == "":
			return fmt.Errorf("case %d has no name", i+1)
		case seen[c.Name]:
			return fmt.Errorf("two cases are named %q", c.Name)
		case c.Document == "":
			return fmt.Errorf("case %q names no document", c.Name)
		case filepath.IsAbs(c.Document) || !filepath.IsLocal(c.Document):
			return fmt.Errorf("case %q: document %q must be a path inside the workspace directory", c.Name, c.Document)
		}
		if _, ok := policyeval.ParseOutcome(c.Expect.Outcome); !ok {
			return fmt.Errorf("case %q: expected outcome %q is not reject, review, approve or default", c.Name, c.Expect.Outcome)
		}
		seen[c.Name] = true
	}
	return nil
}

// Add appends c, refusing a name already used.
func (cf *CaseFile) Add(c Case) error {
	next := &CaseFile{Format: CasesFormat, Cases: append(append([]Case(nil), cf.Cases...), c)}
	if err := next.validate(); err != nil {
		return err
	}
	cf.Format, cf.Cases = next.Format, next.Cases
	return nil
}

// Save writes the cases to dir's cases file, creating .appolicy if needed.
func (cf *CaseFile) Save(dir string) error {
	cf.Format = CasesFormat
	if err := cf.validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	path := CasesPath(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return fsutil.WriteFileDurable(path, append(data, '\n'))
}

// CaseResult is how one case ran: the answer it got, or why it could not
// run.
type CaseResult struct {
	Case   Case
	Got    TryResult
	Err    error
	Passed bool
}

// ErrDocumentMissing reports a case whose document is not in the workspace.
var ErrDocumentMissing = errors.New("document not found")

// RunCases runs every case. document returns the document a case names, so
// the editor can run them against unsaved edits; it returns an error
// wrapping ErrDocumentMissing when there is none.
func RunCases(cases []Case, document func(name string) (*File, error), networks Networks) []CaseResult {
	out := make([]CaseResult, len(cases))
	for i, c := range cases {
		out[i].Case = c
		f, err := document(c.Document)
		if err != nil {
			out[i].Err = err
			continue
		}
		got, err := Try(f, c.Txn.TryTxn(), networks)
		if err != nil {
			out[i].Err = err
			continue
		}
		out[i].Got = got
		out[i].Passed = expectMatches(c.Expect, ExpectOf(got))
	}
	return out
}

func expectMatches(want, got CaseExpect) bool {
	if want.Outcome != got.Outcome {
		return false
	}
	if want.Outcome == policyeval.Reject.String() && want.RuleID == "" {
		return true
	}
	return want.RuleID == got.RuleID
}

// DiskDocuments looks documents up on disk under dir, for running cases
// outside the editor.
func DiskDocuments(dir string) func(name string) (*File, error) {
	return func(name string) (*File, error) {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrDocumentMissing, path)
		}
		return LoadFile(path), nil
	}
}

// Documents looks documents up among w's files, under its directory, as
// shown presents file i: in the editor, with its unsaved edits.
func (w *Workspace) Documents(shown func(i int) *File) func(name string) (*File, error) {
	dir := w.Dir()
	return func(name string) (*File, error) {
		want, err := filepath.Abs(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		for i, f := range w.Files {
			if path, err := filepath.Abs(f.Path); err == nil && path == want {
				return shown(i), nil
			}
		}
		return nil, fmt.Errorf("%w: %s is not in the workspace", ErrDocumentMissing, name)
	}
}
