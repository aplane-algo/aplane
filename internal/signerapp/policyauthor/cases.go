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
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/externalcheck"
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
// workspace directory, the transaction, how the external checks' lookups
// end, and the answer expected. Answers and Failures are keyed by check ID;
// a check in neither still decides, and none is in both.
type Case struct {
	Name     string                `json:"name"`
	Document string                `json:"document"`
	Txn      CaseTxn               `json:"txn"`
	Answers  map[string]CaseAnswer `json:"answers,omitempty"`
	Failures map[string]string     `json:"failures,omitempty"`
	Expect   CaseExpect            `json:"expect"`
}

// CaseAnswer is one check's canned answer: Answer for every unit of the
// check, or ByPath, one per rendered request path and query, when units need
// different answers. Exactly one is set. An answer is read as the cosigner
// reads one, from its text without the file's indentation.
type CaseAnswer struct {
	Answer json.RawMessage            `json:"answer,omitempty"`
	ByPath map[string]json.RawMessage `json:"by_path,omitempty"`
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
	e := CaseExpect{Outcome: r.OutcomeWord(), RuleID: r.RuleID}
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
		case !filepath.IsLocal(c.Document):
			return fmt.Errorf("case %q: document %q must be a path inside the workspace directory", c.Name, c.Document)
		}
		if _, ok := policyeval.ParseOutcome(c.Expect.Outcome); !ok && c.Expect.Outcome != OutcomeConditionalApprove {
			return fmt.Errorf("case %q: expected outcome %q is not reject, review, approve, %s or default", c.Name, c.Expect.Outcome, OutcomeConditionalApprove)
		}
		if err := c.validateExternal(); err != nil {
			return fmt.Errorf("case %q: %w", c.Name, err)
		}
		seen[c.Name] = true
	}
	return nil
}

// validateExternal checks a case's answers and failures as far as they can
// be checked without its document: each answer has one form, each failure is
// a named one, and no check has both. Whether the document has the check, and
// whether its source could fail that way, is checked when the case runs.
func (c Case) validateExternal() error {
	for _, id := range sortedKeys(c.Answers) {
		a := c.Answers[id]
		switch {
		case id == "":
			return errors.New("an answer names no check")
		case (len(a.Answer) > 0) == (a.ByPath != nil):
			return fmt.Errorf("answer for external check %s needs exactly one of \"answer\" and \"by_path\"", id)
		case a.ByPath != nil && len(a.ByPath) == 0:
			return fmt.Errorf("answer for external check %s: by_path names no request", id)
		}
		for _, path := range sortedKeys(a.ByPath) {
			if !strings.HasPrefix(path, "/") {
				return fmt.Errorf("answer for external check %s: by_path key %q is not a request path", id, path)
			}
		}
		if _, both := c.Failures[id]; both {
			return fmt.Errorf("external check %s has both an answer and a failure", id)
		}
	}
	for _, id := range sortedKeys(c.Failures) {
		if id == "" {
			return errors.New("a failure names no check")
		}
		if !slices.Contains(externalcheck.Failures, c.Failures[id]) {
			return fmt.Errorf("failure %q for external check %s is not one of %s", c.Failures[id], id, strings.Join(externalcheck.Failures, ", "))
		}
	}
	return nil
}

// externalAnswers is how the case's lookups end, as a try takes them. Each
// answer is compacted, so a save's indentation never changes what it is.
func (c Case) externalAnswers() (ExternalAnswers, error) {
	if len(c.Answers) == 0 && len(c.Failures) == 0 {
		return nil, nil
	}
	out := make(ExternalAnswers, len(c.Answers)+len(c.Failures))
	for id, a := range c.Answers {
		var answer CheckAnswer
		if len(a.Answer) > 0 {
			body, err := compactAnswer(a.Answer)
			if err != nil {
				return nil, fmt.Errorf("answer for external check %s: %w", id, err)
			}
			answer.Answer = body
		}
		if a.ByPath != nil {
			answer.ByPath = make(map[string][]byte, len(a.ByPath))
			for path, raw := range a.ByPath {
				body, err := compactAnswer(raw)
				if err != nil {
					return nil, fmt.Errorf("answer for external check %s at %s: %w", id, path, err)
				}
				answer.ByPath[path] = body
			}
		}
		out[id] = answer
	}
	for id, failure := range c.Failures {
		out[id] = CheckAnswer{Failure: failure}
	}
	return out, nil
}

func compactAnswer(raw json.RawMessage) ([]byte, error) {
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// CaseOf is a try kept as a case named name, for the document at path
// document in the workspace: its transaction, how its external checks'
// lookups ended, and its answer. An answer the cosigner would refuse to read
// is kept as the failure it stands for, too_large or not_json, since its
// text may not survive being written into the cases file.
func CaseOf(name, document string, f *File, txn TryTxn, answers ExternalAnswers, result TryResult) Case {
	c := Case{Name: name, Document: document, Txn: CaseTxnOf(txn), Expect: ExpectOf(result)}
	for _, id := range sortedKeys(answers) {
		a := answers[id]
		if a.Failure != "" {
			c.addFailure(id, a.Failure)
			continue
		}
		source := sourceOfCheck(f, id)
		if a.ByPath == nil {
			if failure := unreadableAnswer(a.Answer, source); failure != "" {
				c.addFailure(id, failure)
				continue
			}
			c.addAnswer(id, CaseAnswer{Answer: json.RawMessage(a.Answer)})
			continue
		}
		// Answers by path come from a case, so each is already JSON.
		byPath := make(map[string]json.RawMessage, len(a.ByPath))
		for path, body := range a.ByPath {
			byPath[path] = json.RawMessage(body)
		}
		c.addAnswer(id, CaseAnswer{ByPath: byPath})
	}
	return c
}

func (c *Case) addAnswer(id string, a CaseAnswer) {
	if c.Answers == nil {
		c.Answers = map[string]CaseAnswer{}
	}
	c.Answers[id] = a
}

func (c *Case) addFailure(id, failure string) {
	if c.Failures == nil {
		c.Failures = map[string]string{}
	}
	c.Failures[id] = failure
}

// unreadableAnswer is the failure an answer the cosigner would refuse to read
// stands for, "" for one it reads.
func unreadableAnswer(body []byte, source policy.ExternalSourceV1) string {
	if _, err := externalcheck.ParseAnswer(body, source); err == nil {
		return ""
	}
	if len(body) > source.MaxResponseBytes {
		return externalcheck.FailureTooLarge
	}
	if !json.Valid(body) || !utf8.Valid(body) {
		return externalcheck.FailureNotJSON
	}
	// Valid JSON the strict reader refuses, such as a duplicate key, is kept
	// as it is: it survives the cases file, and is refused again when run.
	return ""
}

func sourceOfCheck(f *File, id string) policy.ExternalSourceV1 {
	if f != nil && f.Document != nil {
		for _, check := range f.Document.ExternalChecks {
			if check.ID == id {
				return f.Document.ExternalSources[check.Source]
			}
		}
	}
	return policy.ExternalSourceV1{MaxResponseBytes: policy.DefaultExternalRespBytes}
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
		answers, err := c.externalAnswers()
		if err != nil {
			out[i].Err = err
			continue
		}
		got, err := TryWithAnswers(f, c.Txn.TryTxn(), answers, networks)
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
