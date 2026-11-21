// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/externalcheck"
)

// A try never asks a source. When the policy would sign, it lists the lookups
// the cosigner would make for the transaction, through the cosigner's own
// plan, and judges each check on the answer the author gives for it, through
// the cosigner's own judge. A check with no answer still decides.

// ExternalAnswers are what a try judges a document's external checks on, by
// check ID.
type ExternalAnswers map[string]CheckAnswer

// CheckAnswer is how one check's lookups end in a try. Exactly one field is
// set.
type CheckAnswer struct {
	// Answer is the body every lookup of the check is answered with. It is
	// read as the cosigner reads an answer, so one it would refuse is a
	// failed lookup.
	Answer []byte
	// ByPath answers each lookup by its rendered path and query, as the try
	// lists them. A lookup it does not name has no answer.
	ByPath map[string][]byte
	// Failure is one of externalcheck.Failures: every lookup of the check
	// fails that way.
	Failure string
}

func (a CheckAnswer) validate(id string, source policy.ExternalSourceV1) error {
	set := 0
	for _, has := range []bool{a.Answer != nil, a.ByPath != nil, a.Failure != ""} {
		if has {
			set++
		}
	}
	switch {
	case set != 1:
		return fmt.Errorf("external check %s needs exactly one of an answer, answers by request path, or a failure", id)
	case a.ByPath != nil && len(a.ByPath) == 0:
		return fmt.Errorf("external check %s: answers by request path name no request", id)
	case a.Failure != "":
		if _, _, err := externalcheck.FailureOf(a.Failure, source); err != nil {
			return fmt.Errorf("external check %s: failure %s: %w", id, a.Failure, err)
		}
	}
	return nil
}

// ParseAnswerArgs reads answers given as check-id=FILE, one per argument. A
// file is read whole up to a little more than the largest answer a source can
// take, so an oversized one is judged as the cosigner judges it: a failed
// lookup.
func ParseAnswerArgs(args []string) (ExternalAnswers, error) {
	if len(args) == 0 {
		return nil, nil
	}
	answers := make(ExternalAnswers, len(args))
	for _, arg := range args {
		id, path, ok := strings.Cut(arg, "=")
		if !ok || id == "" || path == "" {
			return nil, fmt.Errorf("answer %q is not check-id=FILE", arg)
		}
		if _, dup := answers[id]; dup {
			return nil, fmt.Errorf("external check %s is answered twice", id)
		}
		body, err := readAnswerFile(path)
		if err != nil {
			return nil, fmt.Errorf("answer for external check %s: %w", id, err)
		}
		answers[id] = CheckAnswer{Answer: body}
	}
	return answers, nil
}

func readAnswerFile(path string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- the operator names the answer file
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(file, policy.MaxExternalResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if body == nil {
		body = []byte{}
	}
	return body, nil
}

// TryExternalChecks is what follows a cosigner policy that would sign under a
// document with external checks. Nothing is looked up.
type TryExternalChecks struct {
	// Apply are the IDs of the checks that would make a lookup for the
	// transaction, in document order.
	Apply []string
	// Lookups are the lookups the cosigner would make, identical ones merged
	// as its plan merges them. None when the plan refuses.
	Lookups []TryLookup
	// Judged are the units judged on an answer or a named failure, and
	// Pending those that still decide, both in the cosigner's order.
	Judged  []TryJudgment
	Pending []TryUnit
	// Refusal is the refusal the cosigner would report, nil when none is
	// known: the plan's, or the first judged failure, a missing token before
	// a failed lookup before a rule that does not hold, as the cosigner
	// checks them.
	Refusal *externalcheck.Refusal
}

// TryLookup is one GET the cosigner would make, and the checks judged on its
// answer.
type TryLookup struct {
	Source string
	// Path is the request path and query.
	Path   string
	Checks []string
}

// TryUnit is one check applied to one unit of the transaction.
type TryUnit struct {
	Check  string
	Unit   string
	Source string
	Path   string
}

// TryJudgment is one unit judged. RuleID and Detail say why one did not pass;
// EchoUnverified is set when the check's echo was taken on trust, since a
// canned answer echoes no request ID.
type TryJudgment struct {
	TryUnit
	Passed         bool
	RuleID         string
	Detail         string
	EchoUnverified bool
}

// Ranks of a judged unit: a refusal's, in the order the cosigner finds them
// (a missing token before it connects, a failed lookup before it judges, then
// a rule that does not hold), and then the two kinds of pass.
const (
	rankToken = iota
	rankLookup
	rankRule
	rankEchoUnverified
	rankNone
)

// judgeExternalChecks plans cfg's checks for txn on network, as the cosigner
// would for a request for witnessKey that targets txn alone, and judges each
// unit on answers.
func judgeExternalChecks(doc *policy.PolicyV1, cfg *policy.Config, txn types.Transaction, network, witnessKey string, answers ExternalAnswers) (*TryExternalChecks, error) {
	x := &TryExternalChecks{Apply: applicableExternalChecks(doc, network, txn), Lookups: []TryLookup{}, Judged: []TryJudgment{}, Pending: []TryUnit{}}
	for _, id := range sortedKeys(answers) {
		if !slices.Contains(x.Apply, id) {
			return nil, fmt.Errorf("external check %s does not apply to this transaction (applying: %s)", id, wordsOrNone(x.Apply))
		}
	}
	plan, refusal := externalcheck.BuildPlan(cfg.ExternalChecks, cfg.ExternalSources, externalcheck.Request{
		WitnessKey: witnessKey,
		Group:      []types.Transaction{txn},
		Targets:    []int{0},
		NetworkOf:  func(types.Transaction) string { return network },
	})
	if refusal != nil {
		x.Refusal = refusal
		return x, nil
	}
	for i, lookup := range plan.Lookups {
		x.Lookups = append(x.Lookups, TryLookup{Source: lookup.SourceName, Path: lookup.Path})
		for _, j := range plan.Judgments {
			if j.Lookup == i && !slices.Contains(x.Lookups[i].Checks, j.Check.ID) {
				x.Lookups[i].Checks = append(x.Lookups[i].Checks, j.Check.ID)
			}
		}
	}
	if err := checkAnswerPaths(plan, answers); err != nil {
		return nil, err
	}
	best := rankNone
	for _, j := range plan.Judgments {
		lookup := plan.Lookups[j.Lookup]
		unit := TryUnit{Check: j.Check.ID, Unit: j.Unit, Source: lookup.SourceName, Path: lookup.Path}
		refusal, rank, ok := judgeUnit(j, lookup, answers)
		if !ok {
			x.Pending = append(x.Pending, unit)
			continue
		}
		judged := TryJudgment{TryUnit: unit, Passed: refusal == nil, EchoUnverified: rank == rankEchoUnverified}
		if refusal != nil {
			refusal.Unit, refusal.Source, refusal.Path = unit.Unit, unit.Source, unit.Path
			judged.RuleID, judged.Detail = refusal.RuleID(), refusal.Detail
			if rank < best {
				best, x.Refusal = rank, refusal
			}
		}
		x.Judged = append(x.Judged, judged)
	}
	return x, nil
}

// judgeUnit judges one unit on its check's answer: the refusal it gives, nil
// for a pass, ranked by when the cosigner would have found it. ok is false
// when the check has no answer for the unit's lookup.
func judgeUnit(j externalcheck.Judgment, lookup externalcheck.Lookup, answers ExternalAnswers) (*externalcheck.Refusal, int, bool) {
	answer, has := answers[j.Check.ID]
	if !has {
		return nil, rankNone, false
	}
	refuse := func(outcome, detail string) *externalcheck.Refusal {
		return &externalcheck.Refusal{CheckID: j.Check.ID, Outcome: outcome, Detail: detail}
	}
	if answer.Failure != "" {
		outcome, detail, _ := externalcheck.FailureOf(answer.Failure, lookup.Source)
		if outcome == policy.ExternalCheckTokenNotSetOutcome {
			return refuse(outcome, detail), rankToken, true
		}
		return refuse(outcome, detail), rankLookup, true
	}
	body := answer.Answer
	if answer.ByPath != nil {
		if body, has = answer.ByPath[lookup.Path]; !has {
			return nil, rankNone, false
		}
	}
	root, err := externalcheck.ParseAnswer(body, lookup.Source)
	if err != nil {
		return refuse(policy.ExternalCheckUnavailableOutcome, err.Error()), rankLookup, true
	}
	passed, detail, echoUnverified := externalcheck.JudgeOffline(j.Check, j.Facts, root)
	switch {
	case !passed:
		return refuse("", detail), rankRule, true
	case echoUnverified:
		return nil, rankEchoUnverified, true
	}
	return nil, rankNone, true
}

// checkAnswerPaths refuses an answer by request path that names no lookup of
// its check: a path the cosigner would not ask is a mistake in the answer.
func checkAnswerPaths(plan *externalcheck.Plan, answers ExternalAnswers) error {
	for _, id := range sortedKeys(answers) {
		byPath := answers[id].ByPath
		if byPath == nil {
			continue
		}
		var paths []string
		for _, j := range plan.Judgments {
			if p := plan.Lookups[j.Lookup].Path; j.Check.ID == id && !slices.Contains(paths, p) {
				paths = append(paths, p)
			}
		}
		for _, path := range sortedKeys(byPath) {
			if !slices.Contains(paths, path) {
				return fmt.Errorf("external check %s makes no lookup %s for this transaction (its lookups: %s)", id, path, wordsOrNone(paths))
			}
		}
	}
	return nil
}

// validateAnswers refuses answers for checks the document does not have, and
// answers a check's source could not give.
func validateAnswers(doc *policy.PolicyV1, answers ExternalAnswers) error {
	if len(answers) == 0 {
		return nil
	}
	if len(doc.ExternalChecks) == 0 {
		return errors.New("this document has no external checks to answer")
	}
	for _, id := range sortedKeys(answers) {
		i := slices.IndexFunc(doc.ExternalChecks, func(c policy.ExternalCheckV1) bool { return c.ID == id })
		if i < 0 {
			var ids []string
			for _, c := range doc.ExternalChecks {
				ids = append(ids, c.ID)
			}
			return fmt.Errorf("this document has no external check %s (its checks: %s)", id, strings.Join(ids, ", "))
		}
		if err := answers[id].validate(id, doc.ExternalSources[doc.ExternalChecks[i].Source]); err != nil {
			return err
		}
	}
	return nil
}

// decided reports whether the checks reach an answer: a refusal, or every
// unit judged and passed.
func (x *TryExternalChecks) decided() bool {
	return x.Refusal != nil || len(x.Pending) == 0
}

// passedChecks are the checks every unit of which was judged and passed, in
// document order.
func (x *TryExternalChecks) passedChecks() []string {
	var out []string
	for _, id := range x.Apply {
		judged := slices.ContainsFunc(x.Judged, func(j TryJudgment) bool { return j.Check == id })
		failed := slices.ContainsFunc(x.Judged, func(j TryJudgment) bool { return j.Check == id && !j.Passed })
		pending := slices.ContainsFunc(x.Pending, func(u TryUnit) bool { return u.Check == id })
		if judged && !failed && !pending {
			out = append(out, id)
		}
	}
	return out
}

// pendingChecks are the checks with a unit still to decide, in document
// order.
func (x *TryExternalChecks) pendingChecks() []string {
	var out []string
	for _, u := range x.Pending {
		if !slices.Contains(out, u.Check) {
			out = append(out, u.Check)
		}
	}
	return out
}

// refusalViolation is the cosigner's refusal as the try reports it: with the
// detail and the request, which the requester is never told, since a try is
// the operator's own tool.
func refusalViolation(r *externalcheck.Refusal) policy.LintViolation {
	return policy.LintViolation{
		RuleID: r.RuleID(), Scope: "txn", TxnIndex: -1,
		Message: strings.TrimPrefix(r.AuditReason(), r.RuleID()+": "),
	}
}

// Lines are the checks as text: the lookups the cosigner would make, the
// units judged, and those that still decide.
func (x *TryExternalChecks) Lines() []string {
	if x == nil || len(x.Apply) == 0 {
		return nil
	}
	var lines []string
	if len(x.Lookups) > 0 {
		lines = append(lines, "lookups the cosigner would make:")
		for _, l := range x.Lookups {
			lines = append(lines, fmt.Sprintf("  %s: GET %s, for %s", l.Source, l.Path, strings.Join(l.Checks, ", ")))
		}
	}
	if len(x.Judged) > 0 {
		lines = append(lines, "judged on the answers given:")
		for _, j := range x.Judged {
			verdict := "passes"
			switch {
			case !j.Passed:
				verdict = "refuses (" + j.RuleID + "): " + j.Detail
			case j.EchoUnverified:
				verdict = "passes; its echo cannot be verified offline"
			}
			lines = append(lines, fmt.Sprintf("  %s, %s: %s", j.Check, j.Unit, verdict))
		}
	}
	if len(x.Pending) > 0 {
		lines = append(lines, "still to decide, with no answer given:")
		for _, u := range x.Pending {
			lines = append(lines, fmt.Sprintf("  %s, %s: %s GET %s", u.Check, u.Unit, u.Source, u.Path))
		}
	}
	return lines
}

func wordsOrNone(words []string) string {
	if len(words) == 0 {
		return "none"
	}
	return strings.Join(words, ", ")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
