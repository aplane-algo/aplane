// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"flag"
	"io"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
)

// parseInterleaved parses fs over args with flags allowed before and after
// the positional arguments, which it returns.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

type tryViolation struct {
	RuleID  string `json:"rule_id"`
	Message string `json:"message"`
}

// tryExternalChecks is what follows a cosigner policy that would sign under a
// document with external checks: the checks that apply, the lookups the
// cosigner would make, the units judged on the answers given and those still
// to decide, and the refusal the cosigner would report.
type tryExternalChecks struct {
	Apply   []string       `json:"apply"`
	Lookups []tryLookup    `json:"lookups"`
	Judged  []tryJudgment  `json:"judged"`
	Pending []tryCheckUnit `json:"pending"`
	Refusal *tryRefusal    `json:"refusal,omitempty"`
}

type tryLookup struct {
	Source string   `json:"source"`
	Path   string   `json:"path"`
	Checks []string `json:"checks"`
}

type tryCheckUnit struct {
	Check  string `json:"check"`
	Unit   string `json:"unit"`
	Source string `json:"source"`
	Path   string `json:"path"`
}

type tryJudgment struct {
	tryCheckUnit
	Result         string `json:"result"`
	RuleID         string `json:"rule_id,omitempty"`
	Detail         string `json:"detail,omitempty"`
	EchoUnverified bool   `json:"echo_unverified,omitempty"`
}

type tryRefusal struct {
	RuleID string `json:"rule_id"`
	Check  string `json:"check"`
	Unit   string `json:"unit"`
	Source string `json:"source"`
	Path   string `json:"path,omitempty"`
	Detail string `json:"detail"`
}

func tryExternalReport(x *policyauthor.TryExternalChecks) *tryExternalChecks {
	if x == nil {
		return nil
	}
	out := &tryExternalChecks{
		Apply:   append([]string{}, x.Apply...),
		Lookups: []tryLookup{}, Judged: []tryJudgment{}, Pending: []tryCheckUnit{},
	}
	for _, l := range x.Lookups {
		out.Lookups = append(out.Lookups, tryLookup{Source: l.Source, Path: l.Path, Checks: append([]string{}, l.Checks...)})
	}
	unit := func(u policyauthor.TryUnit) tryCheckUnit {
		return tryCheckUnit{Check: u.Check, Unit: u.Unit, Source: u.Source, Path: u.Path}
	}
	for _, j := range x.Judged {
		result := "fail"
		if j.Passed {
			result = "pass"
		}
		out.Judged = append(out.Judged, tryJudgment{tryCheckUnit: unit(j.TryUnit), Result: result, RuleID: j.RuleID, Detail: j.Detail, EchoUnverified: j.EchoUnverified})
	}
	for _, u := range x.Pending {
		out.Pending = append(out.Pending, unit(u))
	}
	if r := x.Refusal; r != nil {
		out.Refusal = &tryRefusal{RuleID: r.RuleID(), Check: r.CheckID, Unit: r.Unit, Source: r.Source, Path: r.Path, Detail: r.Detail}
	}
	return out
}

// answerFlags collects each --answer check-id=FILE.
type answerFlags []string

func (a *answerFlags) String() string { return strings.Join(*a, " ") }

func (a *answerFlags) Set(v string) error {
	*a = append(*a, v)
	return nil
}

type tryReport struct {
	File           string             `json:"file"`
	Role           string             `json:"role"`
	Key            string             `json:"key"`
	Outcome        string             `json:"outcome"`
	RuleID         string             `json:"rule_id,omitempty"`
	Violations     []tryViolation     `json:"violations,omitempty"`
	ExternalChecks *tryExternalChecks `json:"external_checks,omitempty"`
	Summary        string             `json:"summary"`
	Assumes        []string           `json:"assumes"`
}

func runTry(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("try", stderr)
	var txn policyauthor.TryTxn
	fs.StringVar(&txn.Sender, "from", "", "sender address")
	fs.StringVar(&txn.Receiver, "to", "", `receiver address, or "self" for the sender`)
	fs.Uint64Var(&txn.Amount, "amount", 0, "amount in base units: microAlgos, or the asset's raw units")
	fs.Uint64Var(&txn.Asset, "asset", 0, "asset ID; omit for ALGO")
	fs.StringVar(&txn.Network, "network", "testnet", "network the transaction is for")
	fs.Uint64Var(&txn.Fee, "fee", 1000, "fee in microAlgos")
	fs.StringVar(&txn.CloseTo, "close-to", "", "close the sender's ALGO, or its asset holding, to this address")
	fs.StringVar(&txn.ClawbackFrom, "clawback-from", "", "make an asset transfer a clawback from this holder")
	fs.StringVar(&txn.RekeyTo, "rekey-to", "", "rekey the sender to this address")
	fs.BoolVar(&txn.RekeyTargetHeld, "rekey-held", false, "the node holds the rekey target's key (default: it does not)")
	contextFile := fs.String("node-context", "", "use this export context instead of the one beside the file")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	var answerArgs answerFlags
	fs.Var(&answerArgs, "answer", "judge external check ID on the answer in FILE, as check-id=FILE; repeatable")
	files, err := parseInterleaved(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(files) != 1 {
		writeln(stderr, "appolicy try: name one policy file")
		return exitUsage
	}
	if txn.Receiver == "self" {
		txn.Receiver = txn.Sender
	}
	if txn.RekeyTargetHeld && txn.RekeyTo == "" {
		writeln(stderr, "appolicy try: --rekey-held needs --rekey-to")
		return exitUsage
	}
	f := policyauthor.LoadFile(files[0])
	if f.Document == nil {
		writef(stderr, "%s is %s; run appolicy check %s\n", f.Path, f.State, f.Path)
		return exitUsage
	}
	node, err := nodeContextFor([]string{f.Path}, *contextFile)
	if err != nil {
		writef(stderr, "appolicy try: %v\n", err)
		return exitUsage
	}
	networks, err := node.Networks(time.Now())
	if err != nil {
		writef(stderr, "appolicy try: %v\n", err)
		return exitUsage
	}
	answers, err := policyauthor.ParseAnswerArgs(answerArgs)
	if err != nil {
		writef(stderr, "appolicy try: %v\n", err)
		return exitUsage
	}
	result, err := policyauthor.TryWithAnswers(f, txn, answers, networks)
	if err != nil {
		writef(stderr, "appolicy try: %v\n", err)
		return exitUsage
	}
	report := tryReport{
		File:    f.Path,
		Role:    string(result.Role),
		Key:     f.Key,
		Outcome: result.OutcomeWord(),
		RuleID:  result.RuleID,
		Summary: result.Summary,
		Assumes: result.Assumes,
	}
	for _, v := range result.Violations {
		report.Violations = append(report.Violations, tryViolation{RuleID: v.RuleID, Message: v.Message})
	}
	report.ExternalChecks = tryExternalReport(result.ExternalChecks)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			writef(stderr, "appolicy try: %v\n", err)
			return exitUsage
		}
		return exitOK
	}
	writef(stdout, "%s (%s document %q): %s\n", f.Path, result.Role, f.Key, result.Summary)
	for _, v := range result.Violations {
		writef(stdout, "  [%s] %s\n", v.RuleID, v.Message)
	}
	for _, line := range result.ExternalChecks.Lines() {
		writeln(stdout, line)
	}
	writeln(stdout, "assumed:")
	for _, a := range result.Assumes {
		writef(stdout, "  - %s\n", a)
	}
	return exitOK
}
