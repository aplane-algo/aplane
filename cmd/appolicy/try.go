// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"

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

// signerNetworks is the network mapping a try or test uses: the signer's
// config.yaml in signerData, or the built-in networks.
func signerNetworks(signerData string) (policyauthor.Networks, error) {
	if signerData == "" {
		return policyauthor.BuiltinNetworks(), nil
	}
	return policyauthor.SignerNetworks(signerData)
}

type tryViolation struct {
	RuleID  string `json:"rule_id"`
	Message string `json:"message"`
}

type tryReport struct {
	File       string         `json:"file"`
	Role       string         `json:"role"`
	Key        string         `json:"key"`
	Outcome    string         `json:"outcome"`
	RuleID     string         `json:"rule_id,omitempty"`
	Violations []tryViolation `json:"violations,omitempty"`
	Summary    string         `json:"summary"`
	Assumes    []string       `json:"assumes"`
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
	signerData := fs.String("signer-data", os.Getenv("APSIGNER_DATA"), "signer data directory whose config.yaml network mapping is read, read-only")
	asJSON := fs.Bool("json", false, "print the result as JSON")
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
	networks, err := signerNetworks(*signerData)
	if err != nil {
		writef(stderr, "appolicy try: %v\n", err)
		return exitUsage
	}
	result, err := policyauthor.Try(f, txn, networks)
	if err != nil {
		writef(stderr, "appolicy try: %v\n", err)
		return exitUsage
	}
	report := tryReport{
		File:    f.Path,
		Role:    string(result.Role),
		Key:     f.Key,
		Outcome: result.Outcome.String(),
		RuleID:  result.RuleID,
		Summary: result.Summary,
		Assumes: result.Assumes,
	}
	for _, v := range result.Violations {
		report.Violations = append(report.Violations, tryViolation{RuleID: v.RuleID, Message: v.Message})
	}
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
	writeln(stdout, "assumed:")
	for _, a := range result.Assumes {
		writef(stdout, "  - %s\n", a)
	}
	return exitOK
}
