// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/partkeyparse"
)

// keyRegPasteMode handles multiline paste of goal partkeyinfo output. A
// registration whose confirmation wait failed comes back with its result,
// which names the transaction, and the error.
func (r *REPLState) keyRegPasteMode() (command.Result, error) {
	r.println("Paste the output from 'goal account partkeyinfo' below.")
	r.println("Press Enter twice on empty lines when done, Ctrl+C to cancel.")
	r.println()

	// Input ends at the second of two blank lines in a row; single blank
	// lines are dropped.
	blanks := 0
	lines, cancelled, err := r.readLinesUntil(nil, func(line string) bool {
		if strings.TrimSpace(line) != "" {
			blanks = 0
			return false
		}
		blanks++
		return blanks == 2
	})
	if err != nil {
		return nil, err
	}
	if cancelled {
		return newTerminalCommandResult(nil), nil
	}
	lines = slices.DeleteFunc(lines, func(line string) bool { return strings.TrimSpace(line) == "" })
	if len(lines) == 0 {
		return nil, fmt.Errorf("no input provided")
	}

	// Join lines into single string for parsing
	input := strings.Join(lines, "\n")

	// Parse the partkeyinfo output
	parsedInfo, err := partkeyparse.Parse(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse partkeyinfo output: %w", err)
	}

	// Display parsed information
	r.println("\nParsed participation key info:")
	r.printf("  Account: %s\n", r.app().FormatAddress(parsedInfo.ParentAddress))
	r.printf("  Voting key: %s\n", parsedInfo.VoteKey)
	r.printf("  Selection key: %s\n", parsedInfo.SelectionKey)
	r.printf("  State proof key: %s\n", parsedInfo.StateProofKey)
	r.printf("  First round: %d\n", parsedInfo.VoteFirst)
	r.printf("  Last round: %d\n", parsedInfo.VoteLast)
	r.printf("  Key dilution: %d\n", parsedInfo.KeyDilution)
	r.println()

	incentiveEligible, err := askIncentiveEligibility(r)
	if err != nil {
		return nil, err
	}
	r.println()

	result, err := r.app().KeyRegFromPartKey(r.commandContext(), parsedInfo, incentiveEligible)
	if result == nil {
		return nil, err
	}
	commandResult, resultErr := r.keyRegCommandResult(result, true)
	if resultErr != nil {
		return nil, resultErr
	}
	return commandResult, err
}

// keyRegCommandResult is a key registration's result, in either form of the
// command. prompted is true in paste mode, which asked about incentive
// eligibility.
func (r *REPLState) keyRegCommandResult(result *apshellapp.KeyRegCommandResult, prompted bool) (command.Result, error) {
	simulated := r.app().IsSimulateEnabled()
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() { r.renderKeyRegResult(result, simulated, prompted) })
	}, keyRegProjection{
		Account: result.Account, Mode: result.Mode, TxID: result.TxID,
		Confirmed: result.Confirmed, Simulated: simulated,
		IncentiveRequested: result.IncentiveRequested, AlreadyIncentiveEligible: result.AlreadyIncentiveEligible,
	})
}

// renderKeyRegResult draws a key registration: the submission's output (the
// simulation, the signing and the confirmation wait) and warnings, then what
// the registration did or will do once confirmed.
func (r *REPLState) renderKeyRegResult(result *apshellapp.KeyRegCommandResult, simulated, prompted bool) {
	r.renderSubmissionOutput(result.Output)
	r.renderWarnings(result.Warnings)
	account := r.app().FormatAddress(result.Account)
	statusMsg := "OFFLINE"
	if result.Mode == "online" {
		statusMsg = "ONLINE in consensus"
	}
	r.printf("Marking %s %s using %s...\n", account, statusMsg, result.SigningKeyType)
	if !simulated {
		r.printf("Key registration submitted: %s\n", result.TxID)
	}
	reportIncentiveEligibility(r, result, prompted)
	if result.Confirmed {
		switch result.Mode {
		case "online":
			r.printf("\n%s is now ONLINE (participating in consensus)\n", account)
			r.printf("Participation valid from round %d to %d\n", result.VoteFirst, result.VoteLast)
		case "offline":
			r.printf("\n%s is now OFFLINE\n", account)
		}
		return
	}
	switch result.Mode {
	case "online":
		r.printf("\nWhen confirmed, %s will be marked ONLINE\n", account)
	case "offline":
		r.printf("\nWhen confirmed, %s will be marked OFFLINE (temporary)\n", account)
	}
}
