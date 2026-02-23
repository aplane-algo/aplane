// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/util"

	"github.com/chzyer/readline"
)

// keyRegPasteMode handles multiline paste of goal partkeyinfo output
func (r *REPLState) keyRegPasteMode() error {
	fmt.Println("Paste the output from 'goal account partkeyinfo' below.")
	fmt.Println("Press Enter twice on empty lines when done, Ctrl+C to cancel.")
	fmt.Println()

	// Read multiline input using LineReader (supports Ctrl+C) or fallback to scanner
	var lines []string
	emptyLineCount := 0

	if r.LineReader != nil {
		// Use readline-based input (handles Ctrl+C gracefully)
		if r.SetPrompt != nil {
			r.SetPrompt("")
		}
		for {
			line, err := r.LineReader()
			if err != nil {
				if errors.Is(err, readline.ErrInterrupt) {
					fmt.Println("\nCancelled.")
					return nil
				}
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("error reading input: %w", err)
			}
			if strings.TrimSpace(line) == "" {
				emptyLineCount++
				if emptyLineCount >= 2 {
					break
				}
			} else {
				emptyLineCount = 0
				lines = append(lines, line)
			}
		}
	} else {
		// Fallback: basic scanner mode (no Ctrl+C handling)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) == "" {
				emptyLineCount++
				if emptyLineCount >= 2 {
					break
				}
			} else {
				emptyLineCount = 0
				lines = append(lines, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading input: %w", err)
		}
	}

	if len(lines) == 0 {
		return fmt.Errorf("no input provided")
	}

	// Join lines into single string for parsing
	input := strings.Join(lines, "\n")

	// Parse the partkeyinfo output
	parsedInfo, err := util.ParsePartKeyInfo(input)
	if err != nil {
		return fmt.Errorf("failed to parse partkeyinfo output: %w", err)
	}

	// Display parsed information
	fmt.Println("\nParsed participation key info:")
	fmt.Printf("  Account: %s\n", r.FormatAddress(parsedInfo.ParentAddress, ""))
	fmt.Printf("  Voting key: %s\n", parsedInfo.VoteKey)
	fmt.Printf("  Selection key: %s\n", parsedInfo.SelectionKey)
	fmt.Printf("  State proof key: %s\n", parsedInfo.StateProofKey)
	fmt.Printf("  First round: %d\n", parsedInfo.VoteFirst)
	fmt.Printf("  Last round: %d\n", parsedInfo.VoteLast)
	fmt.Printf("  Key dilution: %d\n", parsedInfo.KeyDilution)
	fmt.Println()

	// Check if account is already incentive eligible and prompt user if needed
	incentiveEligible, err := r.checkIncentiveEligibility(parsedInfo.ParentAddress, false, true)
	if err != nil {
		return err
	}
	fmt.Println()

	// Prepare key registration transaction via engine
	prep, err := r.Engine.PrepareKeyReg(engine.KeyRegParams{
		Account:           parsedInfo.ParentAddress,
		Mode:              "online",
		VoteKey:           parsedInfo.VoteKey,
		SelectionKey:      parsedInfo.SelectionKey,
		StateProofKey:     parsedInfo.StateProofKey,
		VoteFirst:         parsedInfo.VoteFirst,
		VoteLast:          parsedInfo.VoteLast,
		KeyDilution:       parsedInfo.KeyDilution,
		IncentiveEligible: incentiveEligible,
	})
	if err != nil {
		return fmt.Errorf("failed to prepare keyreg: %w", err)
	}

	// Print appropriate message
	fmt.Printf("Marking %s ONLINE (participating) using %s...\n", r.FormatAddress(parsedInfo.ParentAddress, ""), prep.SigningContext.DisplayKeyType())

	// Sign and submit (don't wait - we wait manually below)
	result, err := r.Engine.SignAndSubmit(prep, false)
	if err != nil {
		return fmt.Errorf("key registration failed: %w", err)
	}

	txid := result.TxID
	if r.Engine.Simulate {
		return nil
	}

	fmt.Printf("Key registration submitted: %s\n", txid)

	// Always wait for confirmation in paste mode
	err = algo.WaitForConfirmation(r.Engine.AlgodClient, txid, 9)
	if err != nil {
		return err
	}

	fmt.Printf("\n%s is now ONLINE (participating)\n", r.FormatAddress(parsedInfo.ParentAddress, ""))
	fmt.Printf("Participation valid from round %d to %d\n", parsedInfo.VoteFirst, parsedInfo.VoteLast)

	return nil
}
