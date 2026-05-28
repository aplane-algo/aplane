// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/partkeyparse"

	"github.com/chzyer/readline"
)

// keyRegPasteMode handles multiline paste of goal partkeyinfo output
func (r *REPLState) keyRegPasteMode() error {
	r.println("Paste the output from 'goal account partkeyinfo' below.")
	r.println("Press Enter twice on empty lines when done, Ctrl+C to cancel.")
	r.println()

	// Read multiline input using LineReader (supports Ctrl+C) or fallback to scanner
	var lines []string
	emptyLineCount := 0

	if r.LineReader != nil {
		// Use readline-based input (handles Ctrl+C gracefully)
		r.clearInputPrompt()
		for {
			line, err := r.readInteractiveLine()
			if err != nil {
				if errors.Is(err, readline.ErrInterrupt) {
					r.println("\nCancelled.")
					return nil
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
	parsedInfo, err := partkeyparse.Parse(input)
	if err != nil {
		return fmt.Errorf("failed to parse partkeyinfo output: %w", err)
	}

	// Display parsed information
	r.println("\nParsed participation key info:")
	r.printf("  Account: %s\n", r.app().FormatAddress(parsedInfo.ParentAddress, ""))
	r.printf("  Voting key: %s\n", parsedInfo.VoteKey)
	r.printf("  Selection key: %s\n", parsedInfo.SelectionKey)
	r.printf("  State proof key: %s\n", parsedInfo.StateProofKey)
	r.printf("  First round: %d\n", parsedInfo.VoteFirst)
	r.printf("  Last round: %d\n", parsedInfo.VoteLast)
	r.printf("  Key dilution: %d\n", parsedInfo.KeyDilution)
	r.println()

	// Check if account is already incentive eligible and prompt user if needed
	incentiveEligible, err := checkIncentiveEligibility(r, parsedInfo.ParentAddress, false, true)
	if err != nil {
		return err
	}
	r.println()

	result, err := r.app().KeyRegFromPartKey(r.commandContext(), parsedInfo, incentiveEligible)
	if err != nil {
		return err
	}

	r.printf("Marking %s ONLINE (participating) using %s...\n", r.app().FormatAddress(parsedInfo.ParentAddress, ""), result.SigningKeyType)
	if !r.app().IsSimulateEnabled() {
		r.printf("Key registration submitted: %s\n", result.TxID)
	}
	if result.Confirmed {
		r.printf("\n%s is now ONLINE (participating)\n", r.app().FormatAddress(parsedInfo.ParentAddress, ""))
		r.printf("Participation valid from round %d to %d\n", parsedInfo.VoteFirst, parsedInfo.VoteLast)
	}

	return nil
}
