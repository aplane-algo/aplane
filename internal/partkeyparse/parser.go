// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package partkeyparse parses `goal account partkeyinfo` output into structured
// participation-key metadata.
package partkeyparse

import (
	"fmt"
	"regexp"
	"strconv"
)

type ParsedInfo struct {
	ParentAddress string
	VoteKey       string
	SelectionKey  string
	StateProofKey string
	VoteFirst     uint64
	VoteLast      uint64
	KeyDilution   uint64
}

// Parse parses the multiline output from `goal account partkeyinfo`.
func Parse(input string) (*ParsedInfo, error) {
	info := &ParsedInfo{}

	patterns := map[string]*regexp.Regexp{
		"parent":     regexp.MustCompile(`(?i)Parent address:\s*([A-Z0-9]+)`),
		"selection":  regexp.MustCompile(`(?i)Selection key:\s*([A-Za-z0-9+/=]+)`),
		"voting":     regexp.MustCompile(`(?i)Voting key:\s*([A-Za-z0-9+/=]+)`),
		"stateproof": regexp.MustCompile(`(?i)State proof key:\s*([A-Za-z0-9+/=]+)`),
		"keydil":     regexp.MustCompile(`(?i)Key dilution:\s*(\d+)`),
	}

	effectiveFirstRe := regexp.MustCompile(`(?i)Effective first round:\s*(\d+)`)
	effectiveLastRe := regexp.MustCompile(`(?i)Effective last round:\s*(\d+)`)
	firstRoundRe := regexp.MustCompile(`(?i)First round:\s*(\d+)`)
	lastRoundRe := regexp.MustCompile(`(?i)Last round:\s*(\d+)`)

	if match := patterns["parent"].FindStringSubmatch(input); match != nil {
		info.ParentAddress = match[1]
	} else {
		return nil, fmt.Errorf("could not find 'Parent address' in input")
	}

	if match := patterns["selection"].FindStringSubmatch(input); match != nil {
		info.SelectionKey = match[1]
	} else {
		return nil, fmt.Errorf("could not find 'Selection key' in input")
	}

	if match := patterns["voting"].FindStringSubmatch(input); match != nil {
		info.VoteKey = match[1]
	} else {
		return nil, fmt.Errorf("could not find 'Voting key' in input")
	}

	if match := patterns["stateproof"].FindStringSubmatch(input); match != nil {
		info.StateProofKey = match[1]
	} else {
		return nil, fmt.Errorf("could not find 'State proof key' in input")
	}

	if match := patterns["keydil"].FindStringSubmatch(input); match != nil {
		val, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid key dilution value: %s", match[1])
		}
		info.KeyDilution = val
	} else {
		return nil, fmt.Errorf("could not find 'Key dilution' in input")
	}

	if match := effectiveFirstRe.FindStringSubmatch(input); match != nil {
		val, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid effective first round value: %s", match[1])
		}
		info.VoteFirst = val
	} else if match := firstRoundRe.FindStringSubmatch(input); match != nil {
		val, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid first round value: %s", match[1])
		}
		info.VoteFirst = val
	} else {
		return nil, fmt.Errorf("could not find 'Effective first round' or 'First round' in input")
	}

	if match := effectiveLastRe.FindStringSubmatch(input); match != nil {
		val, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid effective last round value: %s", match[1])
		}
		info.VoteLast = val
	} else if match := lastRoundRe.FindStringSubmatch(input); match != nil {
		val, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid last round value: %s", match[1])
		}
		info.VoteLast = val
	} else {
		return nil, fmt.Errorf("could not find 'Effective last round' or 'Last round' in input")
	}

	return info, nil
}
