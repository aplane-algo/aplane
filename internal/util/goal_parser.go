// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"fmt"
	"regexp"
	"strconv"
)

// ParsedPartKeyInfo contains the parsed information from goal's partkeyinfo output
type ParsedPartKeyInfo struct {
	ParentAddress string
	VoteKey       string
	SelectionKey  string
	StateProofKey string
	VoteFirst     uint64
	VoteLast      uint64
	KeyDilution   uint64
}

// ParsePartKeyInfo parses the multiline output from 'goal account partkeyinfo'
// Example input:
//
//	Parent address:            TESTPARENTADDRESS7777777777777777777777777777777777777777
//	Selection key:             1+bzBrUVQDWDqcv4Iuv9uRYLp4DPViih4x2MGmKcYus=
//	Voting key:                tAtM0mBYE1p5k5KaHOvFYho09qEUEGWzaZs1dmBFWVQ=
//	State proof key:           eS1o+ZVYZDkHBgFqhHAdF8Slyb190C+9aopj85xyUDB7342Pn02Fz2sUP+zGYC697vAWnZFT5SKExOG/PB+asQ==
//	Effective first round:     54647336
//	Effective last round:      57646714
//	Key dilution:              1733
func ParsePartKeyInfo(input string) (*ParsedPartKeyInfo, error) {
	info := &ParsedPartKeyInfo{}

	// Define regex patterns for each field
	patterns := map[string]*regexp.Regexp{
		"parent":     regexp.MustCompile(`(?i)Parent address:\s*([A-Z0-9]+)`),
		"selection":  regexp.MustCompile(`(?i)Selection key:\s*([A-Za-z0-9+/=]+)`),
		"voting":     regexp.MustCompile(`(?i)Voting key:\s*([A-Za-z0-9+/=]+)`),
		"stateproof": regexp.MustCompile(`(?i)State proof key:\s*([A-Za-z0-9+/=]+)`),
		"keydil":     regexp.MustCompile(`(?i)Key dilution:\s*(\d+)`),
	}

	// Try to find effective rounds first, fall back to regular rounds
	effectiveFirstRe := regexp.MustCompile(`(?i)Effective first round:\s*(\d+)`)
	effectiveLastRe := regexp.MustCompile(`(?i)Effective last round:\s*(\d+)`)
	firstRoundRe := regexp.MustCompile(`(?i)First round:\s*(\d+)`)
	lastRoundRe := regexp.MustCompile(`(?i)Last round:\s*(\d+)`)

	// Parse parent address
	if match := patterns["parent"].FindStringSubmatch(input); match != nil {
		info.ParentAddress = match[1]
	} else {
		return nil, fmt.Errorf("could not find 'Parent address' in input")
	}

	// Parse selection key
	if match := patterns["selection"].FindStringSubmatch(input); match != nil {
		info.SelectionKey = match[1]
	} else {
		return nil, fmt.Errorf("could not find 'Selection key' in input")
	}

	// Parse voting key
	if match := patterns["voting"].FindStringSubmatch(input); match != nil {
		info.VoteKey = match[1]
	} else {
		return nil, fmt.Errorf("could not find 'Voting key' in input")
	}

	// Parse state proof key
	if match := patterns["stateproof"].FindStringSubmatch(input); match != nil {
		info.StateProofKey = match[1]
	} else {
		return nil, fmt.Errorf("could not find 'State proof key' in input")
	}

	// Parse key dilution
	if match := patterns["keydil"].FindStringSubmatch(input); match != nil {
		val, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid key dilution value: %s", match[1])
		}
		info.KeyDilution = val
	} else {
		return nil, fmt.Errorf("could not find 'Key dilution' in input")
	}

	// Parse first round (prefer effective first round)
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

	// Parse last round (prefer effective last round)
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
