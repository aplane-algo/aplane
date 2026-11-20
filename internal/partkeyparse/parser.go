// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package partkeyparse parses `goal account partkeyinfo` output into structured
// participation-key metadata.
package partkeyparse

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
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

// keyFields are the string fields of one key, in the order Parse requires
// them, each labelled as the pasted text names it.
var keyFields = []struct {
	label string
	re    *regexp.Regexp
	field func(*ParsedInfo) *string
}{
	{"Parent address", regexp.MustCompile(`(?i)Parent address:\s*([A-Z0-9]+)`), func(i *ParsedInfo) *string { return &i.ParentAddress }},
	{"Selection key", regexp.MustCompile(`(?i)Selection key:\s*([A-Za-z0-9+/=]+)`), func(i *ParsedInfo) *string { return &i.SelectionKey }},
	{"Voting key", regexp.MustCompile(`(?i)Voting key:\s*([A-Za-z0-9+/=]+)`), func(i *ParsedInfo) *string { return &i.VoteKey }},
	{"State proof key", regexp.MustCompile(`(?i)State proof key:\s*([A-Za-z0-9+/=]+)`), func(i *ParsedInfo) *string { return &i.StateProofKey }},
}

const keyDilutionLabel = "Key dilution"

var (
	keyDilutionRe    = regexp.MustCompile(`(?i)Key dilution:\s*(\d+)`)
	effectiveFirstRe = regexp.MustCompile(`(?i)Effective first round:\s*(\d+)`)
	effectiveLastRe  = regexp.MustCompile(`(?i)Effective last round:\s*(\d+)`)
	firstRoundRe     = regexp.MustCompile(`(?i)First round:\s*(\d+)`)
	lastRoundRe      = regexp.MustCompile(`(?i)Last round:\s*(\d+)`)
)

// Parse parses the multiline output from `goal account partkeyinfo`.
func Parse(input string) (*ParsedInfo, error) {
	// One key at a time. Each field below is the first match in the whole
	// text, so with two keys pasted together, or part of one and all of
	// another, the registration would mix them. Any field appearing twice
	// means more than one key is there.
	for _, f := range keyFields {
		if err := requireOneKey(input, f.label, f.re); err != nil {
			return nil, err
		}
	}
	if err := requireOneKey(input, keyDilutionLabel, keyDilutionRe); err != nil {
		return nil, err
	}

	// The round lines too: one key's rounds with another's keys is the same
	// mix. "First round" also matches inside "Effective first round", so each
	// of those two may appear twice in one key's text and no more.
	for label, limit := range map[*regexp.Regexp]int{effectiveFirstRe: 1, effectiveLastRe: 1, firstRoundRe: 2, lastRoundRe: 2} {
		if matches := label.FindAllStringIndex(input, -1); len(matches) > limit {
			return nil, fmt.Errorf("the input holds more than one participation key (its round lines repeat); paste only the one to register")
		}
	}

	info := &ParsedInfo{}
	for _, f := range keyFields {
		match := f.re.FindStringSubmatch(input)
		if match == nil {
			return nil, fmt.Errorf("could not find '%s' in input", f.label)
		}
		*f.field(info) = match[1]
	}

	match := keyDilutionRe.FindStringSubmatch(input)
	if match == nil {
		return nil, fmt.Errorf("could not find '%s' in input", keyDilutionLabel)
	}
	val, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid key dilution value: %s", match[1])
	}
	info.KeyDilution = val

	if info.VoteFirst, err = parseRound(input, effectiveFirstRe, firstRoundRe, "First round"); err != nil {
		return nil, err
	}
	if info.VoteLast, err = parseRound(input, effectiveLastRe, lastRoundRe, "Last round"); err != nil {
		return nil, err
	}
	return info, nil
}

func requireOneKey(input, label string, re *regexp.Regexp) error {
	if matches := re.FindAllStringIndex(input, -1); len(matches) > 1 {
		return fmt.Errorf("the input holds more than one participation key (%s appears %d times); paste only the one to register", label, len(matches))
	}
	return nil
}

// parseRound reads a round from its effective line, else from the plain
// line labelled label.
func parseRound(input string, effectiveRe, regularRe *regexp.Regexp, label string) (uint64, error) {
	lower := strings.ToLower(label)
	if match := effectiveRe.FindStringSubmatch(input); match != nil {
		val, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid effective %s value: %s", lower, match[1])
		}
		return val, nil
	}
	if match := regularRe.FindStringSubmatch(input); match != nil {
		val, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid %s value: %s", lower, match[1])
		}
		return val, nil
	}
	return 0, fmt.Errorf("could not find 'Effective %s' or '%s' in input", lower, label)
}
