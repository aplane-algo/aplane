// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package shellrepl

import (
	"fmt"
	"strings"
)

type commandLineParse struct {
	parts         []string
	trailingSpace bool
	inQuotes      bool
}

// ParseCommand tokenizes one shell command line, handling quoted strings.
func ParseCommand(input string) (string, []string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", nil, nil
	}

	parsed, err := parseCommandLine(input, false)
	if err != nil {
		return "", nil, err
	}
	if len(parsed.parts) == 0 {
		return "", nil, nil
	}

	return parsed.parts[0], parsed.parts[1:], nil
}

func parseCompletableCommandLine(input string) commandLineParse {
	parsed, _ := parseCommandLine(input, true)
	return parsed
}

func parseCommandLine(input string, allowUnterminatedQuote bool) (commandLineParse, error) {
	var parts []string
	var current strings.Builder
	quote := byte(0)
	trailingSpace := false

	for i := 0; i < len(input); i++ {
		ch := input[i]

		switch ch {
		case '"', '\'':
			switch quote {
			case 0:
				quote = ch
				trailingSpace = false
			case ch:
				quote = 0
				trailingSpace = false
			default:
				current.WriteByte(ch)
				trailingSpace = false
			}
		case ' ', '	':
			if quote != 0 {
				current.WriteByte(ch)
				trailingSpace = false
			} else if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
				trailingSpace = true
			} else {
				trailingSpace = true
			}
		default:
			current.WriteByte(ch)
			trailingSpace = false
		}
	}

	if quote != 0 && !allowUnterminatedQuote {
		return commandLineParse{}, fmt.Errorf("unterminated quoted string")
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return commandLineParse{
		parts:         parts,
		trailingSpace: trailingSpace,
		inQuotes:      quote != 0,
	}, nil
}
