// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"fmt"
	"strings"
)

// ExtractBracketList extracts items from bracket notation starting at args[startIdx].
// It supports both standalone brackets ([ alice bob ]) and attached brackets ([alice bob]).
// The returned endIdx is the index of the final token consumed.
func ExtractBracketList(args []string, startIdx int) ([]string, int, error) {
	if startIdx >= len(args) {
		return nil, startIdx, fmt.Errorf("expected '[' to start bracket list")
	}

	first := args[startIdx]
	if !strings.HasPrefix(first, "[") {
		return nil, startIdx, fmt.Errorf("expected '[' to start bracket list")
	}

	var items []string

	first = strings.TrimPrefix(first, "[")
	if strings.Contains(first, "[") {
		return nil, startIdx, fmt.Errorf("nested '[' is not allowed in bracket list")
	}
	if strings.HasSuffix(first, "]") {
		item := strings.TrimSuffix(first, "]")
		if strings.Contains(item, "]") {
			return nil, startIdx, fmt.Errorf("invalid bracket list item %q", args[startIdx])
		}
		if item != "" {
			items = append(items, item)
		}
		if len(items) == 0 {
			return nil, startIdx, fmt.Errorf("empty bracket list is not allowed")
		}
		return items, startIdx, nil
	}
	if first != "" {
		items = append(items, first)
	}

	for i := startIdx + 1; i < len(args); i++ {
		arg := args[i]
		if strings.Contains(arg, "[") {
			return nil, startIdx, fmt.Errorf("nested '[' is not allowed in bracket list")
		}
		if arg == "]" {
			if len(items) == 0 {
				return nil, startIdx, fmt.Errorf("empty bracket list is not allowed")
			}
			return items, i, nil
		}
		if strings.HasSuffix(arg, "]") {
			last := strings.TrimSuffix(arg, "]")
			if strings.Contains(last, "]") {
				return nil, startIdx, fmt.Errorf("invalid bracket list item %q", args[i])
			}
			if last != "" {
				items = append(items, last)
			}
			if len(items) == 0 {
				return nil, startIdx, fmt.Errorf("empty bracket list is not allowed")
			}
			return items, i, nil
		}
		if strings.Contains(arg, "]") {
			return nil, startIdx, fmt.Errorf("invalid bracket list item %q", args[i])
		}
		items = append(items, arg)
	}

	return nil, startIdx, fmt.Errorf("missing closing ']' for bracket list")
}
