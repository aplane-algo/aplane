// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"fmt"
	"strings"
)

// ParseKeyValueArgs separates positional args from key=value pairs with bracket awareness.
// Bracketed values are collapsed to a comma-separated string as a slice-1 compatibility shim.
func ParseKeyValueArgs(args []string) ([]string, map[string]string, error) {
	positional := make([]string, 0)
	kv := make(map[string]string)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			positional = append(positional, arg)
			continue
		}

		key := parts[0]
		value := parts[1]
		if key == "" {
			return nil, nil, fmt.Errorf("invalid parameter %q (empty key)", arg)
		}

		if strings.HasPrefix(value, "[") {
			listArgs := append([]string{value}, args[i+1:]...)
			items, endIdx, err := ExtractBracketList(listArgs, 0)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid parameter %q: %w", key, err)
			}
			kv[key] = strings.Join(items, ",")
			i += endIdx
			continue
		}

		kv[key] = value
	}

	return positional, kv, nil
}
