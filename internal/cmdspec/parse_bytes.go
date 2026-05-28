// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseByteValue parses a byte-oriented value token.
// Supported forms:
// - hex:...
// - b64:...
// - text:...
// - 0x... (hex compatibility form)
// - bare text when allowBareText is true
func ParseByteValue(input string, allowBareText bool) ([]byte, error) {
	switch {
	case strings.HasPrefix(input, "hex:"):
		value, err := hex.DecodeString(strings.TrimSpace(strings.TrimPrefix(input, "hex:")))
		if err != nil {
			return nil, fmt.Errorf("invalid hex value: %w", err)
		}
		return value, nil
	case strings.HasPrefix(input, "b64:"):
		value, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(input, "b64:")))
		if err != nil {
			return nil, fmt.Errorf("invalid base64 value: %w", err)
		}
		return value, nil
	case strings.HasPrefix(input, "text:"):
		return []byte(strings.TrimPrefix(input, "text:")), nil
	case strings.HasPrefix(input, "0x"):
		value, err := hex.DecodeString(input[2:])
		if err != nil {
			return nil, fmt.Errorf("invalid hex value: %w", err)
		}
		return value, nil
	case allowBareText:
		return []byte(input), nil
	default:
		return nil, fmt.Errorf("unsupported byte value %q (expected hex:, b64:, text:, or 0x...)", input)
	}
}
