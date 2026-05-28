// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"fmt"
	"strings"
)

// ParseLsigArg parses an "arg:name=value" token.
// The value side is decoded via ParseByteValue with bare text enabled.
func ParseLsigArg(token string) (string, []byte, error) {
	argPart := strings.TrimPrefix(token, "arg:")
	eqIdx := strings.Index(argPart, "=")
	if eqIdx == -1 {
		return "", nil, fmt.Errorf("invalid arg syntax, expected arg:name=value, got: %s", token)
	}
	argName := argPart[:eqIdx]
	argValueRaw := argPart[eqIdx+1:]

	argValue, err := ParseByteValue(argValueRaw, true)
	if err != nil {
		return "", nil, fmt.Errorf("invalid arg:%s: %w", argName, err)
	}
	return argName, argValue, nil
}
