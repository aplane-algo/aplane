// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/appinput"
)

// ParseLsigArg parses an "arg:name=value" token.
// The value side is decoded via the shared byte-value grammar in appinput.
func ParseLsigArg(token string) (string, []byte, error) {
	argPart := strings.TrimPrefix(token, "arg:")
	eqIdx := strings.Index(argPart, "=")
	if eqIdx == -1 {
		return "", nil, fmt.Errorf("invalid arg syntax, expected arg:name=value, got: %s", token)
	}
	argName := argPart[:eqIdx]
	argValueRaw := argPart[eqIdx+1:]

	argValue, err := appinput.ParseByteValue(argValueRaw)
	if err != nil {
		return "", nil, fmt.Errorf("invalid arg:%s: %w", argName, err)
	}
	return argName, argValue, nil
}
