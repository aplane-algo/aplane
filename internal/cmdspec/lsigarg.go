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

// AddLsigArg parses an "arg:name=value" token into args, making the map on
// first use. Different names may each be given once; a name given twice is
// refused, because the second value would silently replace the first.
func AddLsigArg(args *map[string][]byte, token string) error {
	name, value, err := ParseLsigArg(token)
	if err != nil {
		return err
	}
	if _, repeated := (*args)[name]; repeated {
		return fmt.Errorf("arg:%s given more than once", name)
	}
	if *args == nil {
		*args = make(map[string][]byte)
	}
	(*args)[name] = value
	return nil
}
