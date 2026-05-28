// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/cmdspec"
)

// extractPluginLsigArgs separates arg: tokens from plugin command args.
func extractPluginLsigArgs(args []string) ([]string, map[string][]byte, error) {
	var cleanArgs []string
	var lsigArgs map[string][]byte
	for _, a := range args {
		if strings.HasPrefix(a, "arg:") {
			name, value, err := cmdspec.ParseLsigArg(a)
			if err != nil {
				return nil, nil, err
			}
			if lsigArgs == nil {
				lsigArgs = make(map[string][]byte)
			}
			lsigArgs[name] = value
		} else {
			cleanArgs = append(cleanArgs, a)
		}
	}
	return cleanArgs, lsigArgs, nil
}
