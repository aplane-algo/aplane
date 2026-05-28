// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package appinput

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/cmdspec"
)

// ProgramSource describes an application program path parsed from user input.
type ProgramSource struct {
	Path     string
	Compiled bool
}

// ParseByteValue parses string inputs with hex:/b64:/text: prefixes.
func ParseByteValue(raw string) ([]byte, error) {
	return cmdspec.ParseByteValue(raw, true)
}

// ParseOnCompletion parses supported application on-completion values.
func ParseOnCompletion(raw string) (types.OnCompletion, error) {
	switch strings.ToLower(raw) {
	case "", "noop", "no-op":
		return types.NoOpOC, nil
	case "optin", "opt-in":
		return types.OptInOC, nil
	case "closeout", "close-out":
		return types.CloseOutOC, nil
	case "clear", "clearstate", "clear-state":
		return types.ClearStateOC, nil
	case "update":
		return types.UpdateApplicationOC, nil
	case "delete":
		return types.DeleteApplicationOC, nil
	default:
		return 0, fmt.Errorf("unsupported oncomp value %q (supported: noop, optin, closeout, clear, update, delete)", raw)
	}
}

// DetectProgramSource infers whether the file is TEAL source or compiled bytes.
// `.teal` files are treated as source; everything else defaults to compiled bytes.
func DetectProgramSource(path string) ProgramSource {
	return ProgramSource{
		Path:     path,
		Compiled: !strings.EqualFold(filepath.Ext(path), ".teal"),
	}
}
