// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package appinput

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// ProgramSource describes an application program path parsed from user input.
type ProgramSource struct {
	Path     string
	Compiled bool
}

// unknownPrefixRE matches a value that opens with a word and a colon, the
// shape of a prefix. A bare value of that shape is refused: `int:5` read as
// seven text bytes is a different number once a program converts it.
var unknownPrefixRE = regexp.MustCompile(`^[A-Za-z0-9]+:`)

// ParseByteValue parses a byte-oriented value token.
// Supported forms:
// - hex:...
// - b64:...
// - text:... or str:... (UTF-8 text)
// - int:... (a decimal uint64, as 8 big-endian bytes)
// - addr:... (an Algorand address, as its 32-byte public key)
// - 0x... (hex compatibility form)
// - bare text otherwise, unless it opens with some other word and a colon
//
// This is the shared semantic grammar for byte values; UI layers (cmdspec)
// consume it from here so engine-layer code never depends on UI parsing.
func ParseByteValue(raw string) ([]byte, error) {
	switch {
	case strings.HasPrefix(raw, "hex:"):
		value, err := hex.DecodeString(strings.TrimSpace(strings.TrimPrefix(raw, "hex:")))
		if err != nil {
			return nil, fmt.Errorf("invalid hex value: %w", err)
		}
		return value, nil
	case strings.HasPrefix(raw, "b64:"):
		value, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(raw, "b64:")))
		if err != nil {
			return nil, fmt.Errorf("invalid base64 value: %w", err)
		}
		return value, nil
	case strings.HasPrefix(raw, "text:"):
		return []byte(strings.TrimPrefix(raw, "text:")), nil
	case strings.HasPrefix(raw, "str:"):
		return []byte(strings.TrimPrefix(raw, "str:")), nil
	case strings.HasPrefix(raw, "int:"):
		number, err := strconv.ParseUint(strings.TrimPrefix(raw, "int:"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid int value: %w", err)
		}
		return binary.BigEndian.AppendUint64(nil, number), nil
	case strings.HasPrefix(raw, "addr:"):
		address, err := types.DecodeAddress(strings.TrimPrefix(raw, "addr:"))
		if err != nil {
			return nil, fmt.Errorf("invalid addr value: %w", err)
		}
		return address[:], nil
	case strings.HasPrefix(raw, "0x"):
		value, err := hex.DecodeString(raw[2:])
		if err != nil {
			return nil, fmt.Errorf("invalid hex value: %w", err)
		}
		return value, nil
	case unknownPrefixRE.MatchString(raw):
		prefix := raw[:strings.Index(raw, ":")+1]
		return nil, fmt.Errorf(
			"unknown value prefix %q (supported: hex:, b64:, text:, str:, int:, addr:); use text:%s for literal text",
			prefix, raw)
	default:
		return []byte(raw), nil
	}
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
