// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package timelock provides a generic LogicSig template for time-locked funds.
// Funds can only be sent to a specific recipient address after a certain round.
//
// To use this template, import it in lsig/all.go:
//
//	import _ "github.com/aplane-algo/aplane/lsig/timelock"
package timelock

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/lsigprovider"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// Family and version constants
const (
	family     = "timelock"
	versionV1  = "timelock-v1"
	versionPfx = "timelock-v"
)

// TimelockTemplate implements genericlsig.Template for timelock LogicSigs
type TimelockTemplate struct{}

// Compile-time check that TimelockTemplate implements Template
var _ genericlsig.Template = (*TimelockTemplate)(nil)

// Identity methods
func (t *TimelockTemplate) KeyType() string { return versionV1 }
func (t *TimelockTemplate) Family() string  { return family }
func (t *TimelockTemplate) Version() int    { return 1 }

// Display methods
func (t *TimelockTemplate) DisplayName() string { return "Timelock" }
func (t *TimelockTemplate) Description() string {
	return "Restrict funds (ALGO or ASA) to recipient after specified round"
}
func (t *TimelockTemplate) DisplayColor() string { return "35" } // Magenta

// Category returns the LSig category (generic_lsig for templates).
func (t *TimelockTemplate) Category() string { return lsigprovider.CategoryGenericLsig }

// RuntimeArgs returns the runtime arguments needed at signing time.
// Timelock doesn't require any runtime arguments - it only checks transaction fields.
func (t *TimelockTemplate) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return nil
}

// BuildArgs assembles the LogicSig Args array.
// Timelock has no runtime args, so this returns an empty slice.
func (t *TimelockTemplate) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	// Generic templates ignore signature (they don't use crypto signatures)
	// Timelock has no runtime args
	return nil, nil
}

// CreationParams returns the parameter definitions for timelock
func (t *TimelockTemplate) CreationParams() []lsigprovider.ParameterDef {
	return []lsigprovider.ParameterDef{
		{
			Name:        "recipient",
			Label:       "Recipient Address",
			Description: "Algorand address that can receive funds after unlock",
			Type:        "address",
			Required:    true,
			MaxLength:   58,
		},
		{
			Name:        "unlock_round",
			Label:       "Unlock Round",
			Description: "Round number after which funds can be withdrawn",
			Type:        "uint64",
			Required:    true,
			MaxLength:   20,
		},
	}
}

// ValidateCreationParams validates the provided parameters
func (t *TimelockTemplate) ValidateCreationParams(params map[string]string) error {
	recipient, ok := params["recipient"]
	if !ok || recipient == "" {
		return fmt.Errorf("missing required parameter: recipient")
	}
	if len(recipient) != 58 {
		return fmt.Errorf("invalid recipient address length: expected 58, got %d", len(recipient))
	}

	unlockRoundStr, ok := params["unlock_round"]
	if !ok || unlockRoundStr == "" {
		return fmt.Errorf("missing required parameter: unlock_round")
	}
	if _, err := strconv.ParseUint(unlockRoundStr, 10, 64); err != nil {
		return fmt.Errorf("invalid unlock_round: %w", err)
	}

	return nil
}

// GenerateTEAL generates the TEAL source code for a timelock LogicSig
func (t *TimelockTemplate) GenerateTEAL(params map[string]string) (string, error) {
	if err := t.ValidateCreationParams(params); err != nil {
		return "", err
	}

	unlockRound := params["unlock_round"]
	recipient := params["recipient"]

	teal := `#pragma version 10

// Timelock: funds (ALGO or ASA) locked until round ` + unlockRound + `, then only to ` + recipient + `

// Check 1: Transaction first valid round >= unlock round
// (Transaction cannot be submitted until network reaches this round)
txn FirstValid
int ` + unlockRound + `
>=
assert

// Security: Prevent RekeyTo takeover
txn RekeyTo
global ZeroAddress
==
assert

// Allow ASA opt-in: 0-amount axfer to self, no close, no clawback
txn TypeEnum
int axfer
==
txn AssetAmount
int 0
==
&&
txn AssetReceiver
txn Sender
==
&&
txn AssetCloseTo
global ZeroAddress
==
&&
txn AssetSender
global ZeroAddress
==
&&
bnz allow

// Check transaction type is payment or asset transfer
txn TypeEnum
int pay
==
txn TypeEnum
int axfer
==
||
assert

// Branch on transaction type for field checks
txn TypeEnum
int pay
==
bnz pay_path

// --- asset transfer path ---
txn AssetSender
global ZeroAddress
==
assert

txn AssetReceiver
addr ` + recipient + `
==
assert

txn AssetCloseTo
addr ` + recipient + `
==
txn AssetCloseTo
global ZeroAddress
==
||
assert

int 1
return

// --- payment path ---
pay_path:
    txn Receiver
    addr ` + recipient + `
    ==
    assert

    txn CloseRemainderTo
    addr ` + recipient + `
    ==
    txn CloseRemainderTo
    global ZeroAddress
    ==
    ||
    assert

    int 1
    return

// === ASA OPT-IN (approved above) ===
allow:
    int 1
    return
`

	return strings.TrimSpace(teal), nil
}

// Compile compiles the timelock TEAL and returns bytecode and address
func (t *TimelockTemplate) Compile(params map[string]string, algodClient *algod.Client) ([]byte, string, error) {
	tealSource, err := t.GenerateTEAL(params)
	if err != nil {
		return nil, "", err
	}

	result, err := algodClient.TealCompile([]byte(tealSource)).Do(context.Background())
	if err != nil {
		return nil, "", fmt.Errorf("TEAL compilation failed: %w", err)
	}

	bytecode, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode bytecode: %w", err)
	}

	// result.Hash is the program address (SHA512/256 of bytecode)
	return bytecode, result.Hash, nil
}

var registerTemplateOnce sync.Once

// RegisterTemplate registers the timelock template with the genericlsig registry.
// This is idempotent and safe to call multiple times.
func RegisterTemplate() {
	registerTemplateOnce.Do(func() {
		genericlsig.Register(&TimelockTemplate{})
	})
}
