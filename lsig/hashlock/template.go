// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package hashlock provides a hashlock LogicSig template for trustless atomic swaps.
//
// A hashlock locks funds until someone provides a secret preimage that hashes to
// a known hash value. This enables trustless atomic swaps between parties:
//
//  1. Alice creates a secret preimage and shares only its SHA256 hash with Bob
//  2. Both Alice and Bob create hashlock LogicSigs using the same hash
//  3. When Alice claims Bob's funds (revealing the preimage on-chain),
//     Bob can use that preimage to claim Alice's funds
//
// The hashlock has two spending paths:
//   - Claim path: recipient provides the correct preimage (arg 0)
//   - Refund path: refund_address reclaims after timeout_round
package hashlock

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

const (
	family     = "hashlock"
	versionV1  = "hashlock-v1"
	versionPfx = "hashlock-v"
)

// Compile-time check that HashlockTemplate implements Template
var _ genericlsig.Template = (*HashlockTemplate)(nil)

// HashlockTemplate implements a hashlock LogicSig for atomic swaps
type HashlockTemplate struct{}

// Identity methods
func (t *HashlockTemplate) KeyType() string { return versionV1 }
func (t *HashlockTemplate) Family() string  { return family }
func (t *HashlockTemplate) Version() int    { return 1 }

// Display methods
func (t *HashlockTemplate) DisplayName() string { return "Hashlock" }
func (t *HashlockTemplate) Description() string {
	return "Lock funds (ALGO or ASA) until preimage is revealed (for atomic swaps)"
}
func (t *HashlockTemplate) DisplayColor() string { return "36" } // Cyan

// Category returns the LSig category (generic_lsig for templates).
func (t *HashlockTemplate) Category() string { return lsigprovider.CategoryGenericLsig }

// RuntimeArgs returns the arguments required at transaction signing time.
// For hashlock, the claimant must provide the preimage.
func (t *HashlockTemplate) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return []lsigprovider.RuntimeArgDef{
		{
			Name:        "preimage",
			Label:       "Secret Preimage",
			Description: "The 32-byte secret that hashes to the stored hash (hex-encoded)",
			Type:        "bytes",
			Required:    false, // Not required for refund path
			ByteLength:  32,
		},
	}
}

// BuildArgs assembles the LogicSig Args array.
// For hashlock, args are ordered according to RuntimeArgs(): [preimage].
func (t *HashlockTemplate) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	// Generic templates ignore signature (they don't use crypto signatures)
	var args [][]byte
	for _, argDef := range t.RuntimeArgs() {
		if val, ok := runtimeArgs[argDef.Name]; ok {
			args = append(args, val)
		} else if argDef.Required {
			return nil, fmt.Errorf("missing required arg: %s", argDef.Name)
		}
	}
	return args, nil
}

// CreationParams returns the parameter definitions for hashlock
func (t *HashlockTemplate) CreationParams() []lsigprovider.ParameterDef {
	return []lsigprovider.ParameterDef{
		{
			Name:        "hash",
			Label:       "Hash (SHA256)",
			Description: "SHA256 hash of the secret preimage (64 hex characters)",
			Type:        "bytes",
			Required:    true,
			MaxLength:   64, // 32 bytes = 64 hex chars
			InputModes: []lsigprovider.InputMode{
				{
					Name:       "hash",
					Label:      "SHA256 Hash (hex)",
					Transform:  "",
					ByteLength: 32,
				},
				{
					Name:      "preimage",
					Label:     "Preimage (text, will be hashed)",
					Transform: "sha256",
					InputType: "string",
				},
			},
		},
		{
			Name:        "recipient",
			Label:       "Recipient Address",
			Description: "Address that can claim funds by providing the preimage",
			Type:        "address",
			Required:    true,
		},
		{
			Name:        "refund_address",
			Label:       "Refund Address",
			Description: "Address that can reclaim funds after timeout",
			Type:        "address",
			Required:    true,
		},
		{
			Name:        "timeout_round",
			Label:       "Timeout Round",
			Description: "Block round after which refund is allowed",
			Type:        "uint64",
			Required:    true,
		},
	}
}

// ValidateCreationParams validates the hashlock parameters
func (t *HashlockTemplate) ValidateCreationParams(params map[string]string) error {
	// Validate hash
	hashHex, ok := params["hash"]
	if !ok || hashHex == "" {
		return fmt.Errorf("hash is required")
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return fmt.Errorf("invalid hash hex: %w", err)
	}
	if len(hashBytes) != 32 {
		return fmt.Errorf("hash must be 32 bytes (64 hex chars), got %d bytes", len(hashBytes))
	}

	// Validate recipient address
	recipient, ok := params["recipient"]
	if !ok || recipient == "" {
		return fmt.Errorf("recipient is required")
	}
	if _, err := types.DecodeAddress(recipient); err != nil {
		return fmt.Errorf("invalid recipient address: %w", err)
	}

	// Validate refund address
	refundAddr, ok := params["refund_address"]
	if !ok || refundAddr == "" {
		return fmt.Errorf("refund_address is required")
	}
	if _, err := types.DecodeAddress(refundAddr); err != nil {
		return fmt.Errorf("invalid refund_address: %w", err)
	}

	// Validate timeout round
	timeoutStr, ok := params["timeout_round"]
	if !ok || timeoutStr == "" {
		return fmt.Errorf("timeout_round is required")
	}
	timeout, err := strconv.ParseUint(timeoutStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timeout_round: %w", err)
	}
	if timeout == 0 {
		return fmt.Errorf("timeout_round must be greater than 0")
	}

	return nil
}

// GenerateTEAL generates the TEAL source code for the hashlock
func (t *HashlockTemplate) GenerateTEAL(params map[string]string) (string, error) {
	if err := t.ValidateCreationParams(params); err != nil {
		return "", err
	}

	hashHex := params["hash"]
	recipient := params["recipient"]
	refundAddr := params["refund_address"]
	timeoutRound := params["timeout_round"]

	// Build TEAL program
	// Note: Using arg 0 for LogicSig arguments (not ApplicationArgs)
	// Logic: Check timeout first - if past timeout, allow refund path.
	// Otherwise, require valid preimage for claim path.
	// Supports both ALGO payments (pay) and ASA transfers (axfer).
	teal := `#pragma version 10

// Hashlock LogicSig - Two spending paths:
// 1. Claim: recipient provides correct preimage as arg 0 (before timeout)
// 2. Refund: refund_address reclaims after timeout (no arg needed)
// Supports both ALGO payments (pay) and ASA transfers (axfer).

// Security: Prevent rekey attacks
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

// Check if timeout has passed - if so, allow refund path
txn FirstValid
int ` + timeoutRound + `
>=
bnz refund_path

// === CLAIM PATH (before timeout) ===
// Verify SHA256(preimage) == stored hash
// Note: If no arg provided, this will fail (arg 0 doesn't exist)
arg 0
sha256
byte 0x` + hashHex + `
==
assert

// Branch on transaction type for field checks
txn TypeEnum
int pay
==
bnz claim_pay

// --- claim: asset transfer ---
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

// --- claim: payment ---
claim_pay:
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

// === REFUND PATH (after timeout) ===
refund_path:
    // Branch on transaction type for field checks
    txn TypeEnum
    int pay
    ==
    bnz refund_pay

    // --- refund: asset transfer ---
    txn AssetSender
    global ZeroAddress
    ==
    assert

    txn AssetReceiver
    addr ` + refundAddr + `
    ==
    assert

    txn AssetCloseTo
    addr ` + refundAddr + `
    ==
    txn AssetCloseTo
    global ZeroAddress
    ==
    ||
    assert

    int 1
    return

    // --- refund: payment ---
    refund_pay:
        txn Receiver
        addr ` + refundAddr + `
        ==
        assert

        txn CloseRemainderTo
        addr ` + refundAddr + `
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

// Compile compiles the hashlock LogicSig and returns bytecode and address
func (t *HashlockTemplate) Compile(params map[string]string, algodClient *algod.Client) ([]byte, string, error) {
	teal, err := t.GenerateTEAL(params)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate TEAL: %w", err)
	}

	// Compile TEAL to bytecode
	result, err := algodClient.TealCompile([]byte(teal)).Do(context.Background())
	if err != nil {
		return nil, "", fmt.Errorf("TEAL compilation failed: %w", err)
	}

	bytecode, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode compiled bytecode: %w", err)
	}

	// result.Hash is the program address (SHA512/256 of bytecode)
	return bytecode, result.Hash, nil
}

var registerTemplateOnce sync.Once

// RegisterTemplate registers the hashlock template with the genericlsig registry.
// This is idempotent and safe to call multiple times.
func RegisterTemplate() {
	registerTemplateOnce.Do(func() {
		genericlsig.Register(&HashlockTemplate{})
	})
}
