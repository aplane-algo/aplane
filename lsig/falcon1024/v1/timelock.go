// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package v1

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falcontimelock "github.com/aplane-algo/aplane/lsig/falcon1024/v1/timelock"
)

// FalconTimelockV1 implements a hybrid LogicSig that enforces a timelock
// and verifies a Falcon-1024 signature.
type FalconTimelockV1 struct {
	family.FalconCore
}

// KeyType returns the full identifier including version.
func (f *FalconTimelockV1) KeyType() string {
	return "falcon1024-timelock-v1"
}

// Family returns the algorithm family without version.
// Returns "falcon1024" since the timelock variant uses the same cryptographic primitive.
func (f *FalconTimelockV1) Family() string {
	return family.Name
}

// Version returns the derivation version number.
func (f *FalconTimelockV1) Version() int {
	return 1
}

// Category returns the LSig category for Falcon-1024 timelock.
func (f *FalconTimelockV1) Category() string {
	return lsigprovider.CategoryDSALsig
}

// DisplayName returns the human-readable name.
func (f *FalconTimelockV1) DisplayName() string {
	return "Falcon-1024 Timelock"
}

// Description returns a short description for UI display.
func (f *FalconTimelockV1) Description() string {
	return "Falcon-1024 signature with round-based timelock (funds locked until specified round)"
}

// CreationParams returns parameter definitions for LSig creation.
func (f *FalconTimelockV1) CreationParams() []lsigprovider.ParameterDef {
	return []lsigprovider.ParameterDef{
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

// ValidateCreationParams validates the provided creation parameters.
func (f *FalconTimelockV1) ValidateCreationParams(params map[string]string) error {
	unlockRoundStr, ok := params["unlock_round"]
	if !ok || unlockRoundStr == "" {
		return fmt.Errorf("missing required parameter: unlock_round")
	}
	if _, err := strconv.ParseUint(unlockRoundStr, 10, 64); err != nil {
		return fmt.Errorf("invalid unlock_round: %w", err)
	}

	return nil
}

// RuntimeArgs returns argument definitions needed at transaction signing time.
func (f *FalconTimelockV1) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return nil
}

// BuildArgs assembles the LogicSig Args array.
// For Falcon-Timelock, args are: [signature] (no runtime args).
func (f *FalconTimelockV1) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	if signature == nil {
		return nil, fmt.Errorf("signature is required for DSA LogicSig")
	}
	return [][]byte{signature}, nil
}

// DeriveLsig derives the LogicSig bytecode and address from a Falcon public key.
// The params map must include timelock parameters such as unlock_round and recipient.
func (f *FalconTimelockV1) DeriveLsig(publicKey []byte, params map[string]string) ([]byte, string, error) {
	if err := f.ValidateCreationParams(params); err != nil {
		return nil, "", err
	}

	unlockRound, err := strconv.ParseUint(params["unlock_round"], 10, 64)
	if err != nil {
		return nil, "", fmt.Errorf("invalid unlock_round: %w", err)
	}

	return falcontimelock.DeriveLsig(publicKey, unlockRound)
}

// Compile-time interface checks.
var (
	_ logicsigdsa.LogicSigDSA       = (*FalconTimelockV1)(nil)
	_ lsigprovider.LSigProvider     = (*FalconTimelockV1)(nil)
	_ lsigprovider.SigningProvider  = (*FalconTimelockV1)(nil)
	_ lsigprovider.MnemonicProvider = (*FalconTimelockV1)(nil)
)

var registerFalconTimelockOnce sync.Once

// RegisterFalconTimelockV1 registers FalconTimelockV1 with the logicsigdsa registry.
// This is idempotent and safe to call multiple times.
func RegisterFalconTimelockV1() {
	registerFalconTimelockOnce.Do(func() {
		logicsigdsa.Register(&FalconTimelockV1{})
	})
}
