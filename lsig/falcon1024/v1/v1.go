// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package v1

import (
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// Falcon1024V1 implements LogicSigDSA for Falcon-1024 with version 1 derivation.
//
// This is the canonical Falcon-1024 implementation using the ComposedDSA architecture
// with zero constraints. It uses runtime TEAL compilation via algod for maximum safety.
//
// An algod client must be configured (via SetAlgodClient or server startup) before
// calling DeriveLsig.
type Falcon1024V1 struct {
	family.FalconCore
	algodClient *algod.Client
}

// SetAlgodClient sets the algod client for runtime TEAL compilation.
// This must be called before DeriveLsig (typically done automatically at server startup).
func (f *Falcon1024V1) SetAlgodClient(client *algod.Client) {
	f.algodClient = client
}

// KeyType returns the full identifier including version.
func (f *Falcon1024V1) KeyType() string {
	return "falcon1024-v1"
}

// Family returns the algorithm family without version.
func (f *Falcon1024V1) Family() string {
	return family.Name
}

// Version returns the derivation version number.
func (f *Falcon1024V1) Version() int {
	return 1
}

// DeriveLsig derives the LogicSig bytecode and address from a Falcon public key.
//
// This uses runtime TEAL compilation through the ComposedDSA system, which
// validates the entire program structure for maximum safety.
//
// Requires SetAlgodClient to be called first (typically done at server startup).
func (f *Falcon1024V1) DeriveLsig(publicKey []byte, params map[string]string) (lsigBytecode []byte, address string, err error) {
	_ = params // Pure Falcon ignores params
	if len(publicKey) != family.PublicKeySize {
		return nil, "", fmt.Errorf("invalid public key size: expected %d, got %d",
			family.PublicKeySize, len(publicKey))
	}

	if f.algodClient == nil {
		return nil, "", fmt.Errorf("algod client not set: configure teal_compiler_algod_url in config.yaml")
	}

	// Use the composed derivation with zero constraints
	comp := newFalconV1Composed()
	comp.SetAlgodClient(f.algodClient)
	return comp.DeriveLsig(publicKey, nil)
}

// newFalconV1Composed creates a ComposedDSA with no TEAL suffix that produces
// bytecode identical to the standard falcon1024-v1 precompiled derivation.
//
// This is the canonical Falcon-1024 implementation as a ComposedDSA.
// With no suffix, the generated TEAL is:
//
//	#pragma version 12
//	bytecblock 0x00
//	txn TxID
//	arg 0
//	byte 0x<pubkey>
//	falcon_verify
//
// Which compiles to identical bytecode as the precompiled v1 template.
func newFalconV1Composed() *ComposedDSA {
	return NewComposedDSA(ComposedDSAConfig{
		KeyType:     "falcon1024-v1",
		FamilyName:  family.Name,
		Version:     1,
		DisplayName: "Falcon-1024",
		Description: "Post-quantum signature scheme using Falcon-1024 lattice-based cryptography",
		Base:        family.FalconBase,
		// No TEALSuffix, no Params, no RuntimeArgs = pure Falcon-1024
	})
}

// GenerateTEAL generates the TEAL source for this Falcon-1024 LogicSig.
// This delegates to the ComposedDSA architecture to produce the canonical TEAL.
func (f *Falcon1024V1) GenerateTEAL(publicKey []byte, params map[string]string) (string, error) {
	comp := newFalconV1Composed()
	return comp.GenerateTEAL(publicKey, nil)
}

// Category returns the LSig category for Falcon-1024.
func (f *Falcon1024V1) Category() string {
	return lsigprovider.CategoryDSALsig
}

// DisplayName returns the human-readable name.
func (f *Falcon1024V1) DisplayName() string {
	return "Falcon-1024"
}

// Description returns a short description for UI display.
func (f *Falcon1024V1) Description() string {
	return "Post-quantum signature scheme using Falcon-1024 lattice-based cryptography"
}

// CreationParams returns parameter definitions for LSig creation.
// Pure Falcon has no creation parameters (public key is the only input).
func (f *Falcon1024V1) CreationParams() []lsigprovider.ParameterDef {
	return nil
}

// ValidateCreationParams validates creation parameters.
// Pure Falcon has no parameters, so this always succeeds.
func (f *Falcon1024V1) ValidateCreationParams(params map[string]string) error {
	return nil
}

// RuntimeArgs returns argument definitions needed at transaction signing time.
// Falcon signatures are generated automatically, so no runtime args are needed.
func (f *Falcon1024V1) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return nil
}

// BuildArgs assembles the LogicSig Args array.
// For pure Falcon-1024, args are: [signature].
func (f *Falcon1024V1) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	if signature == nil {
		return nil, fmt.Errorf("signature is required for DSA LogicSig")
	}
	return [][]byte{signature}, nil
}

// Compile-time interface checks
var (
	_ logicsigdsa.LogicSigDSA       = (*Falcon1024V1)(nil)
	_ logicsigdsa.TEALGenerator     = (*Falcon1024V1)(nil)
	_ lsigprovider.LSigProvider     = (*Falcon1024V1)(nil)
	_ lsigprovider.SigningProvider  = (*Falcon1024V1)(nil)
	_ lsigprovider.MnemonicProvider = (*Falcon1024V1)(nil)
)

var registerLogicSigDSAOnce sync.Once

// RegisterLogicSigDSA registers Falcon1024V1 with the logicsigdsa registry.
// This is idempotent and safe to call multiple times.
func RegisterLogicSigDSA() {
	registerLogicSigDSAOnce.Do(func() {
		logicsigdsa.Register(&Falcon1024V1{})
	})
}
