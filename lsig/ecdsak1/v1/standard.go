// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"context"
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/lsig/ecdsak1/family"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// ECDSAK1V1 is the canonical secp256k1-based LogicSig DSA provider.
type ECDSAK1V1 struct {
	family.ECDSAK1Core
	algodClient *algod.Client
	algodMu     sync.RWMutex
}

// SetAlgodClient sets the algod client for runtime TEAL compilation.
func (e *ECDSAK1V1) SetAlgodClient(client *algod.Client) {
	e.algodMu.Lock()
	defer e.algodMu.Unlock()
	e.algodClient = client
}

func (e *ECDSAK1V1) KeyType() string {
	return "aplane.ecdsak1.v1"
}

func (e *ECDSAK1V1) RoutingFamily() string {
	return family.Name
}

func (e *ECDSAK1V1) Version() int {
	return 1
}

// DeriveLsig derives LogicSig bytecode and address from public key.
func (e *ECDSAK1V1) DeriveLsig(ctx context.Context, publicKey []byte, params map[string]string) (lsigBytecode []byte, address string, err error) {
	_ = params // Standard provider ignores creation params.

	if len(publicKey) != family.PublicKeySize {
		return nil, "", fmt.Errorf("invalid public key size: expected %d, got %d", family.PublicKeySize, len(publicKey))
	}

	e.algodMu.RLock()
	client := e.algodClient
	e.algodMu.RUnlock()
	if client == nil {
		return nil, "", fmt.Errorf("algod client not set: configure algod.<network>.server in config.yaml")
	}

	comp := newECDSAK1V1Composed()
	comp.SetAlgodClient(client)
	return comp.DeriveLsig(ctx, publicKey, nil)
}

// DeriveLsigWithSalt derives the LogicSig bytecode, address, and salt counter
// used to keep the resulting LogicSig address off-curve.
func (e *ECDSAK1V1) DeriveLsigWithSalt(ctx context.Context, publicKey []byte, params map[string]string) (lsigsalt.FindResult, error) {
	_ = params // Standard provider ignores creation params.

	if len(publicKey) != family.PublicKeySize {
		return lsigsalt.FindResult{}, fmt.Errorf("invalid public key size: expected %d, got %d", family.PublicKeySize, len(publicKey))
	}

	e.algodMu.RLock()
	client := e.algodClient
	e.algodMu.RUnlock()
	if client == nil {
		return lsigsalt.FindResult{}, fmt.Errorf("algod client not set: configure algod.<network>.server in config.yaml")
	}

	comp := newECDSAK1V1Composed()
	comp.SetAlgodClient(client)
	return comp.DeriveLsigWithSalt(ctx, publicKey, nil)
}

func newECDSAK1V1Composed() *ComposedECDSA {
	return NewComposedECDSA(ComposedECDSAConfig{
		KeyType:     "aplane.ecdsak1.v1",
		FamilyName:  family.Name,
		Version:     1,
		DisplayName: "ECDSA secp256k1",
		Description: "ECDSA secp256k1 signature scheme",
		Base:        family.ECDSAK1Base,
		SaltStyle:   lsigsalt.StyleBytecblock,
	})
}

// GenerateTEAL generates the TEAL source for this provider.
func (e *ECDSAK1V1) GenerateTEAL(publicKey []byte, params map[string]string) (string, error) {
	comp := newECDSAK1V1Composed()
	return comp.GenerateTEAL(publicKey, nil)
}

func (e *ECDSAK1V1) Category() string {
	return lsigprovider.CategoryDSALsig
}

func (e *ECDSAK1V1) DisplayName() string {
	return "ECDSA secp256k1"
}

func (e *ECDSAK1V1) Description() string {
	return "ECDSA secp256k1 signature scheme"
}

func (e *ECDSAK1V1) CreationParams() []lsigprovider.ParameterDef {
	return nil
}

func (e *ECDSAK1V1) ValidateCreationParams(params map[string]string) error {
	return nil
}

func (e *ECDSAK1V1) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return nil
}

func (e *ECDSAK1V1) SupportsMnemonicImport() bool {
	return false
}

// BuildArgs assembles LogicSig args as [r, s] for standard ecdsak1.
func (e *ECDSAK1V1) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	comp := newECDSAK1V1Composed()
	return comp.BuildArgs(signature, runtimeArgs)
}

// Compile-time interface checks.
var (
	_ logicsigdsa.LogicSigDSA       = (*ECDSAK1V1)(nil)
	_ logicsigdsa.TEALGenerator     = (*ECDSAK1V1)(nil)
	_ logicsigdsa.SaltedDeriver     = (*ECDSAK1V1)(nil)
	_ lsigprovider.LSigProvider     = (*ECDSAK1V1)(nil)
	_ lsigprovider.SigningProvider  = (*ECDSAK1V1)(nil)
	_ lsigprovider.MnemonicProvider = (*ECDSAK1V1)(nil)
)

var registerLogicSigDSAOnce sync.Once

// RegisterLogicSigDSA registers ECDSAK1V1 with the logicsigdsa registry.
func RegisterLogicSigDSA() {
	registerLogicSigDSAOnce.Do(func() {
		logicsigdsa.Register(&ECDSAK1V1{})
	})
}
