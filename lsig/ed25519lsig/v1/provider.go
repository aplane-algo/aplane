// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"context"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig/family"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

type Ed25519LsigV1 struct {
	inner *composeddsa.ComposedDSA
}

func NewProvider() *Ed25519LsigV1 {
	return &Ed25519LsigV1{inner: newComposed()}
}

func newComposed() *composeddsa.ComposedDSA {
	return composeddsa.NewComposedDSA(composeddsa.Config{
		KeyType:     family.KeyTypeV1,
		BaseKeyType: family.KeyTypeV1,
		FamilyName:  family.Name,
		Version:     1,
		DisplayName: "Ed25519 LogicSig",
		Description: "Ed25519 signature scheme verified inside a LogicSig",
		Ops:         NewOps(),
		SaltStyle:   lsigsalt.StyleAlgodAutoSalt,
	})
}

func (p *Ed25519LsigV1) ensureInner() *composeddsa.ComposedDSA {
	if p.inner == nil {
		p.inner = newComposed()
	}
	return p.inner
}

func (p *Ed25519LsigV1) SetAlgodClient(client *algod.Client) {
	p.ensureInner().SetAlgodClient(client)
}

func (p *Ed25519LsigV1) KeyType() string { return family.KeyTypeV1 }
func (p *Ed25519LsigV1) BaseKeyType() string {
	return family.KeyTypeV1
}
func (p *Ed25519LsigV1) RoutingFamily() string { return family.Name }
func (p *Ed25519LsigV1) Version() int          { return 1 }
func (p *Ed25519LsigV1) Category() string      { return lsigprovider.CategoryDSALsig }
func (p *Ed25519LsigV1) DisplayName() string   { return "Ed25519 LogicSig" }
func (p *Ed25519LsigV1) Description() string {
	return "Ed25519 signature scheme verified inside a LogicSig"
}
func (p *Ed25519LsigV1) DisplayColor() string                        { return family.DisplayColor }
func (p *Ed25519LsigV1) CryptoSignatureSize() int                    { return family.MaxSignatureSize }
func (p *Ed25519LsigV1) MnemonicScheme() string                      { return family.MnemonicScheme }
func (p *Ed25519LsigV1) MnemonicWordCount() int                      { return family.MnemonicWordCount }
func (p *Ed25519LsigV1) SupportsMnemonicImport() bool                { return true }
func (p *Ed25519LsigV1) CreationParams() []lsigprovider.ParameterDef { return nil }
func (p *Ed25519LsigV1) ValidateCreationParams(map[string]string) error {
	return nil
}
func (p *Ed25519LsigV1) RuntimeArgs() []lsigprovider.RuntimeArgDef { return nil }

func (p *Ed25519LsigV1) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	return p.ensureInner().BuildArgs(signature, runtimeArgs)
}

func (p *Ed25519LsigV1) GenerateTEAL(publicKey []byte, params map[string]string) (string, error) {
	return p.ensureInner().GenerateTEAL(publicKey, params)
}

func (p *Ed25519LsigV1) DeriveLsig(ctx context.Context, publicKey []byte, params map[string]string) ([]byte, string, error) {
	return p.ensureInner().DeriveLsig(ctx, publicKey, params)
}

func (p *Ed25519LsigV1) DeriveLsigWithSalt(ctx context.Context, publicKey []byte, params map[string]string) (lsigsalt.FindResult, error) {
	return p.ensureInner().DeriveLsigWithSalt(ctx, publicKey, params)
}

var (
	_ logicsigdsa.LogicSigDSA        = (*Ed25519LsigV1)(nil)
	_ logicsigdsa.TEALGenerator      = (*Ed25519LsigV1)(nil)
	_ logicsigdsa.SaltedDeriver      = (*Ed25519LsigV1)(nil)
	_ lsigprovider.LSigProvider      = (*Ed25519LsigV1)(nil)
	_ lsigprovider.SigningProvider   = (*Ed25519LsigV1)(nil)
	_ lsigprovider.MnemonicProvider  = (*Ed25519LsigV1)(nil)
	_ lsigprovider.AlgodConfigurable = (*Ed25519LsigV1)(nil)
)
