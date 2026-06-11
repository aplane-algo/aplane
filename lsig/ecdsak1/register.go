// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package ecdsak1 is the ECDSA secp256k1 LogicSig DSA family.
//
// Registration here is client-safe metadata/derivation only. Signer-side
// keygen/signing/mnemonic handlers are registered by lsig/ecdsak1/signerreg.
package ecdsak1

import (
	"sync"

	"github.com/aplane-algo/aplane/lsig/dsafamily"
	"github.com/aplane-algo/aplane/lsig/ecdsak1/family"
	v1 "github.com/aplane-algo/aplane/lsig/ecdsak1/v1"
	falconkeys "github.com/aplane-algo/aplane/lsig/falcon1024/keys"
)

// Package-level identifiers exposed for lsig/all.go and downstream callers.
const (
	FamilyName    = family.Name
	KeyTypeV1     = "aplane.ecdsak1.v1"
	SignatureSize = family.MaxSignatureSize
)

type metadata struct{}

func (metadata) Family() string               { return FamilyName }
func (metadata) CryptoSignatureSize() int     { return SignatureSize }
func (metadata) MnemonicWordCount() int       { return family.MnemonicWordCount }
func (metadata) SupportsMnemonicImport() bool { return false }
func (metadata) MnemonicScheme() string       { return family.MnemonicScheme }
func (metadata) RequiresLogicSig() bool       { return true }
func (metadata) CurrentLsigVersion() int      { return 1 }
func (metadata) SupportedLsigVersions() []int { return []int{1} }
func (metadata) DefaultDerivation() string    { return "bip39-standard" }
func (metadata) DisplayColor() string         { return family.DisplayColor }

var (
	registerClientOnce sync.Once
)

// RegisterClient wires client-safe ecdsak1 metadata and derivation. Idempotent.
func RegisterClient() {
	registerClientOnce.Do(func() {
		dsafamily.RegisterClient(dsafamily.ClientRegistration{
			Family:   FamilyName,
			Metadata: metadata{},
			KeyTypes: []dsafamily.KeyType{{
				KeyType:        KeyTypeV1,
				DSA:            &v1.ECDSAK1V1{},
				AddressDeriver: falconkeys.GetFalconAddressDeriverForType(KeyTypeV1),
			}},
		})
	})
}
