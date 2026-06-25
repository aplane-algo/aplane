// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package ed25519lsig registers the hidden Ed25519 LogicSig DSA family.
package ed25519lsig

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/dsafamily"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig/family"
	ed25519keys "github.com/aplane-algo/aplane/lsig/ed25519lsig/keys"
	v1 "github.com/aplane-algo/aplane/lsig/ed25519lsig/v1"
)

const (
	FamilyName = family.Name
	KeyTypeV1  = family.KeyTypeV1
)

type metadata struct{}

func (metadata) RoutingFamily() string        { return FamilyName }
func (metadata) CryptoSignatureSize() int     { return family.MaxSignatureSize }
func (metadata) MnemonicWordCount() int       { return family.MnemonicWordCount }
func (metadata) SupportsMnemonicImport() bool { return true }
func (metadata) MnemonicScheme() string       { return family.MnemonicScheme }
func (metadata) RequiresLogicSig() bool       { return true }
func (metadata) CurrentLsigVersion() int      { return 1 }
func (metadata) SupportedLsigVersions() []int { return []int{1} }
func (metadata) DefaultDerivation() string    { return "algorand-standard" }
func (metadata) DisplayColor() string         { return family.DisplayColor }

var registerClientOnce sync.Once

func RegisterClient() {
	registerClientOnce.Do(func() {
		dsafamily.RegisterClient(dsafamily.ClientRegistration{
			Family:   FamilyName,
			Metadata: metadata{},
			KeyTypes: []dsafamily.KeyType{{
				KeyType:        KeyTypeV1,
				DSA:            v1.NewProvider(),
				AddressDeriver: ed25519keys.NewAddressDeriver(KeyTypeV1),
			}},
			Extra: []func(){func() {
				composeddsa.RegisterBase(composeddsa.BaseRegistration{
					BaseKeyType: KeyTypeV1,
					FamilyName:  FamilyName,
					Version:     1,
					Ops:         v1.NewOps(),
					NewAddressDeriver: func(templateKeyType string) addressderive.Deriver {
						return ed25519keys.NewAddressDeriver(templateKeyType)
					},
				})
			}},
		})
	})
}
