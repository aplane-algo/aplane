// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package corridor

import (
	"sync"

	"github.com/aplane-algo/aplane/lsig/dsafamily"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconkeys "github.com/aplane-algo/aplane/lsig/falcon1024/keys"
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

var registerClientOnce sync.Once

func RegisterClient() {
	registerClientOnce.Do(func() {
		dsafamily.RegisterClient(dsafamily.ClientRegistration{
			Family:   FamilyName,
			Metadata: metadata{},
			KeyTypes: []dsafamily.KeyType{{
				KeyType:        KeyTypeV1,
				DSA:            NewProviderV1(),
				AddressDeriver: falconkeys.GetFalconAddressDeriverForType(KeyTypeV1),
			}},
		})
	})
}
