// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falcon1024guarded

import (
	"sync"

	"github.com/aplane-algo/aplane/lsig/dsafamily"

	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconkeys "github.com/aplane-algo/aplane/lsig/falcon1024/keys"
)

type metadata struct {
	family        string
	signatureSize int
}

func (m metadata) RoutingFamily() string      { return m.family }
func (m metadata) CryptoSignatureSize() int   { return m.signatureSize }
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
		// Two single-key-type registrations: the guarded variants have
		// distinct registry family names, and algorithm metadata is keyed by
		// family, so each carries its own metadata.
		dsafamily.RegisterClient(dsafamily.ClientRegistration{
			Family:   FamilyName,
			Metadata: metadata{family: FamilyName, signatureSize: SignatureSize},
			KeyTypes: []dsafamily.KeyType{{
				KeyType:        KeyTypeV1,
				DSA:            NewProviderV1(),
				AddressDeriver: falconkeys.GetFalconAddressDeriverForType(KeyTypeV1),
			}},
		})
		dsafamily.RegisterClient(dsafamily.ClientRegistration{
			Family:   FamilyNameFalcon1024,
			Metadata: metadata{family: FamilyNameFalcon1024, signatureSize: SignatureSizeFalcon1024},
			KeyTypes: []dsafamily.KeyType{{
				KeyType:        KeyTypeFalcon1024V1,
				DSA:            NewFalconSentryProviderV1(),
				AddressDeriver: falconkeys.GetFalconAddressDeriverForType(KeyTypeFalcon1024V1),
			}},
		})
	})
}
