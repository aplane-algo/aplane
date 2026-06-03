// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falcon1024attested

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
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
		logicsigdsa.Register(NewProviderV1())
		algorithm.RegisterMetadata(metadata{})
		addressderive.Register(KeyTypeV1, falconkeys.GetFalconAddressDeriverForType(KeyTypeV1))
	})
}
