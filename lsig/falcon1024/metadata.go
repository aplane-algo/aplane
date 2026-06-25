// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falcon

import (
	"github.com/aplane-algo/aplane/lsig/falcon1024/derivation"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

// FalconMetadata implements SignatureMetadata for the Falcon-1024 family
type FalconMetadata struct{}

func (m *FalconMetadata) RoutingFamily() string        { return family.Name }
func (m *FalconMetadata) CryptoSignatureSize() int     { return family.MaxSignatureSize }
func (m *FalconMetadata) MnemonicWordCount() int       { return family.MnemonicWordCount }
func (m *FalconMetadata) SupportsMnemonicImport() bool { return true }
func (m *FalconMetadata) MnemonicScheme() string       { return family.MnemonicScheme }
func (m *FalconMetadata) RequiresLogicSig() bool       { return true }
func (m *FalconMetadata) CurrentLsigVersion() int      { return derivation.CurrentVersion }
func (m *FalconMetadata) SupportedLsigVersions() []int { return derivation.SupportedVersions() }
func (m *FalconMetadata) DefaultDerivation() string    { return "bip39-standard" }
func (m *FalconMetadata) DisplayColor() string         { return family.DisplayColor }
