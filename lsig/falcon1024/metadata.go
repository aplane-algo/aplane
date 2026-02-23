// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package falcon

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/lsig/falcon1024/derivation"
)

// FalconMetadata implements SignatureMetadata for the Falcon-1024 family
type FalconMetadata struct{}

func (m *FalconMetadata) Family() string               { return "falcon1024" }
func (m *FalconMetadata) CryptoSignatureSize() int     { return 1280 } // Max Falcon-1024 signature size
func (m *FalconMetadata) MnemonicWordCount() int       { return 24 }
func (m *FalconMetadata) MnemonicScheme() string       { return "bip39" }
func (m *FalconMetadata) RequiresLogicSig() bool       { return true }
func (m *FalconMetadata) CurrentLsigVersion() int      { return derivation.CurrentVersion }
func (m *FalconMetadata) SupportedLsigVersions() []int { return derivation.SupportedVersions() }
func (m *FalconMetadata) DefaultDerivation() string    { return "bip39-standard" }
func (m *FalconMetadata) DisplayColor() string         { return "33" } // Yellow for falcon1024

var registerMetadataOnce sync.Once

// RegisterMetadata registers Falcon metadata with the algorithm registry.
// This is idempotent and safe to call multiple times.
func RegisterMetadata() {
	registerMetadataOnce.Do(func() {
		algorithm.RegisterMetadata(&FalconMetadata{})
	})
}
