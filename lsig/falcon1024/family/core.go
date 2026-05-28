// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package family

// FalconCore contains shared Falcon-1024 metadata.
// It is embedded by version-specific implementations (Falcon1024V1, Falcon1024V2, etc.)
// to provide common metadata while allowing version-specific LogicSig derivation.
type FalconCore struct{}

// CryptoSignatureSize returns the maximum Falcon-1024 signature size in bytes.
// Used for pre-signing fee estimation.
func (c *FalconCore) CryptoSignatureSize() int {
	return MaxSignatureSize
}

// MnemonicScheme returns the mnemonic scheme used by Falcon.
func (c *FalconCore) MnemonicScheme() string {
	return MnemonicScheme
}

// MnemonicWordCount returns the expected number of mnemonic words.
func (c *FalconCore) MnemonicWordCount() int {
	return MnemonicWordCount
}

// DisplayColor returns the ANSI color code for Falcon addresses in UI.
func (c *FalconCore) DisplayColor() string {
	return DisplayColor
}
