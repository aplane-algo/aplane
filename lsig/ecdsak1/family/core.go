// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package family

// ECDSAK1Core contains shared ECDSA secp256k1 metadata.
type ECDSAK1Core struct{}

func (c *ECDSAK1Core) CryptoSignatureSize() int { return MaxSignatureSize }
func (c *ECDSAK1Core) MnemonicScheme() string   { return MnemonicScheme }
func (c *ECDSAK1Core) MnemonicWordCount() int   { return MnemonicWordCount }
func (c *ECDSAK1Core) DisplayColor() string     { return DisplayColor }
