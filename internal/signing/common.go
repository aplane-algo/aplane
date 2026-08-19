// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	_ "embed"
)

//go:embed dummy.teal.tok
var EmbeddedDummyTealTok []byte

// DefaultMinFee is the standard Algorand minimum fee (1000 microAlgos).
const DefaultMinFee uint64 = 1000
