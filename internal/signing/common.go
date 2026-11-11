// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	_ "embed"
)

//go:embed dummy.teal.tok
var EmbeddedDummyTealTok []byte

// DummyOpcodeCost is the opcode cost of one run of EmbeddedDummyTealTok:
// txn RekeyTo, global ZeroAddress and ==, three opcodes costing 1 each, with
// no branch. Every resource plan counts each dummy at this cost. A test derives
// it from the embedded bytecode, so the two cannot drift.
const DummyOpcodeCost uint64 = 3

// DefaultMinFee is the standard Algorand minimum fee (1000 microAlgos).
const DefaultMinFee uint64 = 1000
