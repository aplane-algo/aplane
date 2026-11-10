// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigresource

// LogicSig argument limits. The node holds these as constants, not consensus
// parameters (go-algorand data/transactions/logicsig.go: EvalMaxArgs and
// MaxLogicSigArgSize), so the SDK's consensus table doesn't carry them and they
// are restated here. A LogicSig that exceeds either is refused whatever its
// group looks like: dummy transactions pool total size and opcode budget, never
// the size of one argument or the number of them.
const (
	// MaxLogicSigArgs is the most arguments one LogicSig may carry.
	MaxLogicSigArgs = 255
	// MaxLogicSigArgBytes is the largest single LogicSig argument.
	MaxLogicSigArgBytes = 4096
)
