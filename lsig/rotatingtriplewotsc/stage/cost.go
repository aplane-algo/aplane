// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stage

// ChainSteps is the number of chain steps in every accepted run: each of the
// 32 chains runs 15 - digit steps, and the digits sum to 240.
const ChainSteps = 240

// StepOpcodeCost is one chain step: 6 unit-cost instructions plus sha256 (35).
const StepOpcodeCost = 41

// BaseOpcodeCost is everything else in an accepted run: the guards, the Ed25519
// and Falcon checks, the digest, the chain loop, the leaf compression and the
// six tree nodes. None of it depends on the input.
const BaseOpcodeCost = 5881

// MaxOpcodeCost is the exact cost of every accepted run, for every leaf and
// TxID. The salt tail follows return and is unreachable. The LocalNet test
// compares it to node traces.
const MaxOpcodeCost = BaseOpcodeCost + StepOpcodeCost*ChainSteps
