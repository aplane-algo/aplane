// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stage

const (
	// Each WOTS+ layer performs c + 45 - digitSum16(c) verification steps,
	// where c is the checksum of 32 nibbles (0..480). The maximum is 510.
	MaxStepsPerLayer = 510
	MaxAcceptedSteps = 7 * MaxStepsPerLayer
	// The fixed work includes 14 FORS leaves and 168 FORS path hashes,
	// one FORS compression, seven WOTS compressions, 63 HT path hashes,
	// two H_msg hashes, and the Falcon/Ed25519 checks. All branches except
	// the chain loop have input-independent cost. Each chain iteration has
	// 18 unit-cost instructions plus sha256 (35), including its loop check.
	// Terminal checks for all 245 chains are included in BaseOpcodeCost.
	BaseOpcodeCost = 42113
	StepOpcodeCost = 53
	MaxOpcodeCost  = BaseOpcodeCost + StepOpcodeCost*MaxAcceptedSteps
)

// OpcodeCost is the exact accepting execution cost. The salt tail follows
// return and is unreachable. LocalNet tests compare this to node traces.
func OpcodeCost(steps int) uint64 { return uint64(BaseOpcodeCost + StepOpcodeCost*steps) }
