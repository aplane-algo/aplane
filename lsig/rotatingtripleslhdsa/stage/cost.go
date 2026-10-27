// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stage

// Each WOTS+ layer performs c + 45 - digitSum16(c) verification steps,
// where c is the checksum of 32 nibbles (0..480). The maximum is 510.
const MaxStepsPerLayer = 510

// The verifier's cost is affine in the WOTS+ chain steps. The fixed work
// includes 14 FORS leaves and 168 FORS path hashes, one FORS compression,
// one WOTS compression and h' path hashes per layer, two H_msg hashes, and
// the Falcon/Ed25519 checks. All branches except the unrolled chain steps
// have input-independent cost. Each chain step has 6 unit-cost
// instructions plus sha256 (35); switch entry and endpoint collection for
// every chain are included in BaseOpcodeCost. Both constants are checked
// against node traces by the LocalNet test, for the selected shape.
var (
	BaseOpcodeCost   = selected.base
	StepOpcodeCost   = selected.step
	MaxAcceptedSteps = int(Params.D) * MaxStepsPerLayer
	MaxOpcodeCost    = BaseOpcodeCost + StepOpcodeCost*MaxAcceptedSteps
)

// OpcodeCost is the exact accepting execution cost. The salt tail follows
// return and is unreachable. LocalNet tests compare this to node traces.
func OpcodeCost(steps int) uint64 { return uint64(BaseOpcodeCost + StepOpcodeCost*steps) }
