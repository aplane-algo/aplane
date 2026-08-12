// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigresource

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/protocol"
	sdkconfig "github.com/algorand/go-algorand-sdk/v2/protocol/config"
)

func TestPinnedLogicSigConsensusContracts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		version          protocol.ConsensusVersion
		logicSigVersion  uint64
		perByteSurcharge uint64
	}{
		{name: "v41", version: protocol.ConsensusV41, logicSigVersion: 12},
		{name: "v42", version: protocol.ConsensusV42, logicSigVersion: 13, perByteSurcharge: 100},
		{name: "fnet5", version: protocol.ConsensusVFnet5, logicSigVersion: 13, perByteSurcharge: 100},
		// LocalNet reports "future"; it is v42 with a newer LogicSigVersion.
		{name: "future", version: protocol.ConsensusFuture, logicSigVersion: 14, perByteSurcharge: 100},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params, ok := sdkconfig.Consensus[test.version]
			if !ok {
				t.Fatalf("SDK consensus table has no entry for %s", test.version)
			}
			if params.LogicSigVersion != test.logicSigVersion {
				t.Fatalf("LogicSigVersion = %d, want %d", params.LogicSigVersion, test.logicSigVersion)
			}
			if params.LogicSigMaxSize != 1_000 {
				t.Fatalf("LogicSigMaxSize = %d, want 1000", params.LogicSigMaxSize)
			}
			if params.MaxAbsoluteLogicSigProgramSize != 16_000 {
				t.Fatalf("MaxAbsoluteLogicSigProgramSize = %d, want 16000", params.MaxAbsoluteLogicSigProgramSize)
			}
			if params.LogicSigMaxCost != 20_000 {
				t.Fatalf("LogicSigMaxCost = %d, want 20000", params.LogicSigMaxCost)
			}
			if got := uint64(params.PerByteTxnSurcharge); got != test.perByteSurcharge {
				t.Fatalf("PerByteTxnSurcharge = %d, want %d", got, test.perByteSurcharge)
			}
		})
	}
}

func TestPinnedV41AndV42LogicSigSizeVectors(t *testing.T) {
	t.Parallel()

	v41 := sdkconfig.Consensus[protocol.ConsensusV41]
	v42 := sdkconfig.Consensus[protocol.ConsensusV42]
	tests := []struct {
		name     string
		programs []int
		args     []int
		group    int
		v41OK    bool
		v42OK    bool
	}{
		{
			name:     "large program is priced only in v42",
			programs: []int{4_500}, args: []int{0}, group: 1,
			v41OK: false, v42OK: true,
		},
		{
			name:     "individual argument allowance does not pool small args",
			programs: []int{1, 1}, args: []int{900, 900}, group: 2,
			v41OK: true, v42OK: true,
		},
		{
			name:     "one large argument activates the whole argument pool",
			programs: []int{1, 1}, args: []int{1_001, 1_000}, group: 2,
			v41OK: false, v42OK: false,
		},
		{
			name:     "large argument pool fits after group expansion",
			programs: []int{1, 1}, args: []int{1_001, 1_000}, group: 3,
			v41OK: true, v42OK: true,
		},
		{
			name:     "program hard cap is independent of pricing",
			programs: []int{16_001}, args: []int{0}, group: 16,
			v41OK: false, v42OK: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := referenceLogicSigSizeAllowed(v41, test.programs, test.args, test.group); got != test.v41OK {
				t.Fatalf("v41 allowed = %t, want %t", got, test.v41OK)
			}
			if got := referenceLogicSigSizeAllowed(v42, test.programs, test.args, test.group); got != test.v42OK {
				t.Fatalf("v42 allowed = %t, want %t", got, test.v42OK)
			}
		})
	}
}

func TestPinnedV42ProgramSurchargeVectors(t *testing.T) {
	t.Parallel()

	params := sdkconfig.Consensus[protocol.ConsensusV42]
	tests := []struct {
		name       string
		programs   []int
		group      int
		wantBytes  int
		wantFactor uint64
	}{
		{name: "within free pool", programs: []int{999}, group: 1},
		{name: "one byte charged", programs: []int{1_001}, group: 1, wantBytes: 1, wantFactor: 100},
		{name: "group free pool", programs: []int{1_500, 500}, group: 2},
		{name: "dummy program participates", programs: []int{4_500, 4}, group: 2, wantBytes: 2_504, wantFactor: 250_400},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bytes, factor := referenceProgramSurcharge(params, test.programs, test.group)
			if bytes != test.wantBytes || factor != test.wantFactor {
				t.Fatalf("surcharge = %d bytes/%d factor, want %d/%d", bytes, factor, test.wantBytes, test.wantFactor)
			}
		})
	}
}

// referenceLogicSigSizeAllowed mirrors the size portion of go-algorand's
// logicSigGroupSizeCheck. It is deliberately test-only: production planning
// lands behind independently reviewed resource types in the next slice.
func referenceLogicSigSizeAllowed(params sdkconfig.ConsensusParams, programs, args []int, groupSize int) bool {
	if len(programs) != len(args) || groupSize <= 0 {
		return false
	}
	pooledSize := 0
	argSize := 0
	largeArg := false
	for i, program := range programs {
		if program < 0 || args[i] < 0 || uint64(program) > params.MaxAbsoluteLogicSigProgramSize {
			return false
		}
		pooledSize += program + args[i]
		argSize += args[i]
		largeArg = largeArg || uint64(args[i]) > params.LogicSigMaxSize
	}
	available := groupSize * int(params.LogicSigMaxSize)
	if params.PerByteTxnSurcharge == 0 && pooledSize > available {
		return false
	}
	return !largeArg || argSize <= available
}

func referenceProgramSurcharge(params sdkconfig.ConsensusParams, programs []int, groupSize int) (int, uint64) {
	total := 0
	for _, program := range programs {
		total += program
	}
	charged := total - groupSize*int(params.LogicSigMaxSize)
	if charged < 0 {
		charged = 0
	}
	return charged, uint64(charged) * uint64(params.PerByteTxnSurcharge)
}
