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
		name    string
		version protocol.ConsensusVersion
	}{
		{name: "v42", version: protocol.ConsensusV42},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile, err := ResolveConsensus(string(test.version))
			if err != nil {
				t.Fatal(err)
			}
			if profile.Version != CurrentConsensusVersion {
				t.Fatalf("profile version = %s, want %s", profile.Version, CurrentConsensusVersion)
			}
			params, ok := sdkconfig.Consensus[CurrentConsensusVersion]
			if !ok {
				t.Fatalf("SDK consensus table has no entry for %s", CurrentConsensusVersion)
			}
			if params.LogicSigVersion != 13 {
				t.Fatalf("LogicSigVersion = %d, want 13", params.LogicSigVersion)
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
			if params.MaxTxGroupSize != 16 {
				t.Fatalf("MaxTxGroupSize = %d, want 16", params.MaxTxGroupSize)
			}
			if params.MinTxnFee != 1_000 || profile.MinTxnFee != params.MinTxnFee {
				t.Fatalf("MinTxnFee = SDK %d/profile %d, want 1000", params.MinTxnFee, profile.MinTxnFee)
			}
			if got := uint64(params.PerByteTxnSurcharge); got != 100 {
				t.Fatalf("PerByteTxnSurcharge = %d, want 100", got)
			}
		})
	}
}

func TestPinnedV42LogicSigSizeVectors(t *testing.T) {
	t.Parallel()

	v42 := sdkconfig.Consensus[protocol.ConsensusV42]
	tests := []struct {
		name     string
		programs []int
		args     []int
		group    int
		v42OK    bool
	}{
		{
			name:     "large program is priced",
			programs: []int{4_500}, args: []int{0}, group: 1,
			v42OK: true,
		},
		{
			name:     "individual argument allowance does not pool small args",
			programs: []int{1, 1}, args: []int{900, 900}, group: 2,
			v42OK: true,
		},
		{
			name:     "one large argument activates the whole argument pool",
			programs: []int{1, 1}, args: []int{1_001, 1_000}, group: 2,
			v42OK: false,
		},
		{
			name:     "large argument pool fits after group expansion",
			programs: []int{1, 1}, args: []int{1_001, 1_000}, group: 3,
			v42OK: true,
		},
		{
			name:     "program hard cap is independent of pricing",
			programs: []int{16_001}, args: []int{0}, group: 16,
			v42OK: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
	argSize := 0
	largeArg := false
	for i, program := range programs {
		if program < 0 || args[i] < 0 || uint64(program) > params.MaxAbsoluteLogicSigProgramSize {
			return false
		}
		argSize += args[i]
		largeArg = largeArg || uint64(args[i]) > params.LogicSigMaxSize
	}
	available := groupSize * int(params.LogicSigMaxSize)
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
