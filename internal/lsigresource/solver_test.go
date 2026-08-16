// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigresource

import (
	"errors"
	"math"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/protocol"
)

var minimalDummy = Usage{ProgramBytes: 1, MaxOpcodeCost: 1}

func mustProfile(t *testing.T, version protocol.ConsensusVersion) ConsensusProfile {
	t.Helper()
	profile, err := ResolveConsensus(string(version))
	if err != nil {
		t.Fatalf("ResolveConsensus(%q) error = %v", version, err)
	}
	return profile
}

func TestResolveConsensusUsesSingleV42Contract(t *testing.T) {
	t.Parallel()

	v42 := mustProfile(t, protocol.ConsensusV42)
	if v42.Version != CurrentConsensusVersion || v42.PerByteTxnSurcharge != 100 {
		t.Fatalf("v42 profile = %#v", v42)
	}
	fnet := mustProfile(t, protocol.ConsensusVFnet5)
	if fnet != v42 {
		t.Fatalf("fnet5 profile = %#v, want v42 contract %#v", fnet, v42)
	}
	for _, unsupported := range []protocol.ConsensusVersion{protocol.ConsensusV41, protocol.ConsensusFuture, "future-unreviewed"} {
		if _, err := ResolveConsensus(string(unsupported)); !errors.Is(err, ErrUnknownConsensus) {
			t.Fatalf("ResolveConsensus(%q) error = %v, want unsupported", unsupported, err)
		}
	}
}

func TestSolveV42ArgumentPooling(t *testing.T) {
	t.Parallel()

	profile := mustProfile(t, protocol.ConsensusV42)
	tests := []struct {
		name       string
		requested  uint64
		usages     []Usage
		wantGroup  uint64
		wantDummy  uint64
		wantPooled bool
	}{
		{name: "single Falcon ceiling", requested: 1, usages: []Usage{{ProgramBytes: 1, ArgumentBytes: 1_423, MaxOpcodeCost: 1}}, wantGroup: 2, wantDummy: 1, wantPooled: true},
		{name: "independent small args", requested: 2, usages: []Usage{{ProgramBytes: 1, ArgumentBytes: 900}, {ProgramBytes: 1, ArgumentBytes: 900}}, wantGroup: 2},
		{name: "one large arg activates total pool", requested: 2, usages: []Usage{{ProgramBytes: 1, ArgumentBytes: 1_001}, {ProgramBytes: 1, ArgumentBytes: 999}}, wantGroup: 2, wantPooled: true},
		{name: "pooled total expands group", requested: 2, usages: []Usage{{ProgramBytes: 1, ArgumentBytes: 1_001}, {ProgramBytes: 1, ArgumentBytes: 1_000}}, wantGroup: 3, wantDummy: 1, wantPooled: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := Solve(profile, PlanInput{TransactionCount: test.requested, LogicSigs: test.usages, Dummy: minimalDummy})
			if err != nil {
				t.Fatal(err)
			}
			if plan.GroupSize != test.wantGroup || plan.DummyCount != test.wantDummy || plan.ArgumentsPooled != test.wantPooled {
				t.Fatalf("plan = %#v, want group %d/dummies %d/pooled %t", plan, test.wantGroup, test.wantDummy, test.wantPooled)
			}
		})
	}
}

func TestSolveV42PricesProgramsWithoutAddingDummies(t *testing.T) {
	t.Parallel()

	profile := mustProfile(t, protocol.ConsensusV42)
	plan, err := Solve(profile, PlanInput{
		TransactionCount: 1,
		LogicSigs:        []Usage{{ProgramBytes: 4_500, MaxOpcodeCost: 1}},
		Dummy:            minimalDummy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.GroupSize != 1 || plan.DummyCount != 0 {
		t.Fatalf("program pricing changed group shape: %#v", plan)
	}
	if plan.ChargedProgramBytes != 3_500 || plan.ProgramFeeFactorUsage != 350_000 {
		t.Fatalf("program pricing = %d bytes/%d factor, want 3500/350000", plan.ChargedProgramBytes, plan.ProgramFeeFactorUsage)
	}

	plan, err = Solve(profile, PlanInput{
		TransactionCount: 1,
		LogicSigs:        []Usage{{ProgramBytes: 4_500, ArgumentBytes: 1_423, MaxOpcodeCost: 1}},
		Dummy:            minimalDummy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.GroupSize != 2 || plan.ChargedProgramBytes != 2_501 || plan.ProgramFeeFactorUsage != 250_100 {
		t.Fatalf("Falcon program plan = %#v", plan)
	}
}

func TestSolveIncludesDummyOpcodeCostInFixedPoint(t *testing.T) {
	t.Parallel()

	profile := mustProfile(t, protocol.ConsensusV42)
	plan, err := Solve(profile, PlanInput{
		TransactionCount: 1,
		LogicSigs:        []Usage{{ProgramBytes: 1, MaxOpcodeCost: 40_000}},
		Dummy:            minimalDummy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.GroupSize != 3 || plan.DummyCount != 2 || plan.TotalMaxOpcodeCost != 40_002 {
		t.Fatalf("fixed-point plan = %#v, want group 3 with two dummies", plan)
	}
}

func TestSolveRejectsLimitsAndNonConvergingDummy(t *testing.T) {
	t.Parallel()

	profile := mustProfile(t, protocol.ConsensusV42)
	tests := []struct {
		name  string
		input PlanInput
		want  error
	}{
		{name: "empty program", input: PlanInput{TransactionCount: 1, LogicSigs: []Usage{{ArgumentBytes: 1}}, Dummy: minimalDummy}, want: ErrInvalidUsage},
		{name: "program over hard cap", input: PlanInput{TransactionCount: 1, LogicSigs: []Usage{{ProgramBytes: 16_001}}, Dummy: minimalDummy}, want: ErrInvalidUsage},
		{name: "too many requested", input: PlanInput{TransactionCount: 17, Dummy: minimalDummy}, want: ErrGroupTooLarge},
		{name: "dummy consumes more args than it contributes", input: PlanInput{TransactionCount: 1, LogicSigs: []Usage{{ProgramBytes: 1, ArgumentBytes: 1_001}}, Dummy: Usage{ProgramBytes: 1, ArgumentBytes: 1_001}}, want: ErrGroupTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Solve(profile, test.input)
			if !errors.Is(err, test.want) {
				t.Fatalf("Solve() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSolveAppliesFinalProgramHardCap(t *testing.T) {
	t.Parallel()

	profile := mustProfile(t, protocol.ConsensusV42)
	if _, err := Solve(profile, PlanInput{
		TransactionCount: 1,
		LogicSigs:        []Usage{{ProgramBytes: 16_000}},
		Dummy:            minimalDummy,
	}); err != nil {
		t.Fatalf("Solve(16000-byte final program) error = %v", err)
	}
	if _, err := Solve(profile, PlanInput{
		TransactionCount: 1,
		LogicSigs:        []Usage{{ProgramBytes: 16_001}},
		Dummy:            minimalDummy,
	}); !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("Solve(16001-byte final program) error = %v", err)
	}
}

func TestArithmeticRejectsOverflow(t *testing.T) {
	t.Parallel()

	if _, err := checkedAdd(math.MaxUint64, 1); !errors.Is(err, ErrResourceOverflow) {
		t.Fatalf("checkedAdd overflow error = %v", err)
	}
	if _, err := checkedMul(math.MaxUint64, 2); !errors.Is(err, ErrResourceOverflow) {
		t.Fatalf("checkedMul overflow error = %v", err)
	}
	if _, err := ceilDiv(math.MaxUint64, 2); !errors.Is(err, ErrResourceOverflow) {
		t.Fatalf("ceilDiv overflow error = %v", err)
	}
}
