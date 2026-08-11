// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigresource

import (
	"errors"
	"testing"
)

func TestProfileRequiresExplicitSelectedPath(t *testing.T) {
	t.Parallel()

	profile := Profile{
		ProgramBytes: 100,
		Default:      &PathProfile{ArgumentBytes: 64, MaxOpcodeCost: 1_900},
		Spend:        &PathProfile{ArgumentBytes: 1_423, MaxOpcodeCost: 1_750},
	}
	usage, err := profile.UsageForPath(PathSpend)
	if err != nil {
		t.Fatal(err)
	}
	if usage != (Usage{ProgramBytes: 100, ArgumentBytes: 1_423, MaxOpcodeCost: 1_750}) {
		t.Fatalf("spend usage = %#v", usage)
	}
	if _, err := profile.UsageForPath(PathAdminRekey); !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("missing admin path error = %v", err)
	}
	defaultUsage, err := profile.UsageForPath(PathDefault)
	if err != nil {
		t.Fatal(err)
	}
	if defaultUsage.ArgumentBytes != 64 {
		t.Fatalf("default argument bytes = %d", defaultUsage.ArgumentBytes)
	}
}

func TestProfileCloneDoesNotAliasPaths(t *testing.T) {
	t.Parallel()

	original := Profile{ProgramBytes: 1, Spend: &PathProfile{ArgumentBytes: 2, MaxOpcodeCost: 3}}
	cloned := original.Clone()
	cloned.Spend.ArgumentBytes = 99
	if original.Spend.ArgumentBytes != 2 {
		t.Fatalf("clone changed original: %#v", original)
	}
}

func TestProfileRejectsIncompleteUsage(t *testing.T) {
	t.Parallel()

	tests := []Profile{
		{Default: &PathProfile{MaxOpcodeCost: 1}},
		{ProgramBytes: 1, Default: &PathProfile{}},
	}
	for _, profile := range tests {
		if _, err := profile.UsageForPath(PathDefault); !errors.Is(err, ErrInvalidUsage) {
			t.Fatalf("UsageForPath(%#v) error = %v", profile, err)
		}
	}
}

func TestOpcodeProfileRequiresClosedPathShape(t *testing.T) {
	t.Parallel()

	if err := DefaultOpcodeProfile(1_900).Validate(false); err != nil {
		t.Fatalf("default profile: %v", err)
	}
	if err := BoundedOpcodeProfile(1_700, 1_800, 3_400).Validate(true); err != nil {
		t.Fatalf("bounded profile: %v", err)
	}
	tests := []struct {
		name    string
		profile OpcodeProfile
		bounded bool
	}{
		{name: "missing default"},
		{name: "mixed vocabulary", profile: OpcodeProfile{Default: 1, Spend: 1}},
		{name: "incomplete bounded", profile: OpcodeProfile{Spend: 1, SpendingRekey: 1}, bounded: true},
		{name: "over maximum", profile: OpcodeProfile{Default: MaximumDeclaredOpcodeCost + 1}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.profile.Validate(test.bounded); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestMaterializeCombinesOnlyDerivedAndDurableFields(t *testing.T) {
	t.Parallel()

	args := uint64(1_423)
	profile, err := Materialize(1_800, &args, nil, DefaultOpcodeProfile(1_750))
	if err != nil {
		t.Fatal(err)
	}
	usage, err := profile.UsageForPath(PathDefault)
	if err != nil {
		t.Fatal(err)
	}
	if usage != (Usage{ProgramBytes: 1_800, ArgumentBytes: 1_423, MaxOpcodeCost: 1_750}) {
		t.Fatalf("usage = %#v", usage)
	}
}
