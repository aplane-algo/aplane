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
