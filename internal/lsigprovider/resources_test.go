// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigresource"
)

type testOpcodeProfileProvider struct {
	profile lsigresource.OpcodeProfile
}

func (p testOpcodeProfileProvider) LogicSigOpcodeProfile() lsigresource.OpcodeProfile {
	return p.profile
}

func TestResolveOpcodeProfileUsesConservativeFallback(t *testing.T) {
	profile, err := ResolveOpcodeProfile(struct{}{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Default != lsigresource.MaximumDeclaredOpcodeCost {
		t.Fatalf("default ceiling = %d, want %d", profile.Default, lsigresource.MaximumDeclaredOpcodeCost)
	}
}

func TestResolveOpcodeProfilePreservesReviewedProviderProfile(t *testing.T) {
	want := lsigresource.DefaultOpcodeProfile(12_345)
	got, err := ResolveOpcodeProfile(testOpcodeProfileProvider{profile: want}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("profile = %#v, want %#v", got, want)
	}
}

func TestResolveOpcodeProfileRejectsWrongShape(t *testing.T) {
	_, err := ResolveOpcodeProfile(testOpcodeProfileProvider{
		profile: lsigresource.DefaultOpcodeProfile(20_000),
	}, true)
	if err == nil {
		t.Fatal("bounded provider with default-path profile was accepted")
	}
}
