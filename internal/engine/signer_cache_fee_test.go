// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestAuthorizationFeeReserveUsesCompiledV42ResourceModel(t *testing.T) {
	const address = "ADDR"
	engine, err := NewEngine("test")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	engine.SignerCache.SetLogicSigResourceProfile(address, lsigresource.Profile{
		ProgramBytes: 4_500,
		Spend: &lsigresource.PathProfile{
			ArgumentBytes: 1_423,
			MaxOpcodeCost: 20_000,
		},
	})

	got, err := engine.AuthorizationFeeReserve(address)
	if err != nil {
		t.Fatalf("AuthorizationFeeReserve() error = %v", err)
	}
	if got != 1_251 {
		t.Fatalf("AuthorizationFeeReserve() = %d, want 1251", got)
	}
}

// The reserve counts each dummy at the dummy program's real cost of 3, as the
// signer's planner does: 39,999 needs two dummies (40,005), not one (40,002 is
// over two transactions' 40,000), so it reserves two dummies' base fees.
func TestAuthorizationFeeReserveCountsTheDummyProgramCost(t *testing.T) {
	const address = "ADDR"
	engine, err := NewEngine("test")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	engine.SignerCache.SetLogicSigResourceProfile(address, lsigresource.Profile{
		ProgramBytes: 1_000,
		Spend:        &lsigresource.PathProfile{MaxOpcodeCost: 39_999},
	})

	got, err := engine.AuthorizationFeeReserve(address)
	if err != nil {
		t.Fatalf("AuthorizationFeeReserve() error = %v", err)
	}
	if got != 2_000 {
		t.Fatalf("AuthorizationFeeReserve() = %d, want 2000 for two dummies", got)
	}
}

func TestAuthorizationFeeReserveUsesNativeFalconContribution(t *testing.T) {
	const address = "ADDR"
	engine, err := NewEngine("test")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	engine.SignerCache.AddAddress(address, "falcon1024")

	got, err := engine.AuthorizationFeeReserve(address)
	if err != nil {
		t.Fatalf("AuthorizationFeeReserve() error = %v", err)
	}
	if got != 2_000 {
		t.Fatalf("AuthorizationFeeReserve() = %d, want 2000", got)
	}
}

func TestAuthorizationFeeReserveSkipsOrdinaryAccountWithoutAlgod(t *testing.T) {
	engine, err := NewEngine("test")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	got, err := engine.AuthorizationFeeReserve("ADDR")
	if err != nil || got != 0 {
		t.Fatalf("AuthorizationFeeReserve() = %d, %v; want 0, nil", got, err)
	}
}

// The reserve is for the address it is given, the one that signs
// (SigningContext.SigningAddr); the auth cache is not read. A rotating
// account's cached auth address is a stage the signer never lists, and the
// account itself, which signs at any stage, still reserves its own profile's.
func TestAuthorizationFeeReserveDoesNotReadTheAuthCache(t *testing.T) {
	const account, stage = "ACCOUNT", "STAGE"
	engine, err := NewEngine("test")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	engine.SignerCache.AddAddress(account, rotatingkey.RotatingTripleXmssV1)
	engine.SignerCache.SetSigningFlowForAddress(account, signerapi.SigningFlowRotating1)
	engine.SignerCache.SetLogicSigResourceProfile(account, lsigresource.Profile{
		ProgramBytes: 4_500,
		Spend:        &lsigresource.PathProfile{ArgumentBytes: 1_423, MaxOpcodeCost: 20_000},
	})
	if err := engine.AuthCache.UpdateAuthAddress(account, stage, "test"); err != nil {
		t.Fatalf("UpdateAuthAddress() error = %v", err)
	}
	got, err := engine.AuthorizationFeeReserve(account)
	if err != nil || got != 1_251 {
		t.Fatalf("AuthorizationFeeReserve() = %d, %v; want 1251, nil", got, err)
	}
}
