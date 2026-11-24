// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestAuthorizationFeeReserveUsesCompiledV42ResourceModel(t *testing.T) {
	const address = "ADDR"
	sc := cache.NewSignerCache()
	sc.SetLogicSigResourceProfile(address, lsigresource.Profile{
		ProgramBytes: 4_500,
		Spend: &lsigresource.PathProfile{
			ArgumentBytes: 1_423,
			MaxOpcodeCost: 20_000,
		},
	})
	engine := NewEngine("test", WithSignerCache(sc))

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
	sc := cache.NewSignerCache()
	sc.SetLogicSigResourceProfile(address, lsigresource.Profile{
		ProgramBytes: 1_000,
		Spend:        &lsigresource.PathProfile{MaxOpcodeCost: 39_999},
	})
	engine := NewEngine("test", WithSignerCache(sc))

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
	sc := cache.NewSignerCache()
	sc.AddAddress(address, "falcon1024", "native_pq")
	engine := NewEngine("test", WithSignerCache(sc))

	got, err := engine.AuthorizationFeeReserve(address)
	if err != nil {
		t.Fatalf("AuthorizationFeeReserve() error = %v", err)
	}
	if got != 2_000 {
		t.Fatalf("AuthorizationFeeReserve() = %d, want 2000", got)
	}
}

func TestAuthorizationFeeReserveSkipsOrdinaryAccountWithoutAlgod(t *testing.T) {
	engine := NewEngine("test")
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
	sc := cache.NewSignerCache()
	sc.AddAddress(account, rotatingkey.RotatingTripleXmssV1, "logic_sig")
	sc.SetSigningFlowForAddress(account, signerapi.SigningFlowRotating1)
	sc.SetLogicSigResourceProfile(account, lsigresource.Profile{
		ProgramBytes: 4_500,
		Spend:        &lsigresource.PathProfile{ArgumentBytes: 1_423, MaxOpcodeCost: 20_000},
	})
	engine := NewEngine("test", WithSignerCache(sc))
	if err := engine.AuthCache.UpdateAuthAddress(account, stage, "test"); err != nil {
		t.Fatalf("UpdateAuthAddress() error = %v", err)
	}
	got, err := engine.AuthorizationFeeReserve(account)
	if err != nil || got != 1_251 {
		t.Fatalf("AuthorizationFeeReserve() = %d, %v; want 1251, nil", got, err)
	}
}
