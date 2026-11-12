// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"reflect"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/txnreview"
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

// RekeyTargetContext reads the held aplane keys and those that are not valid
// rekey targets from one snapshot of the signer cache: every listed address is
// held, a generic LogicSig included, and every held aplane key without a
// recorded valid_rekey_target true is not a valid rekey target.
func TestRekeyTargetContextReadsTheSignerCacheOnce(t *testing.T) {
	engine, err := NewEngine("test")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	if err := engine.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: "NATIVE", KeyType: "ed25519", ValidRekeyTarget: true},
		{Address: "ROTATING", KeyType: "aplane.rotating-triple-wotsc.v1", SigningFlow: signerapi.SigningFlowRotating1},
		{Address: "HTLC", KeyType: "aplane.htlc.v1", IsGenericLsig: true},
		{Address: "VAULT", KeyType: "example.vault.v1", IsGenericLsig: true, ValidRekeyTarget: true},
	}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	got := engine.RekeyTargetContext()
	wantHeld := map[string]bool{"NATIVE": true, "ROTATING": true, "HTLC": true, "VAULT": true}
	if !reflect.DeepEqual(got.KnownAddresses, wantHeld) {
		t.Errorf("KnownAddresses = %v, want %v", got.KnownAddresses, wantHeld)
	}
	wantInvalid := map[string]txnreview.InvalidRekeyTarget{
		"ROTATING": {KeyType: "aplane.rotating-triple-wotsc.v1"},
		"HTLC":     {KeyType: "aplane.htlc.v1", GenericLogicSig: true},
	}
	if !reflect.DeepEqual(got.InvalidRekeyTargets, wantInvalid) {
		t.Errorf("InvalidRekeyTargets = %v, want %v", got.InvalidRekeyTargets, wantInvalid)
	}
	if got.ListedRekeyTargets != nil || got.ProtocolRekeyTargets != nil {
		t.Errorf("the signer cache knows no rekey-to lists or protocol targets: %+v", got)
	}
}
