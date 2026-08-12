// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigresource"
)

func TestScanLogicSigResourcesSeparatesProgramAndArguments(t *testing.T) {
	t.Parallel()

	payload := &Payload{
		Category:         CategoryDSALsig,
		LogicSigBytecode: make([]byte, 250),
		SigningArgs: []StoredSigningArg{
			{Name: "proof", Type: "bytes", ByteLength: 32},
			{Name: "note", Type: "bytes", MaxSize: 64},
		},
		LogicSigOpcodeProfile: lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling),
	}
	profile, err := scanLogicSigResources(payload, 1_423)
	if err != nil {
		t.Fatal(err)
	}
	if profile.ProgramBytes != 250 || profile.Default == nil || profile.Default.ArgumentBytes != 1_423+32+64 {
		t.Fatalf("default resources = %#v", profile)
	}
	if _, err := profile.UsageForPath(lsigresource.PathDefault); err != nil {
		t.Fatalf("scanned profile was not plannable: %v", err)
	}
}

func TestScanBoundedResourcesUsesPathMasks(t *testing.T) {
	t.Parallel()

	metadata := &boundedmeta.Metadata{ArgumentLayout: []boundedmeta.ArgumentSlot{
		{MaxSize: 1_423, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgRequired, AdminRekey: boundedmeta.ArgRequired}},
		{MaxSize: 512, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgOptional, SpendingRekey: boundedmeta.ArgForbidden, AdminRekey: boundedmeta.ArgForbidden}},
		{MaxSize: 1_423, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgForbidden, SpendingRekey: boundedmeta.ArgForbidden, AdminRekey: boundedmeta.ArgRequired}},
	}}
	profile, err := scanLogicSigResources(&Payload{
		Category:             CategoryDSALsig,
		LogicSigBytecode:     make([]byte, 4_500),
		BoundedAuthorization: metadata,
		LogicSigOpcodeProfile: lsigresource.BoundedOpcodeProfile(
			lsigresource.SingleTransactionOpcodeCeiling,
			lsigresource.SingleTransactionOpcodeCeiling,
			lsigresource.SingleTransactionOpcodeCeiling,
		),
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Spend == nil || profile.AdminRekey == nil || profile.Spend.ArgumentBytes != 1_935 || profile.AdminRekey.ArgumentBytes != 2_846 {
		t.Fatalf("bounded profile = %#v", profile)
	}
	if _, err := profile.UsageForPath(lsigresource.PathSpend); err != nil {
		t.Fatalf("bounded spend path was not plannable: %v", err)
	}
	if _, err := profile.UsageForPath(lsigresource.PathDefault); err == nil {
		t.Fatal("bounded resource profile exposed a default path")
	}
}

// Every LogicSig payload constructor stamps an opcode profile, so a key file
// that reaches the scanner without one is malformed. Rejecting it there keeps
// the failure at load time instead of surfacing as a planner internal error on
// the first signing attempt.
func TestScanLogicSigResourcesRejectsMissingOpcodeProfile(t *testing.T) {
	t.Parallel()

	_, err := scanLogicSigResources(&Payload{
		Category:         CategoryDSALsig,
		LogicSigBytecode: make([]byte, 250),
	}, 1_423)
	if err == nil {
		t.Fatal("payload without an opcode profile was accepted")
	}
}

// Constructors cannot infer opcode cost from program bytes or salt style.
// Generation must attach an explicit provider-owned or conservative profile.
func TestLogicSigPayloadConstructorsRequireExplicitOpcodeProfile(t *testing.T) {
	t.Parallel()

	zero := lsigresource.OpcodeProfile{}
	payloads := map[string]*Payload{
		"dsa":              NewDSALSigPayload("kt", "base", []byte{1}, []byte{2}, nil, []byte{6, 129, 1, 0}, 0, "", nil, ""),
		"dsa-autosalted":   NewAutoSaltedDSALSigPayload("kt", "base", []byte{1}, []byte{2}, nil, []byte{6, 129, 1, 0}, "", nil, ""),
		"generic":          NewGenericLSigPayload("kt", nil, []byte{6, 129, 1, 0}, 0, "", nil, ""),
		"generic-autosalt": NewAutoSaltedGenericLSigPayload("kt", nil, []byte{6, 129, 1, 0}, "", nil, ""),
	}
	for name, payload := range payloads {
		if payload.LogicSigOpcodeProfile != zero {
			t.Errorf("%s payload invented opcode profile %#v", name, payload.LogicSigOpcodeProfile)
		}
		if _, err := scanLogicSigResources(payload, 0); err == nil {
			t.Errorf("%s payload without explicit profile scanned successfully", name)
		}
		if err := payload.SetLogicSigOpcodeProfile(lsigresource.DefaultOpcodeProfile(lsigresource.MaximumDeclaredOpcodeCost), false); err != nil {
			t.Errorf("%s conservative profile: %v", name, err)
		} else if _, err := scanLogicSigResources(payload, 0); err != nil {
			t.Errorf("%s payload with explicit profile did not scan: %v", name, err)
		}
	}
}

func TestScanAutoSaltedResourcesUsesDurableOpcodeProfile(t *testing.T) {
	t.Parallel()

	payload := &Payload{
		Category:              CategoryDSALsig,
		LogicSigBytecode:      make([]byte, 1_800),
		LogicSigOpcodeProfile: lsigresource.DefaultOpcodeProfile(1_750),
	}
	profile, err := scanLogicSigResources(payload, 1_423)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := profile.UsageForPath(lsigresource.PathDefault)
	if err != nil {
		t.Fatal(err)
	}
	if usage != (lsigresource.Usage{ProgramBytes: 1_800, ArgumentBytes: 1_423, MaxOpcodeCost: 1_750}) {
		t.Fatalf("usage = %#v", usage)
	}
}
