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
	}
	profile, err := scanLogicSigResources(payload, 250+1_423)
	if err != nil {
		t.Fatal(err)
	}
	if profile.ProgramBytes != 250 || profile.Default == nil || profile.Default.ArgumentBytes != 1_423+32+64 || profile.Default.MaxOpcodeCost != 0 {
		t.Fatalf("default resources = %#v", profile)
	}
	if _, err := profile.UsageForPath(lsigresource.PathDefault); err == nil {
		t.Fatal("profile without reviewed opcode ceiling became plannable")
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
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Spend == nil || profile.AdminRekey == nil || profile.Spend.ArgumentBytes != 1_935 || profile.AdminRekey.ArgumentBytes != 2_846 {
		t.Fatalf("bounded profile = %#v", profile)
	}
	if _, err := profile.UsageForPath(lsigresource.PathDefault); err == nil {
		t.Fatal("bounded resource profile exposed a default path")
	}
}

func TestScanAutoSaltedResourcesUsesDurableOpcodeProfile(t *testing.T) {
	t.Parallel()

	payload := &Payload{
		Category:              CategoryDSALsig,
		LogicSigBytecode:      make([]byte, 1_800),
		LogicSigOpcodeProfile: lsigresource.DefaultOpcodeProfile(1_750),
	}
	profile, err := scanLogicSigResources(payload, 1_800+1_423)
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
