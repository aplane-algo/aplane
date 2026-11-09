// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// TestCosignedSignerCacheViewDelegation pins the engine→cosigned cache-view
// wiring: each SignerCacheView method must surface the matching signer-cache
// field. A transposed or mistargeted delegation here would only fail at
// cosigned submit time ("missing cosigner_component_key_type metadata" or wrong
// dummy budgeting), so it is asserted directly.
func TestCosignedSignerCacheViewDelegation(t *testing.T) {
	addr := testAddress(1).String()
	nativeFalconAddr := testAddress(2).String()
	cosignerHex := testCosignerPublicKeyHex(0xd6)
	nativefalcon.RegisterClient()

	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(addr, "aplane.falcon1024.v1")
	signerCache.SetSigningFlowForAddress(addr, signerapi.SigningFlowCosigned1)
	signerCache.SetBoundedContractForAddress(addr, signerapi.BoundedContractBounded2)
	signerCache.SetBoundedMaxFeeForAddress(addr, 10_000)
	signerCache.SetCosignerComponentKeyTypeForAddress(addr, witness.Falcon1024V1)
	signerCache.SetCosignerPublicKeyForAddress(addr, cosignerHex)
	signerCache.SetLogicSigResourceProfile(addr, lsigresource.Profile{ProgramBytes: 1_500, Default: &lsigresource.PathProfile{MaxOpcodeCost: 1}})
	signerCache.AddAddress(nativeFalconAddr, nativefalcon.KeyType)

	eng, err := NewEngine("testnet", WithSignerCache(signerCache))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	view := cosignedSignerCacheView{eng.Core}
	if got, ok := view.AuthorizationKind(nativeFalconAddr); !ok || got != string(algorithm.AuthorizationNativePQ) {
		t.Fatalf("AuthorizationKind(native Falcon) = %q/%v, want %s/true", got, ok, algorithm.AuthorizationNativePQ)
	}

	if got := view.SigningFlow(addr); got != signerapi.SigningFlowCosigned1 {
		t.Fatalf("SigningFlow() = %q, want %q", got, signerapi.SigningFlowCosigned1)
	}
	if got, ok := view.BoundedContract(addr); !ok || got != signerapi.BoundedContractBounded2 {
		t.Fatalf("BoundedContract() = %q/%v", got, ok)
	}
	if got, ok := view.BoundedMaxFee(addr); !ok || got != 10_000 {
		t.Fatalf("BoundedMaxFee() = %d/%v", got, ok)
	}
	if got, ok := view.CosignerComponentKeyType(addr); !ok || got != witness.Falcon1024V1 {
		t.Fatalf("CosignerComponentKeyType() = %q/%v, want %s/true", got, ok, witness.Falcon1024V1)
	}
	if got, ok := view.CosignerPublicKey(addr); !ok || got != cosignerHex {
		t.Fatalf("CosignerPublicKey() = %q/%v, want %s/true", got, ok, cosignerHex)
	}
	if profile, ok := view.LogicSigResourceProfile(addr); !ok || profile.ProgramBytes != 1_500 {
		t.Fatalf("LogicSigResourceProfile() = %+v/%v, want profile", profile, ok)
	}

	unknown := testAddress(9).String()
	if got := view.SigningFlow(unknown); got != "" {
		t.Fatalf("SigningFlow(unknown) = %q, want empty", got)
	}
	if _, ok := view.CosignerComponentKeyType(unknown); ok {
		t.Fatal("CosignerComponentKeyType(unknown) ok = true, want false")
	}
	if _, ok := view.LogicSigResourceProfile(unknown); ok {
		t.Fatal("LogicSigResourceProfile(unknown) ok = true, want false")
	}
}
