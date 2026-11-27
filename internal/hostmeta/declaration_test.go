// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package hostmeta

import "testing"

func TestDeclarationProjectsTheStoredContract(t *testing.T) {
	metadata := &Metadata{
		Contract: BoundedContract,
		Bounds:   &Bounds{SpendEffects: []string{SpendEffectPay, SpendEffectAxfer}, MaxFee: new(uint64(5_000)), Layer3Policy: Layer3PolicyFixedAllowlist},
		Rekey:    RekeyRefused,
		Cosigner: &CosignerAuthorization{ComponentKeyType: DefaultCosignerComponentKeyType, RequiredOn: []string{PathSpend}},
	}
	refused, err := metadata.Declaration()
	if err != nil {
		t.Fatal(err)
	}
	if refused.Rekey != RekeyRefused || refused.Bounds == nil || refused.Bounds.MaxFee == nil || *refused.Bounds.MaxFee != 5_000 || refused.Bounds.Layer3Policy != Layer3PolicyFixedAllowlist {
		t.Fatalf("refused declaration = %+v", refused)
	}
	if refused.Cosigner == nil || refused.Cosigner.ComponentKeyType != DefaultCosignerComponentKeyType || !refused.AllowsSpendEffect(SpendEffectAxfer) || refused.AllowsSpendEffect(SpendEffectAssetOptIn) {
		t.Fatalf("refused declaration = %+v", refused)
	}
	// The declaration is a copy: changing it must not reach the stored contract.
	refused.Bounds.SpendEffects[0] = "changed"
	refused.Cosigner.RequiredOn[0] = "changed"
	if metadata.Bounds.SpendEffects[0] != SpendEffectPay || metadata.Cosigner.RequiredOn[0] != PathSpend {
		t.Fatal("the declaration shares storage with the metadata")
	}

	metadata.Cosigner = nil
	metadata.Rekey = RekeySpendingKey
	spending, err := metadata.Declaration()
	if err != nil || spending.Rekey != RekeySpendingKey || spending.Cosigner != nil {
		t.Fatalf("spending-key declaration = %+v, %v", spending, err)
	}

	if _, err := (*Metadata)(nil).Declaration(); err == nil {
		t.Fatal("a nil contract produced a declaration")
	}
}
