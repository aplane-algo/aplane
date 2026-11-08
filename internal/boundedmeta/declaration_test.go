// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedmeta

import (
	"strings"
	"testing"
)

func TestDeclarationProjectsTheStoredContract(t *testing.T) {
	metadata := &Metadata{
		Contract:     ContractV1,
		SpendEffects: []string{SpendEffectPay, SpendEffectAxfer},
		MaxFee:       5_000,
		Layer3Policy: Layer3PolicyFixedAllowlist,
		Cosigner:     &CosignerAuthorization{ComponentKeyType: CosignerComponentKeyTypeV1, RequiredOn: []string{PathSpend}},
	}
	refused, err := metadata.Declaration()
	if err != nil {
		t.Fatal(err)
	}
	if refused.Rekey != RekeyRefused || refused.MaxFee == nil || *refused.MaxFee != 5_000 || refused.Layer3Policy != Layer3PolicyFixedAllowlist {
		t.Fatalf("refused declaration = %+v", refused)
	}
	if refused.Cosigner == nil || refused.Cosigner.ComponentKeyType != CosignerComponentKeyTypeV1 || !refused.AllowsSpendEffect(SpendEffectAxfer) || refused.AllowsSpendEffect(SpendEffectAssetOptIn) {
		t.Fatalf("refused declaration = %+v", refused)
	}
	// The declaration is a copy: changing it must not reach the stored contract.
	refused.SpendEffects[0] = "changed"
	refused.Cosigner.RequiredOn[0] = "changed"
	if metadata.SpendEffects[0] != SpendEffectPay || metadata.Cosigner.RequiredOn[0] != PathSpend {
		t.Fatal("the declaration shares storage with the metadata")
	}

	metadata.Cosigner = nil
	metadata.AdminOperations = []AdminOperation{{Kind: AdminOperationRekey, Authorization: AdminAuthorizationSpend, PolicyGate: PolicyGateLayer3}}
	spending, err := metadata.Declaration()
	if err != nil || spending.Rekey != RekeySpendingKey || spending.Cosigner != nil {
		t.Fatalf("spending-key declaration = %+v, %v", spending, err)
	}

	for name, operation := range map[string]AdminOperation{
		"unknown kind":          {Kind: "freeze", Authorization: AdminAuthorizationSpend},
		"unknown authorization": {Kind: AdminOperationRekey, Authorization: "admin_key"},
	} {
		metadata.AdminOperations = []AdminOperation{operation}
		if _, err := metadata.Declaration(); err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("%s: Declaration() error = %v", name, err)
		}
	}
	if _, err := (*Metadata)(nil).Declaration(); err == nil {
		t.Fatal("a nil contract produced a declaration")
	}
}
