// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/txeffects"
)

func TestFixedAllowlistPolicyRendersCompleteSpendDispatch(t *testing.T) {
	provider := fixedAllowlistTestProvider()
	recipientA := types.Address{1}
	recipientB := types.Address{2}
	teal, err := provider.GenerateTEAL([]byte{1}, map[string]string{
		"recipients": recipientB.String() + "," + recipientA.String(),
	})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	for _, want := range []string{
		"txn TypeEnum\npushint 1\n==\nbnz __aplane_bounded1_layer3_pay",
		"txn TypeEnum\npushint 4\n==\nbnz __aplane_bounded1_layer3_axfer",
		"txn Receiver\ntxn Sender\n==\nbnz __aplane_bounded1_layer3_pay_amount",
		"txn AssetReceiver\ntxn Sender\n==\nbnz __aplane_bounded1_layer3_asset_constraints",
		"txn Receiver\ncallsub __aplane_bounded1_layer3_recipient_allowed\nassert",
		"txn AssetReceiver\ncallsub __aplane_bounded1_layer3_recipient_allowed\nassert",
	} {
		if !strings.Contains(teal, want) {
			t.Fatalf("GenerateTEAL() missing %q:\n%s", want, teal)
		}
	}
	if strings.Count(teal, "__aplane_bounded1_layer3_recipient_yes") != 3 {
		t.Fatalf("recipient membership does not contain exactly two branches and one label:\n%s", teal)
	}
	if provider.Layer3PolicyName() != boundedmeta.Layer3PolicyFixedAllowlist {
		t.Fatalf("Layer3PolicyName() = %q", provider.Layer3PolicyName())
	}
}

// An asset ID names an asset on one network only and a base-unit amount means
// nothing across assets, but one program runs on every network. The fixed
// allowlist therefore compiles no asset or amount check of its own.
func TestFixedAllowlistPolicyCompilesNoAssetOrAmountConstraint(t *testing.T) {
	teal, err := fixedAllowlistTestProvider().GenerateTEAL([]byte{1}, map[string]string{
		"recipients": types.Address{1}.String(),
	})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	policy := teal[strings.Index(teal, "// === framework-owned fixed allowlist ==="):]
	for _, absent := range []string{"txn XferAsset", "txn Amount", "txn AssetAmount"} {
		if strings.Contains(policy, absent) {
			t.Fatalf("allowlist policy contains %q:\n%s", absent, policy)
		}
	}
}

func TestFixedAllowlistTemplateRejectsAssetAndAmountOptions(t *testing.T) {
	for _, field := range []string{"asset_ids_parameter", "max_payment_amount_parameter", "max_asset_amount_parameter"} {
		t.Run(field, func(t *testing.T) {
			_, err := ParseTemplateSpec([]byte(`schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: generated
publisher: test
family: fixed
version: 1
display_name: Test
valid_rekey_target: true
description: Test
bounded:
  contract: bounded2
  spend_effects: [pay, axfer]
  max_fee: 10000
  rekey: refused
  layer3:
    policy: fixed_allowlist
    recipients_parameter: recipients
    ` + field + `: limit
parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 30
`))
			if err == nil || !strings.Contains(err.Error(), "field "+field+" not found") {
				t.Fatalf("ParseTemplateSpec() error = %v, want rejection of %s", err, field)
			}
		})
	}
}

func TestFixedAllowlistPolicyRejectsUnsafeSchema(t *testing.T) {
	profile := fixedAllowlistTestProfile()
	validParams := []lsigprovider.ParameterDef{{Name: "recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: BoundedInlineListMax}}
	valid := &Layer3Policy{Policy: Layer3PolicyFixedAllowlist, RecipientsParameter: "recipients"}
	tests := []struct {
		name   string
		policy *Layer3Policy
		params []lsigprovider.ParameterDef
		want   string
	}{
		{name: "unknown policy", policy: &Layer3Policy{Policy: "customish", RecipientsParameter: "recipients"}, params: validParams, want: "unsupported policy"},
		{name: "missing recipients", policy: &Layer3Policy{Policy: Layer3PolicyFixedAllowlist}, params: validParams, want: "recipients_parameter is required"},
		{name: "optional recipients", policy: valid, params: []lsigprovider.ParameterDef{{Name: "recipients", Type: "address[]", MinItems: 1, MaxItems: 30}}, want: "must be required"},
		{name: "unbounded recipients", policy: valid, params: []lsigprovider.ParameterDef{{Name: "recipients", Type: "address[]", Required: true, MinItems: 1}}, want: "max_items"},
		{name: "over audited maximum", policy: valid, params: []lsigprovider.ParameterDef{{Name: "recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: BoundedInlineListMax + 1}}, want: "max_items"},
		{name: "unused parameter", policy: valid, params: append(validParams, lsigprovider.ParameterDef{Name: "hidden", Type: "uint64"}), want: "is not used"},
		{name: "wrong recipients type", policy: valid, params: []lsigprovider.ParameterDef{{Name: "recipients", Type: "uint64[]", Required: true, MinItems: 1, MaxItems: 30}}, want: "must have type address[]"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateLayer3Policy(test.policy, test.params, profile, false)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateLayer3Policy() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestMerkleAllowlistPolicyRequiresClosedProofContract(t *testing.T) {
	profile := fixedAllowlistTestProfile()
	policy := &Layer3Policy{Policy: Layer3PolicyMerkleAllowlist, RecipientsParameter: "recipients"}
	params := []lsigprovider.ParameterDef{{Name: "recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: 65536}}
	if err := validateLayer3Policy(policy, params, profile, false); err != nil {
		t.Fatalf("validateLayer3Policy() error = %v", err)
	}

	err := validateLayer3Policy(policy, append(params, lsigprovider.ParameterDef{Name: "limit", Type: "uint64"}), profile, false)
	if err == nil || !strings.Contains(err.Error(), "is not used") {
		t.Fatalf("validateLayer3Policy(extra parameter) error = %v", err)
	}

	provider := &ComposedDSA{
		layer3: policy,
		derivedArgs: []boundedmeta.DerivedArg{{
			Name: "proof", Kind: boundedmeta.DerivedArgMerkleProof, Parameter: "recipients", MaxSize: boundedmeta.MerkleProofSize,
		}},
	}
	if err := provider.validateFrameworkLayer3Arguments(); err != nil {
		t.Fatalf("validateFrameworkLayer3Arguments() error = %v", err)
	}
	provider.derivedArgs = nil
	if err := provider.validateFrameworkLayer3Arguments(); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("validateFrameworkLayer3Arguments(no proof) error = %v", err)
	}
}

// A rekey never reaches Layer 3, so the allowlist asks nothing of the rekey
// setting: a spending-key rekey needs no pay, which only the spend path reads.
func TestFixedAllowlistPolicyAcceptsEitherRekeySettingWithoutPay(t *testing.T) {
	policy := &Layer3Policy{Policy: Layer3PolicyFixedAllowlist, RecipientsParameter: "recipients"}
	params := []lsigprovider.ParameterDef{{
		Name: "recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: BoundedInlineListMax,
	}}
	for _, rekey := range []boundedmeta.RekeySetting{boundedmeta.RekeySpendingKey, boundedmeta.RekeyRefused} {
		profile := &BoundedAuthorizationProfile{
			Contract:     BoundedContract,
			SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectAxfer},
			MaxFee:       new(uint64(10_000)),
			Rekey:        rekey,
		}
		if err := validateLayer3Policy(policy, params, profile, false); err != nil {
			t.Fatalf("validateLayer3Policy(rekey %s) error = %v", rekey, err)
		}
	}
}

func TestLayer3SchemaRejectsUnknownNestedField(t *testing.T) {
	_, err := ParseTemplateSpec([]byte(`schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: generated
publisher: test
family: layer3
version: 1
display_name: Test
valid_rekey_target: true
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 1000
  rekey: refused
  layer3:
    policy: fixed_allowlist
    recipients_parameter: recipients
    surprise: true
parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 30
`))
	if err == nil || !strings.Contains(err.Error(), "field surprise not found") {
		t.Fatalf("ParseTemplateSpec() error = %v, want strict nested-field rejection", err)
	}
}

func fixedAllowlistTestProvider() *ComposedDSA {
	return NewComposedDSA(Config{
		KeyType: "aplane.test-fixed-allowlist.v1", BaseKeyType: "aplane.falcon1024.v1",
		FamilyName: "aplane.test", Version: 1, Ops: boundedTestOps{}, SaltStyle: lsigsalt.StylePushbytes,
		TemplateMode: "generated", Params: fixedAllowlistTestParams(), Bounded: fixedAllowlistTestProfile(),
		Layer3: &Layer3Policy{Policy: Layer3PolicyFixedAllowlist, RecipientsParameter: "recipients"},
	})
}

func fixedAllowlistTestProfile() *BoundedAuthorizationProfile {
	return &BoundedAuthorizationProfile{
		Contract: BoundedContract, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay, txeffects.SpendEffectAxfer}, MaxFee: new(uint64(10_000)),
		Rekey: boundedmeta.RekeyRefused,
	}
}

func fixedAllowlistTestParams() []lsigprovider.ParameterDef {
	return []lsigprovider.ParameterDef{
		{Name: "recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: BoundedInlineListMax},
	}
}
