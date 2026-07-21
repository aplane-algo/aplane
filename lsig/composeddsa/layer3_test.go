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
		"recipients":         recipientB.String() + "," + recipientA.String(),
		"asset_ids":          "11,7",
		"max_payment_amount": "1000000",
		"max_asset_amount":   "250",
	})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	for _, want := range []string{
		"txn TypeEnum\npushint 1\n==\nbnz __aplane_bounded1_layer3_pay",
		"txn TypeEnum\npushint 4\n==\nbnz __aplane_bounded1_layer3_axfer",
		"txn Receiver\ntxn Sender\n==\nbnz __aplane_bounded1_layer3_pay_amount",
		"txn AssetReceiver\ntxn Sender\n==\nbnz __aplane_bounded1_layer3_asset_constraints",
		"txn XferAsset\ncallsub __aplane_bounded1_layer3_asset_allowed\nassert",
		"txn Amount\npushint 1000000\n<=\nassert",
		"txn AssetAmount\npushint 250\n<=\nassert",
		"pushint 7",
		"pushint 11",
	} {
		if !strings.Contains(teal, want) {
			t.Fatalf("GenerateTEAL() missing %q:\n%s", want, teal)
		}
	}
	if first, second := strings.Index(teal, "pushint 7"), strings.Index(teal, "pushint 11"); first < 0 || second < first {
		t.Fatalf("asset IDs are not canonicalized:\n%s", teal)
	}
	if strings.Count(teal, "__aplane_bounded1_layer3_recipient_yes") != 3 {
		t.Fatalf("recipient membership does not contain exactly two branches and one label:\n%s", teal)
	}
	if provider.Layer3PolicyName() != boundedmeta.Layer3PolicyFixedAllowlist {
		t.Fatalf("Layer3PolicyName() = %q", provider.Layer3PolicyName())
	}
}

func TestFixedAllowlistPolicyOptionalConstraintsAreAbsentWhenOmitted(t *testing.T) {
	teal, err := fixedAllowlistTestProvider().GenerateTEAL([]byte{1}, map[string]string{
		"recipients": types.Address{1}.String(),
	})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	for _, absent := range []string{
		"callsub __aplane_bounded1_layer3_asset_allowed",
		"txn Amount\npushint 1000000",
		"txn AssetAmount\npushint 250",
	} {
		if strings.Contains(teal, absent) {
			t.Fatalf("GenerateTEAL() contains omitted constraint %q:\n%s", absent, teal)
		}
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
		{name: "wrong asset type", policy: &Layer3Policy{Policy: Layer3PolicyFixedAllowlist, RecipientsParameter: "recipients", AssetIDsParameter: "asset_ids"}, params: append(validParams, lsigprovider.ParameterDef{Name: "asset_ids", Type: "uint64"}), want: "must have type uint64[]"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateLayer3Policy(test.policy, test.params, profile)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateLayer3Policy() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestFixedAllowlistPolicyRejectsLayer3GatedRekeyWithoutPay(t *testing.T) {
	profile := &BoundedAuthorizationProfile{
		Contract:     BoundedContractV1,
		SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectAxfer},
		MaxFee:       10_000,
		AdminOperations: []AdminOperationSpec{{
			Kind: AdminOperationRekey, Authorization: AdminAuthorizationSpendingKey, PolicyGate: AdminPolicyGateLayer3,
		}},
	}
	policy := &Layer3Policy{Policy: Layer3PolicyFixedAllowlist, RecipientsParameter: "recipients"}
	params := []lsigprovider.ParameterDef{{
		Name: "recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: BoundedInlineListMax,
	}}
	err := validateLayer3Policy(policy, params, profile)
	if err == nil || !strings.Contains(err.Error(), "requires pay in spend_effects") {
		t.Fatalf("validateLayer3Policy() error = %v, want pay requirement", err)
	}
}

func TestLayer3SchemaRejectsUnknownNestedField(t *testing.T) {
	_, err := ParseTemplateSpec([]byte(`schema_version: 2
derivation_version: 2
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: generated
publisher: test
family: layer3
version: 1
display_name: Test
bounded:
  contract: bounded1
  spend_effects: [pay]
  max_fee: 1000
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
		Layer3: &Layer3Policy{
			Policy: Layer3PolicyFixedAllowlist, RecipientsParameter: "recipients", AssetIDsParameter: "asset_ids",
			MaxPaymentAmountParameter: "max_payment_amount", MaxAssetAmountParameter: "max_asset_amount",
		},
	})
}

func fixedAllowlistTestProfile() *BoundedAuthorizationProfile {
	return &BoundedAuthorizationProfile{
		Contract: BoundedContractV1, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay, txeffects.SpendEffectAxfer}, MaxFee: 10_000,
	}
}

func fixedAllowlistTestParams() []lsigprovider.ParameterDef {
	return []lsigprovider.ParameterDef{
		{Name: "recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: BoundedInlineListMax},
		{Name: "asset_ids", Type: "uint64[]", MinItems: 1, MaxItems: BoundedInlineListMax},
		{Name: "max_payment_amount", Type: "uint64"},
		{Name: "max_asset_amount", Type: "uint64"},
	}
}
