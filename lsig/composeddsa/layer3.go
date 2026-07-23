// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/merkleallowlist"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

const (
	// Layer3PolicyFixedAllowlist is the framework-owned bounded1 spending
	// policy. It compiles all membership checks inline and uses no runtime
	// witness or signer-generated argument.
	Layer3PolicyFixedAllowlist = "fixed_allowlist"

	// Layer3PolicyMerkleAllowlist is the framework-owned bounded1 spending
	// policy for large recipient sets. Membership is proven by a fixed-size,
	// signer-derived Merkle witness.
	Layer3PolicyMerkleAllowlist = "merkle_allowlist"

	// BoundedInlineListMax is the audited maximum for each framework-owned
	// inline membership list.
	BoundedInlineListMax = 30
)

// Layer3Policy binds a framework-owned policy to typed creation parameters.
// Empty optional parameter names mean that constraint is not compiled.
type Layer3Policy struct {
	Policy                    string `json:"policy"`
	RecipientsParameter       string `json:"recipients_parameter"`
	AssetIDsParameter         string `json:"asset_ids_parameter,omitempty"`
	MaxPaymentAmountParameter string `json:"max_payment_amount_parameter,omitempty"`
	MaxAssetAmountParameter   string `json:"max_asset_amount_parameter,omitempty"`
}

func cloneLayer3Policy(policy *Layer3Policy) *Layer3Policy {
	if policy == nil {
		return nil
	}
	cloned := *policy
	return &cloned
}

func layer3PolicyFromTemplate(spec *generictemplate.BoundedAuthorizationSpec, params []lsigprovider.ParameterDef, profile *BoundedAuthorizationProfile) (*Layer3Policy, error) {
	if spec == nil || spec.Layer3 == nil {
		return nil, nil
	}
	layer3 := &Layer3Policy{
		Policy:                    spec.Layer3.Policy,
		RecipientsParameter:       spec.Layer3.RecipientsParameter,
		AssetIDsParameter:         spec.Layer3.AssetIDsParameter,
		MaxPaymentAmountParameter: spec.Layer3.MaxPaymentAmountParameter,
		MaxAssetAmountParameter:   spec.Layer3.MaxAssetAmountParameter,
	}
	if err := validateLayer3Policy(layer3, params, profile); err != nil {
		return nil, fmt.Errorf("invalid bounded.layer3: %w", err)
	}
	return layer3, nil
}

func validateLayer3Policy(policy *Layer3Policy, params []lsigprovider.ParameterDef, profile *BoundedAuthorizationProfile) error {
	if policy == nil {
		return nil
	}
	if policy.Policy != Layer3PolicyFixedAllowlist && policy.Policy != Layer3PolicyMerkleAllowlist {
		return fmt.Errorf("unsupported policy %q", policy.Policy)
	}
	if profile == nil {
		return fmt.Errorf("framework-owned Layer-3 policy requires bounded1")
	}
	if policy.Policy == Layer3PolicyMerkleAllowlist &&
		(policy.AssetIDsParameter != "" || policy.MaxPaymentAmountParameter != "" || policy.MaxAssetAmountParameter != "") {
		return fmt.Errorf("merkle_allowlist supports only recipients_parameter")
	}

	byName := make(map[string]lsigprovider.ParameterDef, len(params))
	for _, param := range params {
		byName[param.Name] = param
	}
	used := make(map[string]struct{}, len(params))
	listMax := BoundedInlineListMax
	if policy.Policy == Layer3PolicyMerkleAllowlist {
		listMax = merkleallowlist.MaxItems
	}
	if err := requireLayer3Parameter(byName, used, policy.RecipientsParameter, "recipients_parameter", "address[]", true, true, listMax); err != nil {
		return err
	}
	if err := requireLayer3Parameter(byName, used, policy.AssetIDsParameter, "asset_ids_parameter", "uint64[]", false, true, BoundedInlineListMax); err != nil {
		return err
	}
	if err := requireLayer3Parameter(byName, used, policy.MaxPaymentAmountParameter, "max_payment_amount_parameter", "uint64", false, false, 0); err != nil {
		return err
	}
	if err := requireLayer3Parameter(byName, used, policy.MaxAssetAmountParameter, "max_asset_amount_parameter", "uint64", false, false, 0); err != nil {
		return err
	}
	for _, param := range params {
		if _, ok := used[param.Name]; !ok {
			return fmt.Errorf("parameter %q is not used by framework policy %q", param.Name, policy.Policy)
		}
	}

	allowsPay := profileAllowsSpendEffect(profile, txeffects.SpendEffectPay)
	allowsAxfer := profileAllowsSpendEffect(profile, txeffects.SpendEffectAxfer, txeffects.SpendEffectAssetOptIn)
	if boundedRekeyUsesLayer3(profile) && !allowsPay {
		return fmt.Errorf("%s Layer-3-gated rekey requires pay in spend_effects", policy.Policy)
	}
	if !allowsPay && policy.MaxPaymentAmountParameter != "" {
		return fmt.Errorf("max_payment_amount_parameter requires pay in spend_effects")
	}
	if !allowsAxfer && (policy.AssetIDsParameter != "" || policy.MaxAssetAmountParameter != "") {
		return fmt.Errorf("asset options require axfer in spend_effects")
	}
	return nil
}

func requireLayer3Parameter(byName map[string]lsigprovider.ParameterDef, used map[string]struct{}, name, field, wantType string, required, list bool, listMax int) error {
	if name == "" {
		if required {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
	param, ok := byName[name]
	if !ok {
		return fmt.Errorf("%s references unknown parameter %q", field, name)
	}
	if param.Type != wantType {
		return fmt.Errorf("%s parameter %q must have type %s, got %s", field, name, wantType, param.Type)
	}
	if required && !param.Required {
		return fmt.Errorf("%s parameter %q must be required", field, name)
	}
	if list {
		if param.MinItems < 1 {
			return fmt.Errorf("%s parameter %q must set min_items >= 1", field, name)
		}
		if param.MaxItems < 1 || param.MaxItems > listMax {
			return fmt.Errorf("%s parameter %q max_items must be between 1 and %d", field, name, listMax)
		}
	}
	used[name] = struct{}{}
	return nil
}

func profileAllowsSpendEffect(profile *BoundedAuthorizationProfile, wanted ...txeffects.SpendEffect) bool {
	for _, effect := range profile.SpendEffects {
		for _, want := range wanted {
			if effect == want {
				return true
			}
		}
	}
	return false
}

func (c *ComposedDSA) renderLayer3Policy(params map[string]string, profile *BoundedAuthorizationProfile) (string, error) {
	if err := validateLayer3Policy(c.layer3, c.paramsWithoutAdminKey(), profile); err != nil {
		return "", err
	}
	if c.layer3.Policy == Layer3PolicyMerkleAllowlist {
		return c.renderMerkleAllowlist(params, profile)
	}
	if c.layer3.Policy != Layer3PolicyFixedAllowlist {
		return "", fmt.Errorf("unsupported Layer-3 policy %q", c.layer3.Policy)
	}

	recipients := splitCanonicalList(params[c.layer3.RecipientsParameter])
	assetIDs := splitCanonicalList(params[c.layer3.AssetIDsParameter])
	var b strings.Builder
	b.WriteString("// === framework-owned fixed allowlist ===\n")
	if profileAllowsSpendEffect(profile, txeffects.SpendEffectPay) {
		b.WriteString("txn TypeEnum\npushint 1\n==\nbnz __aplane_bounded1_layer3_pay\n")
	}
	if profileAllowsSpendEffect(profile, txeffects.SpendEffectAxfer, txeffects.SpendEffectAssetOptIn) {
		b.WriteString("txn TypeEnum\npushint 4\n==\nbnz __aplane_bounded1_layer3_axfer\n")
	}
	b.WriteString("err\n\n")

	if profileAllowsSpendEffect(profile, txeffects.SpendEffectPay) {
		b.WriteString("__aplane_bounded1_layer3_pay:\n")
		b.WriteString("txn Receiver\ntxn Sender\n==\nbnz __aplane_bounded1_layer3_pay_amount\n")
		b.WriteString("txn Receiver\ncallsub __aplane_bounded1_layer3_recipient_allowed\nassert\n")
		b.WriteString("__aplane_bounded1_layer3_pay_amount:\n")
		writeOptionalAmountLimit(&b, "Amount", params[c.layer3.MaxPaymentAmountParameter])
		b.WriteString("b __aplane_bounded1_layer3_done\n\n")
	}

	if profileAllowsSpendEffect(profile, txeffects.SpendEffectAxfer, txeffects.SpendEffectAssetOptIn) {
		b.WriteString("__aplane_bounded1_layer3_axfer:\n")
		b.WriteString("txn AssetReceiver\ntxn Sender\n==\nbnz __aplane_bounded1_layer3_asset_constraints\n")
		b.WriteString("txn AssetReceiver\ncallsub __aplane_bounded1_layer3_recipient_allowed\nassert\n")
		b.WriteString("__aplane_bounded1_layer3_asset_constraints:\n")
		if len(assetIDs) > 0 {
			b.WriteString("txn XferAsset\ncallsub __aplane_bounded1_layer3_asset_allowed\nassert\n")
		}
		writeOptionalAmountLimit(&b, "AssetAmount", params[c.layer3.MaxAssetAmountParameter])
		b.WriteString("b __aplane_bounded1_layer3_done\n\n")
	}

	if err := writeInlineAddressMembership(&b, recipients); err != nil {
		return "", err
	}
	if len(assetIDs) > 0 {
		writeInlineUintMembership(&b, assetIDs)
	}
	b.WriteString("__aplane_bounded1_layer3_done:\n")
	return b.String(), nil
}

func (c *ComposedDSA) renderMerkleAllowlist(params map[string]string, profile *BoundedAuthorizationProfile) (string, error) {
	root, err := merkleallowlist.RootHexFromRecipientsParam(params[c.layer3.RecipientsParameter])
	if err != nil {
		return "", fmt.Errorf("compute recipient Merkle root: %w", err)
	}
	layout, err := c.validatedSignatureArgLayout()
	if err != nil {
		return "", err
	}
	proofIndex := -1
	for i, arg := range c.derivedArgs {
		if arg.Kind == boundedmeta.DerivedArgMerkleProof && arg.Parameter == c.layer3.RecipientsParameter {
			proofIndex = layout.Count + i
			break
		}
	}
	if proofIndex < 0 {
		return "", fmt.Errorf("merkle proof argument has no bounded argument slot")
	}

	var b strings.Builder
	b.WriteString("// === framework-owned Merkle allowlist ===\n")
	if profileAllowsSpendEffect(profile, txeffects.SpendEffectPay) {
		b.WriteString("txn TypeEnum\npushint 1\n==\nbnz __aplane_bounded1_merkle_pay\n")
	}
	if profileAllowsSpendEffect(profile, txeffects.SpendEffectAxfer, txeffects.SpendEffectAssetOptIn) {
		b.WriteString("txn TypeEnum\npushint 4\n==\nbnz __aplane_bounded1_merkle_axfer\n")
	}
	b.WriteString("err\n\n")
	if profileAllowsSpendEffect(profile, txeffects.SpendEffectPay) {
		b.WriteString("__aplane_bounded1_merkle_pay:\ntxn Receiver\ntxn Sender\n==\nbnz __aplane_bounded1_merkle_done\ntxn Receiver\ncallsub __aplane_bounded1_merkle_verify\nassert\nb __aplane_bounded1_merkle_done\n\n")
	}
	if profileAllowsSpendEffect(profile, txeffects.SpendEffectAxfer, txeffects.SpendEffectAssetOptIn) {
		b.WriteString("__aplane_bounded1_merkle_axfer:\ntxn AssetReceiver\ntxn Sender\n==\nbnz __aplane_bounded1_merkle_done\ntxn AssetReceiver\ncallsub __aplane_bounded1_merkle_verify\nassert\nb __aplane_bounded1_merkle_done\n\n")
	}
	b.WriteString("__aplane_bounded1_merkle_verify:\n")
	b.WriteString(fmt.Sprintf("arg %d\nlen\npushint %d\n==\nassert\n", proofIndex, merkleallowlist.ProofSize))
	b.WriteString("pushbytes 0x00\nswap\nconcat\nsha256\n")
	for offset := 0; offset < merkleallowlist.ProofSize; offset += 32 {
		b.WriteString(fmt.Sprintf("arg %d\npushint %d\npushint 32\nextract3\ncallsub __aplane_bounded1_merkle_combine\n", proofIndex, offset))
	}
	b.WriteString("pushbytes 0x" + root + "\n==\nretsub\n\n")
	b.WriteString("__aplane_bounded1_merkle_combine:\ndup2\nb<\nbnz __aplane_bounded1_merkle_ordered\nswap\n__aplane_bounded1_merkle_ordered:\nconcat\npushbytes 0x01\nswap\nconcat\nsha256\nretsub\n\n")
	b.WriteString("__aplane_bounded1_merkle_done:\n")
	return b.String(), nil
}

func (c *ComposedDSA) validateFrameworkLayer3Arguments() error {
	if c.layer3 == nil {
		return nil
	}
	switch c.layer3.Policy {
	case Layer3PolicyFixedAllowlist:
		if len(c.derivedArgs) != 0 {
			return fmt.Errorf("fixed_allowlist does not accept derived arguments")
		}
	case Layer3PolicyMerkleAllowlist:
		if len(c.derivedArgs) != 1 {
			return fmt.Errorf("merkle_allowlist requires exactly one derived Merkle proof argument")
		}
		arg := c.derivedArgs[0]
		if arg.Kind != boundedmeta.DerivedArgMerkleProof || arg.Parameter != c.layer3.RecipientsParameter || arg.MaxSize != boundedmeta.MerkleProofSize {
			return fmt.Errorf("merkle_allowlist derived argument must be a %d-byte %s for parameter %q", boundedmeta.MerkleProofSize, boundedmeta.DerivedArgMerkleProof, c.layer3.RecipientsParameter)
		}
	}
	return nil
}

func (c *ComposedDSA) paramsWithoutAdminKey() []lsigprovider.ParameterDef {
	params := make([]lsigprovider.ParameterDef, 0, len(c.params))
	for _, param := range c.params {
		if param.Name != BoundedAdminPublicKeyParameter && param.Name != BoundedSentryPublicKeyParameter {
			params = append(params, param)
		}
	}
	return params
}

func writeOptionalAmountLimit(b *strings.Builder, field, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	b.WriteString("txn " + field + "\n")
	b.WriteString("pushint " + strings.TrimSpace(value) + "\n<=\nassert\n")
}

func writeInlineAddressMembership(b *strings.Builder, values []string) error {
	b.WriteString("__aplane_bounded1_layer3_recipient_allowed:\n")
	for _, value := range values {
		address, err := types.DecodeAddress(value)
		if err != nil {
			return fmt.Errorf("decode canonical recipient %q: %w", value, err)
		}
		b.WriteString("dup\npushbytes 0x" + fmt.Sprintf("%x", address[:]) + "\n==\n")
		b.WriteString("bnz __aplane_bounded1_layer3_recipient_yes\n")
	}
	b.WriteString("pop\npushint 0\nretsub\n")
	b.WriteString("__aplane_bounded1_layer3_recipient_yes:\npop\npushint 1\nretsub\n\n")
	return nil
}

func writeInlineUintMembership(b *strings.Builder, values []string) {
	b.WriteString("__aplane_bounded1_layer3_asset_allowed:\n")
	for _, value := range values {
		b.WriteString("dup\npushint " + value + "\n==\n")
		b.WriteString("bnz __aplane_bounded1_layer3_asset_yes\n")
	}
	b.WriteString("pop\npushint 0\nretsub\n")
	b.WriteString("__aplane_bounded1_layer3_asset_yes:\npop\npushint 1\nretsub\n\n")
}
