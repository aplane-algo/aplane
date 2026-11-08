// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/merkleallowlist"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

const (
	// Layer3PolicyFixedAllowlist is the framework-owned bounded spending
	// policy. It compiles all membership checks inline and uses no runtime
	// witness or signer-generated argument.
	Layer3PolicyFixedAllowlist = "fixed_allowlist"

	// Layer3PolicyMerkleAllowlist is the framework-owned bounded spending
	// policy for large recipient sets. Membership is proven by a fixed-size,
	// signer-derived Merkle witness.
	Layer3PolicyMerkleAllowlist = "merkle_allowlist"

	// Layer3PolicyTimelock requires FirstValid >= unlock_round and reads no
	// recipient list.
	Layer3PolicyTimelock = "timelock"

	// Layer3PolicyFixedAllowlistTimelock applies the timelock, then the inline
	// recipient check.
	Layer3PolicyFixedAllowlistTimelock = "fixed_allowlist_timelock"

	// Layer3PolicyMerkleAllowlistTimelock applies the timelock, then the Merkle
	// recipient check.
	Layer3PolicyMerkleAllowlistTimelock = "merkle_allowlist_timelock"

	// Layer3PolicyNone compiles no Layer 3: the bounded envelope and the spending
	// signature are the whole spending rule. Only the general type offers it.
	Layer3PolicyNone = boundedmeta.Layer3PolicyNone

	// BoundedInlineListMax is the audited maximum for each framework-owned
	// inline membership list.
	BoundedInlineListMax = 30
)

// Layer3Policy binds a framework-owned policy to the parameters it reads.
// Recipient addresses are network-independent. An unlock round compiles the same
// way everywhere but means a different time on each network, and it does not bind
// the program to one. Asset and amount limits belong to per-network signer policy.
//
// This struct is hashed into the provider fingerprint. UnlockRoundParameter must
// stay omitempty so that policies without one keep their fingerprints.
type Layer3Policy struct {
	Policy               string `json:"policy"`
	RecipientsParameter  string `json:"recipients_parameter"`
	UnlockRoundParameter string `json:"unlock_round_parameter,omitempty"`
}

// layer3PolicyRules is what a framework policy compiles. The composer treats the
// timelock and the recipient check as independent, so a combined policy is a
// timelock followed by the same allowlist a plain policy renders.
type layer3PolicyRules struct {
	inlineList bool
	merkleList bool
	timelock   bool
}

func (rules layer3PolicyRules) hasList() bool {
	return rules.inlineList || rules.merkleList
}

func rulesForLayer3Policy(policy string) (layer3PolicyRules, bool) {
	switch policy {
	case Layer3PolicyFixedAllowlist:
		return layer3PolicyRules{inlineList: true}, true
	case Layer3PolicyMerkleAllowlist:
		return layer3PolicyRules{merkleList: true}, true
	case Layer3PolicyTimelock:
		return layer3PolicyRules{timelock: true}, true
	case Layer3PolicyFixedAllowlistTimelock:
		return layer3PolicyRules{inlineList: true, timelock: true}, true
	case Layer3PolicyMerkleAllowlistTimelock:
		return layer3PolicyRules{merkleList: true, timelock: true}, true
	case Layer3PolicyNone:
		return layer3PolicyRules{}, true
	}
	return layer3PolicyRules{}, false
}

func cloneLayer3Policy(policy *Layer3Policy) *Layer3Policy {
	if policy == nil {
		return nil
	}
	cloned := *policy
	return &cloned
}

func layer3PolicyFromTemplate(spec *generictemplate.BoundedAuthorizationSpec, params []lsigprovider.ParameterDef, profile *BoundedAuthorizationProfile, hasAuthorTEAL bool) (*Layer3Policy, error) {
	if spec == nil || spec.Layer3 == nil {
		return nil, nil
	}
	if len(spec.RuntimeArgs) != 0 && !hasAuthorTEAL {
		return nil, fmt.Errorf("invalid bounded.layer3: %s has no author TEAL to read runtime arguments", spec.Layer3.Policy)
	}
	layer3 := &Layer3Policy{
		Policy:               spec.Layer3.Policy,
		RecipientsParameter:  spec.Layer3.RecipientsParameter,
		UnlockRoundParameter: spec.Layer3.UnlockRoundParameter,
	}
	if err := validateLayer3Policy(layer3, params, profile, hasAuthorTEAL); err != nil {
		return nil, fmt.Errorf("invalid bounded.layer3: %w", err)
	}
	return layer3, nil
}

// validateLayer3Policy checks a framework policy. Author TEAL may run after a
// plain allowlist and read its own parameters, so a parameter the policy does not
// use is an error only when there is no author TEAL to use it. Timelock policies
// take no author TEAL: an author who wants a list and custom time conditions uses
// a plain allowlist and writes those conditions in the TEAL.
func validateLayer3Policy(policy *Layer3Policy, params []lsigprovider.ParameterDef, profile *BoundedAuthorizationProfile, hasAuthorTEAL bool) error {
	if policy == nil {
		return nil
	}
	rules, ok := rulesForLayer3Policy(policy.Policy)
	if !ok {
		return fmt.Errorf("unsupported policy %q", policy.Policy)
	}
	if profile == nil {
		return fmt.Errorf("framework-owned Layer-3 policy requires a bounded profile")
	}
	if rules.timelock && hasAuthorTEAL {
		return fmt.Errorf("policy %q does not accept author TEAL", policy.Policy)
	}
	// Author TEAL with no framework policy is "custom"; a second name for the same
	// program would let a review call a restricted account unrestricted.
	if policy.Policy == Layer3PolicyNone && hasAuthorTEAL {
		return fmt.Errorf("policy %q does not accept author TEAL; omit bounded.layer3 for custom TEAL", policy.Policy)
	}

	used := make(map[string]struct{}, 2)
	if rules.hasList() {
		listMax := BoundedInlineListMax
		if rules.merkleList {
			listMax = merkleallowlist.MaxItems
		}
		if err := validateRecipientsParameter(policy.RecipientsParameter, params, listMax); err != nil {
			return err
		}
		used[policy.RecipientsParameter] = struct{}{}
	} else if policy.RecipientsParameter != "" {
		return fmt.Errorf("policy %q does not use recipients_parameter", policy.Policy)
	}
	if rules.timelock {
		if err := validateUnlockRoundParameter(policy.UnlockRoundParameter, params); err != nil {
			return err
		}
		used[policy.UnlockRoundParameter] = struct{}{}
	} else if policy.UnlockRoundParameter != "" {
		return fmt.Errorf("policy %q does not use unlock_round_parameter", policy.Policy)
	}
	if !hasAuthorTEAL {
		for _, param := range params {
			if _, ok := used[param.Name]; !ok {
				return fmt.Errorf("parameter %q is not used by framework policy %q", param.Name, policy.Policy)
			}
		}
	}

	return nil
}

func validateRecipientsParameter(name string, params []lsigprovider.ParameterDef, listMax int) error {
	if name == "" {
		return fmt.Errorf("recipients_parameter is required")
	}
	for _, param := range params {
		if param.Name != name {
			continue
		}
		if param.Type != "address[]" {
			return fmt.Errorf("recipients_parameter parameter %q must have type address[], got %s", name, param.Type)
		}
		if !param.Required {
			return fmt.Errorf("recipients_parameter parameter %q must be required", name)
		}
		if param.MinItems < 1 {
			return fmt.Errorf("recipients_parameter parameter %q must set min_items >= 1", name)
		}
		if param.MaxItems < 1 || param.MaxItems > listMax {
			return fmt.Errorf("recipients_parameter parameter %q max_items must be between 1 and %d", name, listMax)
		}
		return nil
	}
	return fmt.Errorf("recipients_parameter references unknown parameter %q", name)
}

// validateUnlockRoundParameter requires a declared positive bound. Zero would
// compile a timelock that every transaction passes.
func validateUnlockRoundParameter(name string, params []lsigprovider.ParameterDef) error {
	if name == "" {
		return fmt.Errorf("unlock_round_parameter is required")
	}
	for _, param := range params {
		if param.Name != name {
			continue
		}
		if param.Type != "uint64" {
			return fmt.Errorf("unlock_round_parameter parameter %q must have type uint64, got %s", name, param.Type)
		}
		if !param.Required {
			return fmt.Errorf("unlock_round_parameter parameter %q must be required", name)
		}
		if param.Min == nil || *param.Min < 1 {
			return fmt.Errorf("unlock_round_parameter parameter %q must set min >= 1", name)
		}
		return nil
	}
	return fmt.Errorf("unlock_round_parameter references unknown parameter %q", name)
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
	if err := validateLayer3Policy(c.layer3, c.paramsWithoutCosignerKey(), profile, c.hasAuthorTEAL()); err != nil {
		return "", err
	}
	rules, ok := rulesForLayer3Policy(c.layer3.Policy)
	if !ok {
		return "", fmt.Errorf("unsupported Layer-3 policy %q", c.layer3.Policy)
	}
	if c.layer3.Policy == Layer3PolicyNone {
		// A comment only: the spend falls through to the accept block.
		if profile != nil && profile.Contract == PlainContract {
			return "// === plain host: no host rules; the cosigner signed this spend ===\n", nil
		}
		return "// === no framework Layer 3: the envelope bounds every spend ===\n", nil
	}

	var b strings.Builder
	if rules.timelock {
		timelock, err := c.renderTimelock(params)
		if err != nil {
			return "", err
		}
		b.WriteString(timelock)
	}
	if rules.inlineList {
		list, err := c.renderFixedAllowlist(params, profile)
		if err != nil {
			return "", err
		}
		b.WriteString(list)
	}
	if rules.merkleList {
		list, err := c.renderMerkleAllowlist(params, profile)
		if err != nil {
			return "", err
		}
		b.WriteString(list)
	}
	return b.String(), nil
}

// renderTimelock emits a check that falls through, so a combined policy reaches
// its recipient check only after the unlock round. A rekey never reaches it.
func (c *ComposedDSA) renderTimelock(params map[string]string) (string, error) {
	unlockRound, err := strconv.ParseUint(strings.TrimSpace(params[c.layer3.UnlockRoundParameter]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid unlock round: %w", err)
	}
	return fmt.Sprintf("// === framework-owned timelock ===\ntxn FirstValid\npushint %d\n>=\nassert\n\n", unlockRound), nil
}

func (c *ComposedDSA) renderFixedAllowlist(params map[string]string, profile *BoundedAuthorizationProfile) (string, error) {
	recipients := splitCanonicalList(params[c.layer3.RecipientsParameter])
	var b strings.Builder
	b.WriteString("// === framework-owned fixed allowlist ===\n")
	if profileAllowsSpendEffect(profile, txeffects.SpendEffectPay) {
		b.WriteString("txn TypeEnum\npushint 1\n==\nbnz __aplane_bounded1_layer3_pay\n")
	}
	if profileAllowsSpendEffect(profile, txeffects.SpendEffectAxfer, txeffects.SpendEffectAssetOptIn) {
		b.WriteString("txn TypeEnum\npushint 4\n==\nbnz __aplane_bounded1_layer3_axfer\n")
	}
	b.WriteString("err\n\n")

	// The self-recipient branches keep their own labels ahead of the jump to
	// done. The label names predate the removal of the amount and asset checks
	// they once guarded; the TEAL text and its branch offsets are frozen by the
	// allowlist goldens, and the offsets decide fixed-list account addresses.
	if profileAllowsSpendEffect(profile, txeffects.SpendEffectPay) {
		b.WriteString("__aplane_bounded1_layer3_pay:\n")
		b.WriteString("txn Receiver\ntxn Sender\n==\nbnz __aplane_bounded1_layer3_pay_amount\n")
		b.WriteString("txn Receiver\ncallsub __aplane_bounded1_layer3_recipient_allowed\nassert\n")
		b.WriteString("__aplane_bounded1_layer3_pay_amount:\n")
		b.WriteString("b __aplane_bounded1_layer3_done\n\n")
	}

	if profileAllowsSpendEffect(profile, txeffects.SpendEffectAxfer, txeffects.SpendEffectAssetOptIn) {
		b.WriteString("__aplane_bounded1_layer3_axfer:\n")
		b.WriteString("txn AssetReceiver\ntxn Sender\n==\nbnz __aplane_bounded1_layer3_asset_constraints\n")
		b.WriteString("txn AssetReceiver\ncallsub __aplane_bounded1_layer3_recipient_allowed\nassert\n")
		b.WriteString("__aplane_bounded1_layer3_asset_constraints:\n")
		b.WriteString("b __aplane_bounded1_layer3_done\n\n")
	}

	if err := writeInlineAddressMembership(&b, recipients); err != nil {
		return "", err
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
	// A framework policy reads no caller argument, so a runtime argument with no
	// author TEAL would be required on every spend and read by nothing.
	if len(c.runtimeArgs) != 0 && !c.hasAuthorTEAL() {
		return fmt.Errorf("%s has no author TEAL to read runtime arguments", c.layer3.Policy)
	}
	rules, ok := rulesForLayer3Policy(c.layer3.Policy)
	if !ok {
		return nil
	}
	if !rules.merkleList {
		if len(c.derivedArgs) != 0 {
			return fmt.Errorf("%s does not accept derived arguments", c.layer3.Policy)
		}
		return nil
	}
	if len(c.derivedArgs) != 1 {
		return fmt.Errorf("%s requires exactly one derived Merkle proof argument", c.layer3.Policy)
	}
	arg := c.derivedArgs[0]
	if arg.Kind != boundedmeta.DerivedArgMerkleProof || arg.Parameter != c.layer3.RecipientsParameter || arg.MaxSize != boundedmeta.MerkleProofSize {
		return fmt.Errorf("%s derived argument must be a %d-byte %s for parameter %q", c.layer3.Policy, boundedmeta.MerkleProofSize, boundedmeta.DerivedArgMerkleProof, c.layer3.RecipientsParameter)
	}
	return nil
}

// paramsWithoutCosignerKey is the parameters a Layer 3 policy accounts for:
// every one but those the framework injects for the envelope's own checks, the
// cosigner key and a rekey-to list's entries.
func (c *ComposedDSA) paramsWithoutCosignerKey() []lsigprovider.ParameterDef {
	params := make([]lsigprovider.ParameterDef, 0, len(c.params))
	for _, param := range c.params {
		if param.Name == BoundedCosignerPublicKeyParameter {
			continue
		}
		if param.Name == BoundedRekeyToParameter && c.bounded != nil && c.bounded.RekeyList != nil {
			continue
		}
		params = append(params, param)
	}
	return params
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
