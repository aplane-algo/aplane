// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import "fmt"

// ConvertSigningPolicyToCosigner projects a signing policy.yaml document to
// direct cosigner policy YAML. The projection preserves deterministic
// hard-reject bounds and transfer routes, but removes review-only controls
// because cosigner policy cannot produce review verdicts.
func ConvertSigningPolicyToCosigner(stored *StoredConfig) (*StoredConfig, error) {
	if stored == nil {
		stored = &StoredConfig{}
	}
	if err := validateSigningDocument(stored); err != nil {
		return nil, err
	}
	if len(stored.KeyOverrides) > 0 {
		return nil, fmt.Errorf("key_overrides cannot be converted automatically; signing overrides are keyed by account, cosigner overrides are keyed by Witness Key ID")
	}

	effective := stored.Clone()
	effective.KeyOverrides = nil

	if effective.TransferPolicy == nil {
		return nil, fmt.Errorf("policy has no transfer_policy to convert")
	}
	if err := validateTransferPolicyConvertibleToCosigner(effective.TransferPolicy); err != nil {
		return nil, err
	}

	out := &StoredConfig{StoredPolicyCore: StoredPolicyCore{RejectRekey: boolPtr(true), RejectCloseRemainder: cloneBoolPtr(effective.RejectCloseRemainder), RejectAssetClose: cloneBoolPtr(effective.RejectAssetClose), RejectClawback: cloneBoolPtr(effective.RejectClawback), MaxFeeMicroAlgos: cloneUint64Ptr(effective.MaxFeeMicroAlgos), MaxAlgoPayments: cloneUintMap(effective.MaxAlgoPayments), MaxASAAmounts: cloneStoredASAAmounts(effective.MaxASAAmounts), TransferPolicy: convertTransferPolicyToCosigner(effective.TransferPolicy)}}
	if err := validateCosignerDocument(out); err != nil {
		return nil, err
	}
	return out, nil
}

// ConvertSigningPolicyToCosignerYAML converts signer-domain policy.yaml
// bytes into direct cosigner policy YAML suitable for review, signing, and
// installation as policy.yaml on a cosigner node.
func ConvertSigningPolicyToCosignerYAML(data []byte) ([]byte, error) {
	stored, err := ParseStoredConfig(data)
	if err != nil {
		return nil, err
	}
	converted, err := ConvertSigningPolicyToCosigner(stored)
	if err != nil {
		return nil, err
	}
	return MarshalStoredCosignerConfig(converted)
}

func convertTransferPolicyToCosigner(tp *StoredTransferPolicy) *StoredTransferPolicy {
	if tp == nil {
		return nil
	}
	out := tp.Clone()
	if out.SchemaVersion == 0 {
		out.SchemaVersion = transferPolicySchemaVersion
	}
	reject := string(TransferOnNoRouteReject)
	if out.Enabled != nil && *out.Enabled {
		out.OnNoRoute = &reject
		out.CloseOnNoRoute = &reject
		out.ClawbackOnNoRoute = &reject
	}
	for i := range out.Routes {
		if out.Routes[i].Limits != nil {
			out.Routes[i].Limits.ReviewAbove = nil
		}
		for network, limits := range out.Routes[i].LimitsByNetwork {
			limits.ReviewAbove = nil
			out.Routes[i].LimitsByNetwork[network] = limits
		}
	}
	return out
}

func validateTransferPolicyConvertibleToCosigner(tp *StoredTransferPolicy) error {
	if tp == nil {
		return nil
	}
	checks := []struct {
		label string
		value *string
	}{
		{label: "transfer_policy.on_no_route", value: tp.OnNoRoute},
		{label: "transfer_policy.close_on_no_route", value: tp.CloseOnNoRoute},
		{label: "transfer_policy.clawback_on_no_route", value: tp.ClawbackOnNoRoute},
	}
	for _, check := range checks {
		if check.value == nil || *check.value == "" || *check.value == string(TransferOnNoRouteReject) {
			continue
		}
		return fmt.Errorf("%s=%q cannot be converted to deterministic cosigner policy; set it to %q and encode allowed movements as routes", check.label, *check.value, TransferOnNoRouteReject)
	}
	return nil
}

func boolPtr(v bool) *bool {
	return &v
}
