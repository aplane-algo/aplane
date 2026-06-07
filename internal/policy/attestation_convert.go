// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import "fmt"

// ConvertSigningPolicyToAttestation projects a signing policy.yaml document to
// direct attestor policy YAML. The projection preserves deterministic
// hard-reject bounds and transfer routes, but removes review-only controls
// because attestor policy cannot produce review verdicts.
func ConvertSigningPolicyToAttestation(stored *StoredConfig) (*StoredConfig, error) {
	if stored == nil {
		stored = &StoredConfig{}
	}
	if err := validateSigningDocument(stored); err != nil {
		return nil, err
	}
	if len(stored.KeyOverrides) > 0 {
		return nil, fmt.Errorf("key_overrides cannot be converted automatically; signing overrides are keyed by account, attestation overrides are keyed by component selector")
	}

	effective := stored.Clone()
	effective.KeyOverrides = nil
	if effective.ClientSigning != nil {
		effective = mergeStoredRoleConfig(effective, effective.ClientSigning)
	}
	effective.ClientSigning = nil
	effective.Attestation = nil

	if effective.TransferPolicy == nil {
		return nil, fmt.Errorf("policy has no transfer_policy to convert")
	}
	if err := validateTransferPolicyConvertibleToAttestation(effective.TransferPolicy); err != nil {
		return nil, err
	}

	out := &StoredConfig{
		RejectRekey:          boolPtr(true),
		RejectCloseRemainder: cloneBoolPtr(effective.RejectCloseRemainder),
		RejectAssetClose:     cloneBoolPtr(effective.RejectAssetClose),
		RejectClawback:       cloneBoolPtr(effective.RejectClawback),
		MaxFeeMicroAlgos:     cloneUint64Ptr(effective.MaxFeeMicroAlgos),
		MaxAlgoPayments:      cloneUintMap(effective.MaxAlgoPayments),
		MaxASAAmounts:        cloneStoredASAAmounts(effective.MaxASAAmounts),
		TransferPolicy:       convertTransferPolicyToAttestation(effective.TransferPolicy),
	}
	if err := validateAttestationDocument(out); err != nil {
		return nil, err
	}
	return out, nil
}

// ConvertSigningPolicyToAttestationYAML converts signer-domain policy.yaml
// bytes into direct attestor policy YAML suitable for review, signing, and
// installation as policy.yaml on an attestor node.
func ConvertSigningPolicyToAttestationYAML(data []byte) ([]byte, error) {
	stored, err := ParseStoredConfig(data)
	if err != nil {
		return nil, err
	}
	converted, err := ConvertSigningPolicyToAttestation(stored)
	if err != nil {
		return nil, err
	}
	return MarshalStoredAttestationConfig(converted)
}

func mergeStoredRoleConfig(base *StoredConfig, role *StoredRoleConfig) *StoredConfig {
	if base == nil {
		base = &StoredConfig{}
	}
	out := base.Clone()
	out.ClientSigning = nil
	out.Attestation = nil
	if role == nil {
		return out
	}
	if role.RejectForeignRekey != nil {
		out.RejectForeignRekey = cloneBoolPtr(role.RejectForeignRekey)
	}
	if role.RejectCloseRemainder != nil {
		out.RejectCloseRemainder = cloneBoolPtr(role.RejectCloseRemainder)
	}
	if role.RejectAssetClose != nil {
		out.RejectAssetClose = cloneBoolPtr(role.RejectAssetClose)
	}
	if role.RejectClawback != nil {
		out.RejectClawback = cloneBoolPtr(role.RejectClawback)
	}
	if role.AlwaysReviewWarnings != nil {
		out.AlwaysReviewWarnings = cloneBoolPtr(role.AlwaysReviewWarnings)
	}
	if role.AutoApproveSelfNoOpTransfer != nil {
		out.AutoApproveSelfNoOpTransfer = cloneBoolPtr(role.AutoApproveSelfNoOpTransfer)
	}
	if role.MaxFeeMicroAlgos != nil {
		out.MaxFeeMicroAlgos = cloneUint64Ptr(role.MaxFeeMicroAlgos)
	}
	if role.ReviewAlgoPayments != nil {
		out.ReviewAlgoPayments = cloneUintMap(role.ReviewAlgoPayments)
	}
	if role.MaxAlgoPayments != nil {
		out.MaxAlgoPayments = cloneUintMap(role.MaxAlgoPayments)
	}
	if role.ReviewASAAmounts != nil {
		out.ReviewASAAmounts = cloneStoredASAAmounts(role.ReviewASAAmounts)
	}
	if role.MaxASAAmounts != nil {
		out.MaxASAAmounts = cloneStoredASAAmounts(role.MaxASAAmounts)
	}
	if role.TransferPolicy != nil {
		out.TransferPolicy = mergeStoredTransferPolicy(out.TransferPolicy, role.TransferPolicy)
	}
	return out
}

func mergeStoredTransferPolicy(base, overlay *StoredTransferPolicy) *StoredTransferPolicy {
	if overlay == nil {
		return base.Clone()
	}
	var out *StoredTransferPolicy
	if base != nil {
		out = base.Clone()
	} else {
		out = &StoredTransferPolicy{}
	}
	if overlay.SchemaVersion != 0 {
		out.SchemaVersion = overlay.SchemaVersion
	}
	if overlay.Enabled != nil {
		out.Enabled = cloneBoolPtr(overlay.Enabled)
	}
	if overlay.OnNoRoute != nil {
		out.OnNoRoute = cloneStringPtr(overlay.OnNoRoute)
	}
	if overlay.CloseOnNoRoute != nil {
		out.CloseOnNoRoute = cloneStringPtr(overlay.CloseOnNoRoute)
	}
	if overlay.ClawbackOnNoRoute != nil {
		out.ClawbackOnNoRoute = cloneStringPtr(overlay.ClawbackOnNoRoute)
	}
	if len(overlay.BlockedDestinations) > 0 {
		out.BlockedDestinations = append(out.BlockedDestinations, overlay.BlockedDestinations...)
	}
	if overlay.AddressSets != nil {
		if out.AddressSets == nil {
			out.AddressSets = make(map[string]StoredAddressSet, len(overlay.AddressSets))
		}
		for name, set := range overlay.AddressSets {
			out.AddressSets[name] = set.Clone()
		}
	}
	if overlay.AssetSets != nil {
		if out.AssetSets == nil {
			out.AssetSets = make(map[string]StoredAssetSet, len(overlay.AssetSets))
		}
		for name, set := range overlay.AssetSets {
			out.AssetSets[name] = set.Clone()
		}
	}
	if overlay.RoutesSet {
		out.Routes = cloneStoredTransferRoutes(overlay.Routes)
		out.RoutesSet = true
	}
	return out
}

func convertTransferPolicyToAttestation(tp *StoredTransferPolicy) *StoredTransferPolicy {
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

func validateTransferPolicyConvertibleToAttestation(tp *StoredTransferPolicy) error {
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
		return fmt.Errorf("%s=%q cannot be converted to deterministic attestor policy; set it to %q and encode allowed movements as routes", check.label, *check.value, TransferOnNoRouteReject)
	}
	return nil
}

func boolPtr(v bool) *bool {
	return &v
}
