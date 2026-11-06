// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypeux

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

var boundedPolicyLabels = map[string]string{
	boundedmeta.Layer3PolicyFixedAllowlist:          "Allowlist",
	boundedmeta.Layer3PolicyMerkleAllowlist:         "Merkle allowlist",
	boundedmeta.Layer3PolicyFixedAllowlistCustom:    "Allowlist plus custom policy",
	boundedmeta.Layer3PolicyMerkleAllowlistCustom:   "Merkle allowlist plus custom policy",
	boundedmeta.Layer3PolicyTimelock:                "Timelock",
	boundedmeta.Layer3PolicyFixedAllowlistTimelock:  "Allowlist timelock",
	boundedmeta.Layer3PolicyMerkleAllowlistTimelock: "Merkle allowlist timelock",
	boundedmeta.Layer3PolicyCustom:                  "Custom policy",
}

// BoundedLabel describes a bounded account from its stored contract, such as
// "Merkle allowlist · admin rekey · cosigner". A custom policy says only that it
// is custom: its conditions are the author's code, and nothing here can state them.
// It returns "" for an account with no bounded contract.
func BoundedLabel(info *signerapi.BoundedAuthorizationInfo) string {
	if info == nil {
		return ""
	}
	var rekey *boundedmeta.AdminOperation
	if len(info.AdminOperations) > 0 {
		rekey = &boundedmeta.AdminOperation{
			Authorization: info.AdminOperations[0].Authorization,
			PolicyGate:    info.AdminOperations[0].PolicyGate,
		}
	}
	return boundedLabel(info.Layer3Policy, rekey, info.Cosigner != nil)
}

// BoundedMetadataLabel is BoundedLabel for a key's durable metadata.
func BoundedMetadataLabel(metadata *boundedmeta.Metadata) string {
	if metadata == nil {
		return ""
	}
	var rekey *boundedmeta.AdminOperation
	if len(metadata.AdminOperations) > 0 {
		rekey = &metadata.AdminOperations[0]
	}
	return boundedLabel(metadata.Layer3Policy, rekey, metadata.Cosigner != nil)
}

func boundedLabel(layer3Policy string, rekey *boundedmeta.AdminOperation, cosigner bool) string {
	policy, ok := boundedPolicyLabels[layer3Policy]
	if !ok {
		policy = "Policy " + layer3Policy
	}
	parts := []string{policy, boundedRekeyLabel(rekey)}
	if cosigner {
		parts = append(parts, "cosigner")
	}
	return strings.Join(parts, " · ")
}

func boundedRekeyLabel(rekey *boundedmeta.AdminOperation) string {
	switch {
	case rekey == nil:
		return "no rekey"
	case rekey.Authorization == boundedmeta.AdminAuthorizationAdmin:
		return "admin rekey"
	case rekey.PolicyGate == boundedmeta.PolicyGateLayer3:
		return "policy-gated rekey"
	default:
		return "spending-key rekey"
	}
}
