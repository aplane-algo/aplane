// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypeux

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

var boundedPolicyLabels = map[string]string{
	hostmeta.Layer3PolicyFixedAllowlist:        "Allowlist",
	hostmeta.Layer3PolicyMerkleAllowlist:       "Merkle allowlist",
	hostmeta.Layer3PolicyFixedAllowlistCustom:  "Allowlist plus custom policy",
	hostmeta.Layer3PolicyMerkleAllowlistCustom: "Merkle allowlist plus custom policy",
	hostmeta.Layer3PolicyCustom:                "Custom policy",
	hostmeta.Layer3PolicyNone:                  "Limits only",
}

// HostLabel describes a host account from its stored contract, such as
// "Merkle allowlist · no rekey · cosigner". A custom policy says only that it
// is custom: its conditions are the author's code, and nothing here can state them.
// It returns "" for an account with no host contract.
func HostLabel(info *signerapi.HostInfo) string {
	if info == nil {
		return ""
	}
	// A plain host has no bounds and is labelled by its contract; a bounded
	// host that arrives without them gets the unknown-policy label.
	layer3Policy := ""
	if info.Bounds != nil {
		layer3Policy = info.Bounds.Layer3Policy
	}
	return hostLabel(info.Contract, layer3Policy, hostmeta.RekeySetting(info.Rekey), info.RekeyList != nil, info.Cosigner != nil)
}

// HostMetadataLabel is HostLabel for a key's durable metadata.
func HostMetadataLabel(metadata *hostmeta.Metadata) string {
	if metadata == nil {
		return ""
	}
	return hostLabel(metadata.Contract, metadata.Layer3Policy(), metadata.Rekey, metadata.RekeyList != nil, metadata.Cosigner != nil)
}

func hostLabel(contract, layer3Policy string, rekey hostmeta.RekeySetting, rekeyList, cosigner bool) string {
	policy, ok := boundedPolicyLabels[layer3Policy]
	if !ok {
		policy = "Policy " + layer3Policy
	}
	// A plain host has no host rules; the cosigner's policy decides what it signs.
	if contract == hostmeta.PlainContract {
		policy = "Plain host"
	}
	rekeyLabel := hostRekeyLabel(rekey)
	switch {
	case rekeyList && rekey == hostmeta.RekeyRefused:
		rekeyLabel = "rekey to listed only"
	case rekeyList && rekey == hostmeta.RekeySpendingKey:
		rekeyLabel = "rekey to listed, or cosigned"
	case cosigner && rekey == hostmeta.RekeySpendingKey:
		// The spending key can't rekey a cosigned account alone.
		rekeyLabel = "cosigned rekey"
	}
	parts := []string{policy, rekeyLabel}
	if cosigner {
		parts = append(parts, "cosigner")
	}
	return strings.Join(parts, " · ")
}

func hostRekeyLabel(rekey hostmeta.RekeySetting) string {
	switch rekey {
	case hostmeta.RekeyRefused:
		return "no rekey"
	case hostmeta.RekeySpendingKey:
		return "spending-key rekey"
	case "":
		return "rekey unknown"
	default:
		// Not a setting this release offers: name it rather than guess.
		return string(rekey) + " rekey"
	}
}
