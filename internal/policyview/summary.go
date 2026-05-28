// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyview

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
)

type FieldRow struct {
	Key    string
	Label  string
	Value  string
	Source string
}

type AssetSetRow struct {
	Index        int
	Name         string
	NetworkCount int
	ASAIDCount   int
	Preview      string
}

type Model struct {
	Policy              *policy.StoredConfig
	YAML                string
	Fields              []FieldRow
	TransferSummary     string
	TransferGuards      []TransferGuardGroup
	AssetSets           []AssetSetRow
	BlockedDestinations []string
	KeyTypeOverrides    []string
}

func ParseYAML(raw string) (*policy.StoredConfig, error) {
	return policy.ParseStoredConfig([]byte(raw))
}

func Build(stored *policy.StoredConfig, yamlText string) Model {
	cp := stored.Clone()
	model := Model{
		Policy:           cp,
		YAML:             yamlText,
		Fields:           FieldRows(cp),
		TransferSummary:  TransferPolicySummary(cp),
		KeyTypeOverrides: sortedKeyTypeOverrides(cp),
	}
	if cp != nil && cp.TransferPolicy != nil {
		model.TransferGuards = TransferGuardGroups(cp.TransferPolicy.Routes)
		model.AssetSets = AssetSetRows(cp.TransferPolicy.AssetSets)
		model.BlockedDestinations = append([]string(nil), cp.TransferPolicy.BlockedDestinations...)
	}
	return model
}

func FieldRows(c *policy.StoredConfig) []FieldRow {
	return []FieldRow{
		boolFieldRow(c, "reject_foreign_rekey", "Reject foreign rekey", true, func(c *policy.StoredConfig) *bool {
			return c.RejectForeignRekey
		}),
		boolFieldRow(c, "reject_close_remainder", "Reject close remainder", false, func(c *policy.StoredConfig) *bool {
			return c.RejectCloseRemainder
		}),
		boolFieldRow(c, "reject_asset_close", "Reject asset close", false, func(c *policy.StoredConfig) *bool {
			return c.RejectAssetClose
		}),
		boolFieldRow(c, "reject_clawback", "Reject clawback", false, func(c *policy.StoredConfig) *bool {
			return c.RejectClawback
		}),
		boolFieldRow(c, "always_review_warnings", "Always review warnings", false, func(c *policy.StoredConfig) *bool {
			return c.AlwaysReviewWarnings
		}),
		boolFieldRow(c, "auto_approve_self_noop_transfer", "Auto-approve self no-op transfer", false, func(c *policy.StoredConfig) *bool {
			return c.AutoApproveSelfNoOpTransfer
		}),
		maxFeeFieldRow(c),
		{
			Key:    "transfer_policy",
			Label:  "Transfer routing",
			Value:  TransferPolicySummary(c),
			Source: transferPolicySource(c),
		},
		{
			Key:    "key_type_overrides",
			Label:  "Key type overrides",
			Value:  fmt.Sprintf("%d", len(sortedKeyTypeOverrides(c))),
			Source: keyTypeOverridesSource(c),
		},
	}
}

func TransferPolicySummary(c *policy.StoredConfig) string {
	if c == nil || c.TransferPolicy == nil {
		return "enabled=false routes=0"
	}
	enabled := "false"
	if c.TransferPolicy.Enabled != nil {
		enabled = fmt.Sprintf("%t", *c.TransferPolicy.Enabled)
	}
	return fmt.Sprintf("enabled=%s routes=%d", enabled, len(c.TransferPolicy.Routes))
}

func AssetSetRows(sets map[string]policy.StoredAssetSet) []AssetSetRow {
	names := sortedAssetSetNames(sets)
	rows := make([]AssetSetRow, 0, len(names))
	for i, name := range names {
		set := sets[name]
		rows = append(rows, AssetSetRow{
			Index:        i,
			Name:         name,
			NetworkCount: len(set),
			ASAIDCount:   AssetSetIDCount(set),
			Preview:      AssetSetPreview(set),
		})
	}
	return rows
}

func AssetSetIDCount(set policy.StoredAssetSet) int {
	var count int
	for _, ids := range set {
		count += len(ids)
	}
	return count
}

func AssetSetPreview(set policy.StoredAssetSet) string {
	if len(set) == 0 {
		return "-"
	}
	networks := SortedAssetSetNetworks(set)
	parts := make([]string, 0, len(networks))
	for _, network := range networks {
		parts = append(parts, network+":"+joinUint64s(set[network]))
	}
	return strings.Join(parts, " ")
}

func SortedAssetSetNetworks(set policy.StoredAssetSet) []string {
	networks := make([]string, 0, len(set))
	for network := range set {
		networks = append(networks, network)
	}
	sort.Strings(networks)
	return networks
}

func boolFieldRow(c *policy.StoredConfig, key, label string, defaultValue bool, ptr func(*policy.StoredConfig) *bool) FieldRow {
	value := defaultValue
	source := "default"
	if c != nil {
		if explicit := ptr(c); explicit != nil {
			value = *explicit
			source = "explicit"
		}
	}
	return FieldRow{
		Key:    key,
		Label:  label,
		Value:  fmt.Sprintf("%t", value),
		Source: source,
	}
}

func maxFeeFieldRow(c *policy.StoredConfig) FieldRow {
	if c == nil || c.MaxFeeMicroAlgos == nil {
		return FieldRow{
			Key:    "max_fee_microalgos",
			Label:  "Max fee microAlgos",
			Value:  "0 (no limit)",
			Source: "default",
		}
	}
	return FieldRow{
		Key:    "max_fee_microalgos",
		Label:  "Max fee microAlgos",
		Value:  fmt.Sprintf("%d", *c.MaxFeeMicroAlgos),
		Source: "explicit",
	}
}

func transferPolicySource(c *policy.StoredConfig) string {
	if c == nil || c.TransferPolicy == nil {
		return "absent"
	}
	return "explicit"
}

func keyTypeOverridesSource(c *policy.StoredConfig) string {
	if c == nil || len(c.KeyTypeOverrides) == 0 {
		return "absent"
	}
	return "explicit"
}

func sortedKeyTypeOverrides(c *policy.StoredConfig) []string {
	if c == nil || len(c.KeyTypeOverrides) == 0 {
		return nil
	}
	out := make([]string, 0, len(c.KeyTypeOverrides))
	for keyType := range c.KeyTypeOverrides {
		out = append(out, keyType)
	}
	sort.Strings(out)
	return out
}

func sortedAssetSetNames(sets map[string]policy.StoredAssetSet) []string {
	names := make([]string, 0, len(sets))
	for name := range sets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func joinUint64s(ids []uint64) string {
	if len(ids) == 0 {
		return "-"
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatUint(id, 10)
	}
	return strings.Join(parts, ",")
}
