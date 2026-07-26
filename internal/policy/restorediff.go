// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// RestoreComparisonStatus is the factual relationship between two normalized
// policy projections.
type RestoreComparisonStatus string

const (
	// RestoreComparisonIdentical means every projected field is equal.
	RestoreComparisonIdentical RestoreComparisonStatus = "identical"
	// RestoreComparisonDifferent means at least one projected field differs.
	RestoreComparisonDifferent RestoreComparisonStatus = "different"
	// RestoreComparisonUnavailable means the policies could not be compared in
	// one role domain.
	RestoreComparisonUnavailable RestoreComparisonStatus = "unavailable"
)

// RestoreChangeCategory orders security-bearing policy facts for review.
type RestoreChangeCategory string

const (
	RestoreCategoryHardRejects  RestoreChangeCategory = "hard_rejects"
	RestoreCategoryCeilings     RestoreChangeCategory = "ceilings"
	RestoreCategoryReview       RestoreChangeCategory = "review_requirements"
	RestoreCategoryRouting      RestoreChangeCategory = "routing_restrictions"
	RestoreCategoryAutoApproval RestoreChangeCategory = "explicit_auto_approval"
	RestoreCategoryRemaining    RestoreChangeCategory = "remaining"
)

// RestorePolicyField is one canonical effective-policy fact for one selector.
type RestorePolicyField struct {
	Category RestoreChangeCategory `json:"category"`
	Selector string                `json:"selector"`
	Path     string                `json:"path"`
	Value    string                `json:"value"`
}

// RestorePolicyProjection is a deterministic effective-policy projection for
// the selectors being recovered.
type RestorePolicyProjection struct {
	Role   string               `json:"role"`
	Fields []RestorePolicyField `json:"fields"`
}

// RestorePolicyChange is one factual source/destination difference.
type RestorePolicyChange struct {
	Category    RestoreChangeCategory `json:"category"`
	Selector    string                `json:"selector"`
	Path        string                `json:"path"`
	Source      string                `json:"source"`
	Destination string                `json:"destination"`
}

// RestorePolicyComparison contains ordered differences and secondary raw
// changed paths.
type RestorePolicyComparison struct {
	Status       RestoreComparisonStatus `json:"status"`
	Changes      []RestorePolicyChange   `json:"changes,omitempty"`
	ChangedPaths []string                `json:"changed_paths,omitempty"`
}

// NormalizeForRestoreDiff resolves key overrides and projects security-bearing
// effective policy fields deterministically.
func NormalizeForRestoreDiff(cfg *Config, role string, selectors []string) (RestorePolicyProjection, error) {
	if cfg == nil {
		return RestorePolicyProjection{}, fmt.Errorf("effective policy is required")
	}
	switch role {
	case "signer", "sentry":
	default:
		return RestorePolicyProjection{}, fmt.Errorf("unsupported restore policy role %q", role)
	}
	selected := slices.Clone(selectors)
	slices.Sort(selected)
	selected = slices.Compact(selected)
	if len(selected) == 0 {
		return RestorePolicyProjection{}, fmt.Errorf("at least one restore selector is required")
	}

	projection := RestorePolicyProjection{Role: role}
	for _, selector := range selected {
		effective := cfg.ForKey(selector)
		appendCoreRestoreFields(&projection.Fields, selector, effective)
		appendTransferRestoreFields(&projection.Fields, selector, effective.TransferPolicy)
		appendRekeyRestoreFields(&projection.Fields, selector, effective.RekeyPolicy)
	}
	sortRestorePolicyFields(projection.Fields)
	return projection, nil
}

// DiffForRestore compares two deterministic projections without assigning a
// widening or safety verdict.
//
// The source projection comes from archive-reported policy that the
// destination store cannot authenticate, so the comparison is review material
// only. It never gates activation, and callers must not derive a security
// verdict from it.
func DiffForRestore(source, destination RestorePolicyProjection) RestorePolicyComparison {
	if source.Role == "" || source.Role != destination.Role {
		return RestorePolicyComparison{Status: RestoreComparisonUnavailable}
	}
	sourceByKey := make(map[string]RestorePolicyField, len(source.Fields))
	destinationByKey := make(map[string]RestorePolicyField, len(destination.Fields))
	for _, field := range source.Fields {
		sourceByKey[restoreFieldKey(field)] = field
	}
	for _, field := range destination.Fields {
		destinationByKey[restoreFieldKey(field)] = field
	}
	keys := make([]string, 0, len(sourceByKey)+len(destinationByKey))
	seen := make(map[string]struct{}, cap(keys))
	for key := range sourceByKey {
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	for key := range destinationByKey {
		if _, ok := seen[key]; !ok {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)

	var changes []RestorePolicyChange
	for _, key := range keys {
		sourceField, sourceOK := sourceByKey[key]
		destinationField, destinationOK := destinationByKey[key]
		if sourceOK && destinationOK && sourceField.Value == destinationField.Value {
			continue
		}
		field := sourceField
		if !sourceOK {
			field = destinationField
		}
		sourceValue := "unavailable"
		if sourceOK {
			sourceValue = sourceField.Value
		}
		destinationValue := "unavailable"
		if destinationOK {
			destinationValue = destinationField.Value
		}
		changes = append(changes, RestorePolicyChange{
			Category:    field.Category,
			Selector:    field.Selector,
			Path:        field.Path,
			Source:      sourceValue,
			Destination: destinationValue,
		})
	}
	slices.SortFunc(changes, compareRestorePolicyChanges)
	if len(changes) == 0 {
		return RestorePolicyComparison{Status: RestoreComparisonIdentical}
	}
	changedPaths := make([]string, len(changes))
	for i, change := range changes {
		changedPaths[i] = "selectors." + change.Selector + "." + change.Path
	}
	return RestorePolicyComparison{
		Status:       RestoreComparisonDifferent,
		Changes:      changes,
		ChangedPaths: changedPaths,
	}
}

func appendCoreRestoreFields(fields *[]RestorePolicyField, selector string, cfg *Config) {
	appendRestoreField(fields, RestoreCategoryHardRejects, selector, "reject_rekey", cfg.RejectRekey)
	appendRestoreField(fields, RestoreCategoryHardRejects, selector, "reject_foreign_rekey", cfg.RejectForeignRekey)
	appendRestoreField(fields, RestoreCategoryHardRejects, selector, "reject_close_remainder", cfg.RejectCloseRemainder)
	appendRestoreField(fields, RestoreCategoryHardRejects, selector, "reject_asset_close", cfg.RejectAssetClose)
	appendRestoreField(fields, RestoreCategoryHardRejects, selector, "reject_clawback", cfg.RejectClawback)
	appendRestoreField(fields, RestoreCategoryCeilings, selector, "max_fee_microalgos", cfg.MaxFeeMicroAlgos)
	appendRestoreField(fields, RestoreCategoryCeilings, selector, "max_algo_payments", sortedUintMap(cfg.MaxAlgoPayments))
	appendRestoreField(fields, RestoreCategoryCeilings, selector, "max_asa_amounts", sortedASAAmounts(cfg.MaxASAAmounts))
	appendRestoreField(fields, RestoreCategoryReview, selector, "always_review_warnings", cfg.AlwaysReviewWarnings)
	appendRestoreField(fields, RestoreCategoryReview, selector, "review_algo_payments", sortedUintMap(cfg.ReviewAlgoPayments))
	appendRestoreField(fields, RestoreCategoryReview, selector, "review_asa_amounts", sortedASAAmounts(cfg.ReviewASAAmounts))
	appendRestoreField(fields, RestoreCategoryAutoApproval, selector, "auto_approve_self_noop_transfer", cfg.AutoApproveSelfNoOpTransfer)
}

func appendTransferRestoreFields(fields *[]RestorePolicyField, selector string, transfer *TransferPolicy) {
	if transfer == nil {
		appendRestoreField(fields, RestoreCategoryRouting, selector, "transfer_policy", nil)
		return
	}
	appendRestoreField(fields, RestoreCategoryRouting, selector, "transfer_policy.enabled", transfer.Enabled)
	appendRestoreField(fields, RestoreCategoryRouting, selector, "transfer_policy.on_no_route", transfer.OnNoRoute)
	appendRestoreField(fields, RestoreCategoryRouting, selector, "transfer_policy.close_on_no_route", transfer.CloseOnNoRoute)
	appendRestoreField(fields, RestoreCategoryRouting, selector, "transfer_policy.clawback_on_no_route", transfer.ClawbackOnNoRoute)
	blocked := make([]string, 0, len(transfer.BlockedDestinations))
	for address := range transfer.BlockedDestinations {
		blocked = append(blocked, address.String())
	}
	slices.Sort(blocked)
	appendRestoreField(fields, RestoreCategoryRouting, selector, "transfer_policy.blocked_destinations", blocked)

	routes := slices.Clone(transfer.Routes)
	slices.SortFunc(routes, func(a, b CompiledTransferRoute) int {
		return strings.Compare(a.ID, b.ID)
	})
	for _, route := range routes {
		prefix := "transfer_policy.routes." + route.ID
		appendRestoreField(fields, RestoreCategoryRouting, selector, prefix+".enabled", route.Enabled)
		appendRestoreField(fields, RestoreCategoryRouting, selector, prefix+".networks", restoreSortedStringSet(route.Networks, route.NetworkWildcard))
		appendRestoreField(fields, RestoreCategoryRouting, selector, prefix+".sources", restoreAddressTerms(route.Sources))
		appendRestoreField(fields, RestoreCategoryRouting, selector, prefix+".asset_sources", restoreAddressTerms(route.AssetSources))
		appendRestoreField(fields, RestoreCategoryRouting, selector, prefix+".assets", restoreAssetTerms(route.Assets))
		appendRestoreField(fields, RestoreCategoryRouting, selector, prefix+".destinations", restoreAddressTerms(route.Destinations))
		appendRestoreField(fields, RestoreCategoryRouting, selector, prefix+".allow_close", route.AllowClose)
		appendRestoreField(fields, RestoreCategoryRouting, selector, prefix+".allow_clawback", route.AllowClawback)
		appendAmountLimitRestoreFields(fields, selector, prefix+".limits", route.Limits)
		networks := make([]string, 0, len(route.LimitsByNetwork))
		for network := range route.LimitsByNetwork {
			networks = append(networks, network)
		}
		slices.Sort(networks)
		for _, network := range networks {
			limits := route.LimitsByNetwork[network]
			appendAmountLimitRestoreFields(fields, selector, prefix+".limits_by_network."+network, &limits)
		}
	}
}

func appendAmountLimitRestoreFields(fields *[]RestorePolicyField, selector, prefix string, limits *AmountLimits) {
	var reviewAbove, rejectAbove *uint64
	if limits != nil {
		reviewAbove = limits.ReviewAbove
		rejectAbove = limits.RejectAbove
	}
	appendRestoreField(fields, RestoreCategoryReview, selector, prefix+".review_above", reviewAbove)
	appendRestoreField(fields, RestoreCategoryCeilings, selector, prefix+".reject_above", rejectAbove)
}

func appendRekeyRestoreFields(fields *[]RestorePolicyField, selector string, rekey *RekeyPolicy) {
	if rekey == nil {
		appendRestoreField(fields, RestoreCategoryRouting, selector, "rekey_policy.allowed", nil)
		return
	}
	rules := make([]string, 0, len(rekey.Allowed))
	for _, rule := range rekey.Allowed {
		senders := restoreRekeyTerms(rule.Sender)
		targets := restoreRekeyTerms(rule.Targets)
		rules = append(rules, strings.Join(senders, ",")+"->"+strings.Join(targets, ","))
	}
	slices.Sort(rules)
	appendRestoreField(fields, RestoreCategoryRouting, selector, "rekey_policy.allowed", rules)
}

func appendRestoreField(fields *[]RestorePolicyField, category RestoreChangeCategory, selector, path string, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("marshal restore policy field %s: %v", path, err))
	}
	*fields = append(*fields, RestorePolicyField{
		Category: category,
		Selector: selector,
		Path:     path,
		Value:    string(encoded),
	})
}

func sortedUintMap(values map[string]uint64) []string {
	out := make([]string, 0, len(values))
	for key, value := range values {
		out = append(out, key+"="+strconv.FormatUint(value, 10))
	}
	slices.Sort(out)
	return out
}

func sortedASAAmounts(values map[string]map[uint64]uint64) []string {
	var out []string
	for network, assets := range values {
		for assetID, value := range assets {
			out = append(out, network+"."+strconv.FormatUint(assetID, 10)+"="+strconv.FormatUint(value, 10))
		}
	}
	slices.Sort(out)
	return out
}

func restoreSortedStringSet(values map[string]struct{}, wildcard bool) []string {
	out := make([]string, 0, len(values)+1)
	if wildcard {
		out = append(out, "*")
	}
	for value := range values {
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func restoreAddressTerms(terms compiledAddressTerms) []string {
	out := slices.Clone(terms.Sets)
	if terms.Wildcard {
		out = append(out, "*")
	}
	if terms.Self {
		out = append(out, "self")
	}
	for _, address := range terms.Direct {
		out = append(out, address.String())
	}
	slices.Sort(out)
	return out
}

func restoreAssetTerms(terms compiledAssetTerms) []string {
	out := slices.Clone(terms.Sets)
	if terms.Wildcard {
		out = append(out, "*")
	}
	if terms.Algo {
		out = append(out, "algo")
	}
	for _, assetID := range terms.ASAIDs {
		out = append(out, "asa:"+strconv.FormatUint(assetID, 10))
	}
	slices.Sort(out)
	return out
}

func restoreRekeyTerms(terms compiledRekeyAddressTerms) []string {
	out := make([]string, len(terms.Direct))
	for i, address := range terms.Direct {
		out[i] = address.String()
	}
	slices.Sort(out)
	return out
}

func sortRestorePolicyFields(fields []RestorePolicyField) {
	slices.SortFunc(fields, func(a, b RestorePolicyField) int {
		if order := categoryOrder(a.Category) - categoryOrder(b.Category); order != 0 {
			return order
		}
		if order := strings.Compare(a.Selector, b.Selector); order != 0 {
			return order
		}
		return strings.Compare(a.Path, b.Path)
	})
}

func compareRestorePolicyChanges(a, b RestorePolicyChange) int {
	if order := categoryOrder(a.Category) - categoryOrder(b.Category); order != 0 {
		return order
	}
	if order := strings.Compare(a.Selector, b.Selector); order != 0 {
		return order
	}
	return strings.Compare(a.Path, b.Path)
}

func categoryOrder(category RestoreChangeCategory) int {
	switch category {
	case RestoreCategoryHardRejects:
		return 0
	case RestoreCategoryCeilings:
		return 1
	case RestoreCategoryReview:
		return 2
	case RestoreCategoryRouting:
		return 3
	case RestoreCategoryAutoApproval:
		return 4
	default:
		return 5
	}
}

func restoreFieldKey(field RestorePolicyField) string {
	return field.Selector + "\x00" + field.Path
}
