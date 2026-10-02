// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/policyschema"
)

// This file decodes and validates policy documents in format v1
// (docs/ARCH_POLICY_FORMAT.md). Decoding enforces every syntax and semantic
// rule, so a document that decodes is one the node may sign and enforce.

const maxPolicyDescriptionLength = 1024

var (
	policyTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	policySetPattern   = regexp.MustCompile(`^[a-z0-9_-]+$`)
)

// ThresholdsV1 is one asset's review and reject thresholds in base units.
type ThresholdsV1 struct {
	ReviewAbove *uint64
	RejectAbove *uint64
}

// LimitsV1 maps network, then asset, to thresholds.
type LimitsV1 map[string]map[TransferAssetRef]ThresholdsV1

// OverrideAmountV1 is a key override threshold: absent (inherit), Null
// (remove the inherited threshold), or Value.
type OverrideAmountV1 struct {
	Set   bool
	Null  bool
	Value uint64
}

// OverrideLimitsV1 maps network, then asset, to override thresholds.
type OverrideLimitsV1 map[string]map[TransferAssetRef]OverrideThresholdsV1

type OverrideThresholdsV1 struct {
	ReviewAbove OverrideAmountV1
	RejectAbove OverrideAmountV1
}

// AddressSetV1 is a flat address list or a per-network address map.
type AddressSetV1 struct {
	Flat      []types.Address
	ByNetwork map[string][]types.Address
}

// AssetSetV1 maps network to assets.
type AssetSetV1 map[string][]TransferAssetRef

// RouteV1 is one allow-list entry. Address and asset terms keep their v1
// spelling ("*", "self", "@set", address, "algo", "asa:<id>").
type RouteV1 struct {
	ID              string
	Description     string
	NetworkWildcard bool
	Networks        []string
	Sources         []string
	Assets          []string
	Destinations    []string
	AssetSources    []string
	Limits          LimitsV1
	AllowClose      bool
	AllowClawback   bool
}

// SignerSettingsV1 holds the signer fields a key override may also set.
type SignerSettingsV1 struct {
	RejectForeignRekey          *bool
	RejectCloseRemainder        *bool
	RejectAssetClose            *bool
	RejectClawback              *bool
	AlwaysReviewWarnings        *bool
	AutoApproveSelfNoOpTransfer *bool
	MaxFeeMicroAlgos            *uint64
}

type SignerTransferPolicyV1 struct {
	Enabled             bool
	OnNoRoute           TransferOnNoRoute
	CloseOnNoRoute      TransferOnNoRoute
	ClawbackOnNoRoute   TransferOnNoRoute
	BlockedDestinations []types.Address
	Routes              []RouteV1
}

type SignerKeyOverrideV1 struct {
	Description string
	SignerSettingsV1
	Limits OverrideLimitsV1
}

// SignerPolicyV1 is a decoded and validated signer policy.json.
type SignerPolicyV1 struct {
	Description string
	SignerSettingsV1
	Limits         LimitsV1
	AddressSets    map[string]AddressSetV1
	AssetSets      map[string]AssetSetV1
	TransferPolicy *SignerTransferPolicyV1
	KeyOverrides   map[string]SignerKeyOverrideV1
}

type RekeyRuleV1 struct {
	Sender  string
	Targets []string
}

// CosignerPolicyV1 is a decoded and validated policies/<WitnessKeyID>.json.
type CosignerPolicyV1 struct {
	Key                  string
	Description          string
	RejectCloseRemainder *bool
	RejectAssetClose     *bool
	RejectClawback       *bool
	RejectRekey          *bool
	MaxFeeMicroAlgos     *uint64
	Limits               LimitsV1
	AddressSets          map[string]AddressSetV1
	AssetSets            map[string]AssetSetV1
	BlockedDestinations  []types.Address
	Routes               []RouteV1
	RekeyPolicy          []RekeyRuleV1
}

// DecodeSignerPolicyV1 decodes and validates a signer policy.json.
func DecodeSignerPolicyV1(data []byte) (*SignerPolicyV1, error) {
	r, err := openPolicyDocument(data, policyschema.SignerFormatV1)
	if err != nil {
		return nil, err
	}
	doc := &SignerPolicyV1{}
	if doc.Description, err = optionalDescription(r); err != nil {
		return nil, err
	}
	if err := decodeSignerSettings(r, &doc.SignerSettingsV1); err != nil {
		return nil, err
	}
	if n := r.field("limits"); n != nil {
		if doc.Limits, err = decodeLimits(n, false); err != nil {
			return nil, err
		}
	}
	if doc.AddressSets, doc.AssetSets, err = decodeSets(r); err != nil {
		return nil, err
	}
	if n := r.field("transfer_policy"); n != nil {
		if doc.TransferPolicy, err = decodeSignerTransferPolicy(n); err != nil {
			return nil, err
		}
	}
	if n := r.field("key_overrides"); n != nil {
		if doc.KeyOverrides, err = decodeSignerKeyOverrides(n); err != nil {
			return nil, err
		}
	}
	if err := r.finish(); err != nil {
		return nil, err
	}
	if err := doc.validate(); err != nil {
		return nil, err
	}
	return doc, nil
}

// DecodeCosignerPolicyV1 decodes and validates one cosigner key's policy.
// fileKey is the Witness Key ID from the document's file name; the signed
// key field must match it.
func DecodeCosignerPolicyV1(data []byte, fileKey string) (*CosignerPolicyV1, error) {
	r, err := openPolicyDocument(data, policyschema.CosignerFormatV1)
	if err != nil {
		return nil, err
	}
	doc := &CosignerPolicyV1{}
	keyNode, err := r.required("key")
	if err != nil {
		return nil, err
	}
	if doc.Key, err = decodeWitnessKeyID(keyNode); err != nil {
		return nil, err
	}
	if doc.Key != fileKey {
		return nil, docErrorf(keyNode.pointer, "key %q does not match its file name %q", doc.Key, fileKey)
	}
	if doc.Description, err = optionalDescription(r); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		name string
		dst  **bool
	}{
		{"reject_close_remainder", &doc.RejectCloseRemainder},
		{"reject_asset_close", &doc.RejectAssetClose},
		{"reject_clawback", &doc.RejectClawback},
		{"reject_rekey", &doc.RejectRekey},
	} {
		if *f.dst, err = optionalBool(r, f.name); err != nil {
			return nil, err
		}
	}
	if doc.MaxFeeMicroAlgos, err = optionalAmount(r, "max_fee_microalgos"); err != nil {
		return nil, err
	}
	if n := r.field("limits"); n != nil {
		if doc.Limits, err = decodeLimits(n, true); err != nil {
			return nil, err
		}
	}
	if doc.AddressSets, doc.AssetSets, err = decodeSets(r); err != nil {
		return nil, err
	}
	tpNode, err := r.required("transfer_policy")
	if err != nil {
		return nil, err
	}
	tp, err := readJSONObject(tpNode, "transfer_policy")
	if err != nil {
		return nil, err
	}
	if n := tp.field("blocked_destinations"); n != nil {
		if doc.BlockedDestinations, err = decodeAddressList(n, 0); err != nil {
			return nil, err
		}
	}
	routesNode, err := tp.required("routes")
	if err != nil {
		return nil, err
	}
	if doc.Routes, err = decodeRoutes(routesNode, true); err != nil {
		return nil, err
	}
	if err := tp.finish(); err != nil {
		return nil, err
	}
	if n := r.field("rekey_policy"); n != nil {
		if doc.RekeyPolicy, err = decodeRekeyPolicy(n); err != nil {
			return nil, err
		}
	}
	if err := r.finish(); err != nil {
		return nil, err
	}
	if err := doc.validate(); err != nil {
		return nil, err
	}
	return doc, nil
}

func openPolicyDocument(data []byte, wantFormat string) (*jsonObjectReader, error) {
	root, err := parseJSONTree(data)
	if err != nil {
		return nil, err
	}
	r, err := readJSONObject(root, "policy document")
	if err != nil {
		return nil, err
	}
	formatNode, err := r.required("format")
	if err != nil {
		return nil, err
	}
	format, err := jsonString(formatNode)
	if err != nil {
		return nil, err
	}
	if format != wantFormat {
		switch format {
		case policyschema.SignerFormatV1, policyschema.CosignerFormatV1:
			return nil, docErrorf(formatNode.pointer, "%q documents are not accepted here; expected %q", format, wantFormat)
		default:
			return nil, docErrorf(formatNode.pointer, "unsupported format %q; expected %q", format, wantFormat)
		}
	}
	return r, nil
}

func decodeSignerSettings(r *jsonObjectReader, s *SignerSettingsV1) error {
	var err error
	for _, f := range []struct {
		name string
		dst  **bool
	}{
		{"reject_foreign_rekey", &s.RejectForeignRekey},
		{"reject_close_remainder", &s.RejectCloseRemainder},
		{"reject_asset_close", &s.RejectAssetClose},
		{"reject_clawback", &s.RejectClawback},
		{"always_review_warnings", &s.AlwaysReviewWarnings},
		{"auto_approve_self_noop_transfer", &s.AutoApproveSelfNoOpTransfer},
	} {
		if *f.dst, err = optionalBool(r, f.name); err != nil {
			return err
		}
	}
	s.MaxFeeMicroAlgos, err = optionalAmount(r, "max_fee_microalgos")
	return err
}

func decodeSignerTransferPolicy(node *jsonNode) (*SignerTransferPolicyV1, error) {
	r, err := readJSONObject(node, "transfer_policy")
	if err != nil {
		return nil, err
	}
	tp := &SignerTransferPolicyV1{}
	enabledNode, err := r.required("enabled")
	if err != nil {
		return nil, err
	}
	if tp.Enabled, err = jsonBool(enabledNode); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		name string
		dst  *TransferOnNoRoute
	}{
		{"on_no_route", &tp.OnNoRoute},
		{"close_on_no_route", &tp.CloseOnNoRoute},
		{"clawback_on_no_route", &tp.ClawbackOnNoRoute},
	} {
		n := r.field(f.name)
		if n == nil {
			continue
		}
		raw, err := jsonString(n)
		if err != nil {
			return nil, err
		}
		action, err := parseTransferOnNoRoute(f.name, raw)
		if err != nil {
			return nil, docErrorf(n.pointer, "must be one of reject, review, operator_default")
		}
		*f.dst = action
	}
	if tp.Enabled && tp.OnNoRoute == "" {
		return nil, docErrorf(node.pointer, "on_no_route is required when enabled is true")
	}
	if n := r.field("blocked_destinations"); n != nil {
		if tp.BlockedDestinations, err = decodeAddressList(n, 0); err != nil {
			return nil, err
		}
	}
	if n := r.field("routes"); n != nil {
		if tp.Routes, err = decodeRoutes(n, false); err != nil {
			return nil, err
		}
	}
	return tp, r.finish()
}

func decodeSignerKeyOverrides(node *jsonNode) (map[string]SignerKeyOverrideV1, error) {
	r, err := readJSONObject(node, "key_overrides")
	if err != nil {
		return nil, err
	}
	out := make(map[string]SignerKeyOverrideV1, len(node.keys))
	for _, key := range node.keys {
		child := r.field(key)
		addr, err := types.DecodeAddress(key)
		if err != nil || addr.String() != key {
			return nil, docErrorf(child.pointer, "key override selector must be an Algorand auth address")
		}
		or, err := readJSONObject(child, "key override")
		if err != nil {
			return nil, err
		}
		if len(child.keys) == 0 {
			return nil, docErrorf(child.pointer, "key override must set at least one field")
		}
		ov := SignerKeyOverrideV1{}
		if ov.Description, err = optionalDescription(or); err != nil {
			return nil, err
		}
		if err := decodeSignerSettings(or, &ov.SignerSettingsV1); err != nil {
			return nil, err
		}
		if n := or.field("limits"); n != nil {
			if ov.Limits, err = decodeOverrideLimits(n); err != nil {
				return nil, err
			}
		}
		if n := or.field("transfer_policy"); n != nil {
			return nil, docErrorf(n.pointer, "key overrides cannot carry transfer_policy; route per account with route sources")
		}
		if err := or.finish(); err != nil {
			return nil, err
		}
		out[key] = ov
	}
	return out, nil
}

func decodeRoutes(node *jsonNode, cosigner bool) ([]RouteV1, error) {
	items, err := jsonArrayItems(node, 0)
	if err != nil {
		return nil, err
	}
	routes := make([]RouteV1, 0, len(items))
	for _, item := range items {
		route, err := decodeRoute(item, cosigner)
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func decodeRoute(node *jsonNode, cosigner bool) (RouteV1, error) {
	r, err := readJSONObject(node, "route")
	if err != nil {
		return RouteV1{}, err
	}
	route := RouteV1{}
	idNode, err := r.required("id")
	if err != nil {
		return RouteV1{}, err
	}
	if route.ID, err = jsonString(idNode); err != nil {
		return RouteV1{}, err
	}
	if len(route.ID) > 64 || !policyTokenPattern.MatchString(route.ID) {
		return RouteV1{}, docErrorf(idNode.pointer, "route id must be lowercase letters, digits, '_' or '-', starting with a letter or digit")
	}
	if route.Description, err = optionalDescription(r); err != nil {
		return RouteV1{}, err
	}
	networksNode, err := r.required("networks")
	if err != nil {
		return RouteV1{}, err
	}
	if route.NetworkWildcard, route.Networks, err = decodeRouteNetworks(networksNode); err != nil {
		return RouteV1{}, err
	}
	for _, f := range []struct {
		name     string
		dst      *[]string
		required bool
		decode   func(*jsonNode) (string, error)
	}{
		{"sources", &route.Sources, true, decodeAddressTerm},
		{"assets", &route.Assets, true, decodeAssetTerm},
		{"destinations", &route.Destinations, true, decodeDestinationTerm},
		{"asset_sources", &route.AssetSources, false, decodeAddressTerm},
	} {
		n := r.field(f.name)
		if n == nil {
			if f.required {
				return RouteV1{}, docErrorf(node.pointer, "missing required field %q", f.name)
			}
			continue
		}
		items, err := jsonArrayItems(n, 1)
		if err != nil {
			return RouteV1{}, err
		}
		for _, item := range items {
			term, err := f.decode(item)
			if err != nil {
				return RouteV1{}, err
			}
			*f.dst = append(*f.dst, term)
		}
	}
	if n := r.field("limits"); n != nil {
		if route.Limits, err = decodeLimits(n, cosigner); err != nil {
			return RouteV1{}, err
		}
	}
	for _, f := range []struct {
		name string
		dst  *bool
	}{{"allow_close", &route.AllowClose}, {"allow_clawback", &route.AllowClawback}} {
		if n := r.field(f.name); n != nil {
			if *f.dst, err = jsonBool(n); err != nil {
				return RouteV1{}, err
			}
		}
	}
	return route, r.finish()
}

func decodeRouteNetworks(node *jsonNode) (bool, []string, error) {
	items, err := jsonArrayItems(node, 1)
	if err != nil {
		return false, nil, err
	}
	if len(items) == 1 && items[0].kind == nodeString && items[0].text == "*" {
		return true, nil, nil
	}
	seen := make(map[string]bool, len(items))
	networks := make([]string, 0, len(items))
	for _, item := range items {
		network, err := decodeNetwork(item)
		if err != nil {
			return false, nil, err
		}
		if seen[network] {
			return false, nil, docErrorf(item.pointer, "duplicate network %q", network)
		}
		seen[network] = true
		networks = append(networks, network)
	}
	return false, networks, nil
}

// decodeLimits decodes network -> asset -> thresholds. Cosigner limits carry
// reject_above only.
func decodeLimits(node *jsonNode, cosigner bool) (LimitsV1, error) {
	out := LimitsV1{}
	err := forEachLimit(node, func(network string, asset TransferAssetRef, tn *jsonNode) error {
		r, err := readJSONObject(tn, "thresholds")
		if err != nil {
			return err
		}
		var t ThresholdsV1
		if t.RejectAbove, err = optionalAmount(r, "reject_above"); err != nil {
			return err
		}
		if !cosigner {
			if t.ReviewAbove, err = optionalAmount(r, "review_above"); err != nil {
				return err
			}
		}
		if err := r.finish(); err != nil {
			if cosigner && tn.members["review_above"] != nil {
				return docErrorf(tn.members["review_above"].pointer, "cosigner policy cannot produce review verdicts")
			}
			return err
		}
		if t.ReviewAbove == nil && t.RejectAbove == nil {
			return docErrorf(tn.pointer, "thresholds must set review_above or reject_above")
		}
		if cosigner && t.RejectAbove == nil {
			return docErrorf(tn.pointer, "missing required field \"reject_above\"")
		}
		if t.ReviewAbove != nil && t.RejectAbove != nil && *t.ReviewAbove > *t.RejectAbove {
			return docErrorf(tn.pointer, "review_above must not exceed reject_above")
		}
		if out[network] == nil {
			out[network] = map[TransferAssetRef]ThresholdsV1{}
		}
		out[network][asset] = t
		return nil
	})
	return out, err
}

func decodeOverrideLimits(node *jsonNode) (OverrideLimitsV1, error) {
	out := OverrideLimitsV1{}
	err := forEachLimit(node, func(network string, asset TransferAssetRef, tn *jsonNode) error {
		r, err := readJSONObject(tn, "thresholds")
		if err != nil {
			return err
		}
		var t OverrideThresholdsV1
		for _, f := range []struct {
			name string
			dst  *OverrideAmountV1
		}{{"review_above", &t.ReviewAbove}, {"reject_above", &t.RejectAbove}} {
			n := r.field(f.name)
			if n == nil {
				continue
			}
			f.dst.Set = true
			if n.kind == nodeNull {
				f.dst.Null = true
				continue
			}
			if f.dst.Value, err = decodeAmount(n); err != nil {
				return err
			}
		}
		if err := r.finish(); err != nil {
			return err
		}
		if !t.ReviewAbove.Set && !t.RejectAbove.Set {
			return docErrorf(tn.pointer, "thresholds must set review_above or reject_above")
		}
		if out[network] == nil {
			out[network] = map[TransferAssetRef]OverrideThresholdsV1{}
		}
		out[network][asset] = t
		return nil
	})
	return out, err
}

func forEachLimit(node *jsonNode, visit func(string, TransferAssetRef, *jsonNode) error) error {
	r, err := readJSONObject(node, "limits")
	if err != nil {
		return err
	}
	for _, network := range node.keys {
		netNode := r.field(network)
		if err := validatePolicyNetwork(netNode.pointer, network); err != nil {
			return err
		}
		ar, err := readJSONObject(netNode, "network limits")
		if err != nil {
			return err
		}
		if len(netNode.keys) == 0 {
			return docErrorf(netNode.pointer, "network limits must name at least one asset")
		}
		for _, assetKey := range netNode.keys {
			tn := ar.field(assetKey)
			asset, err := parseAssetRefV1(tn.pointer, assetKey)
			if err != nil {
				return err
			}
			if err := visit(network, asset, tn); err != nil {
				return err
			}
		}
	}
	return nil
}

func decodeSets(r *jsonObjectReader) (map[string]AddressSetV1, map[string]AssetSetV1, error) {
	var addressSets map[string]AddressSetV1
	var assetSets map[string]AssetSetV1
	if n := r.field("address_sets"); n != nil {
		sr, err := readJSONObject(n, "address_sets")
		if err != nil {
			return nil, nil, err
		}
		addressSets = make(map[string]AddressSetV1, len(n.keys))
		for _, name := range n.keys {
			setNode := sr.field(name)
			if err := validateSetNameV1(setNode.pointer, name); err != nil {
				return nil, nil, err
			}
			set, err := decodeAddressSet(setNode)
			if err != nil {
				return nil, nil, err
			}
			addressSets[name] = set
		}
	}
	if n := r.field("asset_sets"); n != nil {
		sr, err := readJSONObject(n, "asset_sets")
		if err != nil {
			return nil, nil, err
		}
		assetSets = make(map[string]AssetSetV1, len(n.keys))
		for _, name := range n.keys {
			setNode := sr.field(name)
			if err := validateSetNameV1(setNode.pointer, name); err != nil {
				return nil, nil, err
			}
			set, err := decodeAssetSet(setNode)
			if err != nil {
				return nil, nil, err
			}
			assetSets[name] = set
		}
	}
	return addressSets, assetSets, nil
}

func decodeAddressSet(node *jsonNode) (AddressSetV1, error) {
	if node.kind == nodeArray {
		addrs, err := decodeAddressList(node, 1)
		return AddressSetV1{Flat: addrs}, err
	}
	r, err := readJSONObject(node, "address set")
	if err != nil {
		return AddressSetV1{}, docErrorf(node.pointer, "address set must be an address list or a network map")
	}
	if len(node.keys) == 0 {
		return AddressSetV1{}, docErrorf(node.pointer, "address set must not be empty")
	}
	set := AddressSetV1{ByNetwork: make(map[string][]types.Address, len(node.keys))}
	for _, network := range node.keys {
		netNode := r.field(network)
		if err := validatePolicyNetwork(netNode.pointer, network); err != nil {
			return AddressSetV1{}, err
		}
		if set.ByNetwork[network], err = decodeAddressList(netNode, 1); err != nil {
			return AddressSetV1{}, err
		}
	}
	return set, nil
}

func decodeAssetSet(node *jsonNode) (AssetSetV1, error) {
	r, err := readJSONObject(node, "asset set")
	if err != nil {
		return nil, err
	}
	if len(node.keys) == 0 {
		return nil, docErrorf(node.pointer, "asset set must not be empty")
	}
	set := make(AssetSetV1, len(node.keys))
	for _, network := range node.keys {
		netNode := r.field(network)
		if err := validatePolicyNetwork(netNode.pointer, network); err != nil {
			return nil, err
		}
		items, err := jsonArrayItems(netNode, 1)
		if err != nil {
			return nil, err
		}
		seen := make(map[TransferAssetRef]bool, len(items))
		for _, item := range items {
			raw, err := jsonString(item)
			if err != nil {
				return nil, err
			}
			asset, err := parseAssetRefV1(item.pointer, raw)
			if err != nil {
				return nil, err
			}
			if seen[asset] {
				return nil, docErrorf(item.pointer, "duplicate asset %q", raw)
			}
			seen[asset] = true
			set[network] = append(set[network], asset)
		}
	}
	return set, nil
}

func decodeRekeyPolicy(node *jsonNode) ([]RekeyRuleV1, error) {
	r, err := readJSONObject(node, "rekey_policy")
	if err != nil {
		return nil, err
	}
	allowedNode, err := r.required("allowed")
	if err != nil {
		return nil, err
	}
	items, err := jsonArrayItems(allowedNode, 0)
	if err != nil {
		return nil, err
	}
	rules := make([]RekeyRuleV1, 0, len(items))
	for _, item := range items {
		ir, err := readJSONObject(item, "rekey rule")
		if err != nil {
			return nil, err
		}
		senderNode, err := ir.required("sender")
		if err != nil {
			return nil, err
		}
		var rule RekeyRuleV1
		if rule.Sender, err = decodeAddressOrSet(senderNode); err != nil {
			return nil, err
		}
		targetsNode, err := ir.required("targets")
		if err != nil {
			return nil, err
		}
		targets, err := jsonArrayItems(targetsNode, 1)
		if err != nil {
			return nil, err
		}
		for _, t := range targets {
			term, err := decodeAddressOrSet(t)
			if err != nil {
				return nil, err
			}
			rule.Targets = append(rule.Targets, term)
		}
		if err := ir.finish(); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, r.finish()
}

func decodeAddressList(node *jsonNode, minItems int) ([]types.Address, error) {
	items, err := jsonArrayItems(node, minItems)
	if err != nil {
		return nil, err
	}
	seen := make(map[types.Address]bool, len(items))
	out := make([]types.Address, 0, len(items))
	for _, item := range items {
		addr, err := decodeAddress(item)
		if err != nil {
			return nil, err
		}
		if seen[addr] {
			return nil, docErrorf(item.pointer, "duplicate address")
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out, nil
}

func decodeAddress(node *jsonNode) (types.Address, error) {
	raw, err := jsonString(node)
	if err != nil {
		return types.Address{}, err
	}
	addr, err := types.DecodeAddress(raw)
	if err != nil || addr.String() != raw {
		return types.Address{}, docErrorf(node.pointer, "invalid Algorand address %q", raw)
	}
	return addr, nil
}

func decodeWitnessKeyID(node *jsonNode) (string, error) {
	raw, err := jsonString(node)
	if err != nil {
		return "", err
	}
	id, err := witness.NormalizeID(raw)
	if err != nil || id != raw {
		return "", docErrorf(node.pointer, "invalid Witness Key ID %q", raw)
	}
	return id, nil
}

func decodeAddressTerm(node *jsonNode) (string, error) {
	raw, err := jsonString(node)
	if err != nil {
		return "", err
	}
	if raw == "*" {
		return raw, nil
	}
	return decodeAddressOrSet(node)
}

func decodeDestinationTerm(node *jsonNode) (string, error) {
	if node.kind == nodeString && node.text == "self" {
		return "self", nil
	}
	return decodeAddressTerm(node)
}

func decodeAddressOrSet(node *jsonNode) (string, error) {
	raw, err := jsonString(node)
	if err != nil {
		return "", err
	}
	if name, ok := strings.CutPrefix(raw, "@"); ok {
		if err := validateSetNameV1(node.pointer, name); err != nil {
			return "", err
		}
		return raw, nil
	}
	if _, err := decodeAddress(node); err != nil {
		return "", err
	}
	return raw, nil
}

func decodeAssetTerm(node *jsonNode) (string, error) {
	raw, err := jsonString(node)
	if err != nil {
		return "", err
	}
	if raw == "*" {
		return raw, nil
	}
	if name, ok := strings.CutPrefix(raw, "@"); ok {
		if err := validateSetNameV1(node.pointer, name); err != nil {
			return "", err
		}
		return raw, nil
	}
	if _, err := parseAssetRefV1(node.pointer, raw); err != nil {
		return "", err
	}
	return raw, nil
}

func decodeNetwork(node *jsonNode) (string, error) {
	raw, err := jsonString(node)
	if err != nil {
		return "", err
	}
	return raw, validatePolicyNetwork(node.pointer, raw)
}

// parseAssetRefV1 parses "algo" or "asa:<id>" with a canonical uint64 ID.
func parseAssetRefV1(pointer, raw string) (TransferAssetRef, error) {
	if raw == "algo" {
		return TransferAssetRef{Algo: true}, nil
	}
	digits, ok := strings.CutPrefix(raw, "asa:")
	if ok {
		if id, err := parseCanonicalUint64(digits); err == nil && id != 0 {
			return TransferAssetRef{ASAID: id}, nil
		}
	}
	return TransferAssetRef{}, docErrorf(pointer, "asset must be \"algo\" or \"asa:<id>\" with an ASA ID from 1 through 18446744073709551615, not %q", raw)
}

func decodeAmount(node *jsonNode) (uint64, error) {
	if node.kind == nodeNumber {
		return 0, docErrorf(node.pointer, "amounts must be decimal strings in base units, e.g. %q", node.text)
	}
	raw, err := jsonString(node)
	if err != nil {
		return 0, err
	}
	v, err := parseCanonicalUint64(raw)
	if err != nil {
		return 0, docErrorf(node.pointer, "amount %q must be a decimal from 0 through 18446744073709551615 without leading zeros", raw)
	}
	return v, nil
}

func parseCanonicalUint64(raw string) (uint64, error) {
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	if strconv.FormatUint(v, 10) != raw {
		return 0, fmt.Errorf("not canonical")
	}
	return v, nil
}

func optionalAmount(r *jsonObjectReader, name string) (*uint64, error) {
	n := r.field(name)
	if n == nil {
		return nil, nil
	}
	v, err := decodeAmount(n)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func optionalBool(r *jsonObjectReader, name string) (*bool, error) {
	n := r.field(name)
	if n == nil {
		return nil, nil
	}
	v, err := jsonBool(n)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func optionalDescription(r *jsonObjectReader) (string, error) {
	n := r.field("description")
	if n == nil {
		return "", nil
	}
	s, err := jsonString(n)
	if err != nil {
		return "", err
	}
	if utf8.RuneCountInString(s) > maxPolicyDescriptionLength {
		return "", docErrorf(n.pointer, "description is longer than %d characters", maxPolicyDescriptionLength)
	}
	return s, nil
}

func validatePolicyNetwork(pointer, network string) error {
	if err := apconfig.ValidateNetworkID(network); err != nil {
		return docErrorf(pointer, "%v", err)
	}
	return nil
}

func validateSetNameV1(pointer, name string) error {
	if len(name) > 64 || !policySetPattern.MatchString(name) {
		return docErrorf(pointer, "set name %q must be lowercase letters, digits, '_' or '-'", name)
	}
	return nil
}

// --- semantic rules -------------------------------------------------------

func (d *SignerPolicyV1) validate() error {
	if d.TransferPolicy != nil {
		if err := validateRoutesV1("/transfer_policy/routes", d.TransferPolicy.Routes, d.AddressSets, d.AssetSets); err != nil {
			return err
		}
	}
	for _, key := range sortedKeys(d.KeyOverrides) {
		merged := mergeOverrideLimits(d.Limits, d.KeyOverrides[key].Limits)
		for network, assets := range merged {
			for asset, t := range assets {
				if t.ReviewAbove != nil && t.RejectAbove != nil && *t.ReviewAbove > *t.RejectAbove {
					return docErrorf("/key_overrides/"+key+"/limits",
						"after merging with the document limits, %s %s review_above %d exceeds reject_above %d",
						network, assetRefString(asset), *t.ReviewAbove, *t.RejectAbove)
				}
			}
		}
	}
	return nil
}

func (d *CosignerPolicyV1) validate() error {
	if err := validateRoutesV1("/transfer_policy/routes", d.Routes, d.AddressSets, d.AssetSets); err != nil {
		return err
	}
	for i, rule := range d.RekeyPolicy {
		pointer := fmt.Sprintf("/rekey_policy/allowed/%d", i)
		if err := requireRekeyAddressSet(pointer+"/sender", rule.Sender, d.AddressSets); err != nil {
			return err
		}
		for j, target := range rule.Targets {
			if err := requireRekeyAddressSet(fmt.Sprintf("%s/targets/%d", pointer, j), target, d.AddressSets); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateRoutesV1(pointer string, routes []RouteV1, addressSets map[string]AddressSetV1, assetSets map[string]AssetSetV1) error {
	seen := make(map[string]bool, len(routes))
	for i, route := range routes {
		rp := fmt.Sprintf("%s/%d", pointer, i)
		if seen[route.ID] {
			return docErrorf(rp+"/id", "duplicate route id %q", route.ID)
		}
		seen[route.ID] = true
		for _, f := range []struct {
			name  string
			terms []string
		}{{"sources", route.Sources}, {"destinations", route.Destinations}, {"asset_sources", route.AssetSources}} {
			for j, term := range f.terms {
				if err := requireAddressSet(fmt.Sprintf("%s/%s/%d", rp, f.name, j), term, addressSets); err != nil {
					return err
				}
			}
		}
		for j, term := range route.Assets {
			if name, ok := strings.CutPrefix(term, "@"); ok {
				if _, exists := assetSets[name]; !exists {
					return docErrorf(fmt.Sprintf("%s/assets/%d", rp, j), "unknown asset set %q", name)
				}
			}
		}
		if route.AllowClawback != (len(route.AssetSources) > 0) {
			return docErrorf(rp, "allow_clawback and asset_sources must be set together")
		}
		for j, term := range route.Destinations {
			switch {
			case term == "self" && route.AllowClawback:
				return docErrorf(fmt.Sprintf("%s/destinations/%d", rp, j), "self is not allowed in a clawback route's destinations")
			case term == "*" && route.AllowClose:
				return docErrorf(fmt.Sprintf("%s/destinations/%d", rp, j), "allow_close cannot be combined with wildcard destinations")
			}
		}
		if err := validateRouteLimitsCoverage(rp+"/limits", route, assetSets); err != nil {
			return err
		}
	}
	return nil
}

// validateRouteLimitsCoverage requires each route limit to name a network the
// route covers and an asset the route covers on that network.
func validateRouteLimitsCoverage(pointer string, route RouteV1, assetSets map[string]AssetSetV1) error {
	for network, assets := range route.Limits {
		np := pointer + "/" + network
		if !route.NetworkWildcard && !containsString(route.Networks, network) {
			return docErrorf(np, "route does not cover network %q", network)
		}
		for asset := range assets {
			if !routeCoversAsset(route, assetSets, network, asset) {
				return docErrorf(np+"/"+escapeJSONPointer(assetRefString(asset)), "route does not cover %s on %s", assetRefString(asset), network)
			}
		}
	}
	return nil
}

func routeCoversAsset(route RouteV1, assetSets map[string]AssetSetV1, network string, asset TransferAssetRef) bool {
	for _, term := range route.Assets {
		if term == "*" {
			return true
		}
		if name, ok := strings.CutPrefix(term, "@"); ok {
			for _, member := range assetSets[name][network] {
				if member == asset {
					return true
				}
			}
			continue
		}
		if ref, err := parseAssetRefV1("", term); err == nil && ref == asset {
			return true
		}
	}
	return false
}

// requireRekeyAddressSet additionally requires a referenced set to be flat:
// rekey edges are not network-scoped.
func requireRekeyAddressSet(pointer, term string, addressSets map[string]AddressSetV1) error {
	if err := requireAddressSet(pointer, term, addressSets); err != nil {
		return err
	}
	if name, ok := strings.CutPrefix(term, "@"); ok && addressSets[name].ByNetwork != nil {
		return docErrorf(pointer, "rekey_policy cannot reference per-network address set %q", name)
	}
	return nil
}

func requireAddressSet(pointer, term string, addressSets map[string]AddressSetV1) error {
	if name, ok := strings.CutPrefix(term, "@"); ok {
		if _, exists := addressSets[name]; !exists {
			return docErrorf(pointer, "unknown address set %q", name)
		}
	}
	return nil
}

// mergeOverrideLimits applies a key override's thresholds to the document
// limits per network, asset, and threshold: a value replaces, null removes,
// and anything unmentioned is inherited.
func mergeOverrideLimits(base LimitsV1, override OverrideLimitsV1) LimitsV1 {
	merged := LimitsV1{}
	for network, assets := range base {
		merged[network] = make(map[TransferAssetRef]ThresholdsV1, len(assets))
		for asset, t := range assets {
			merged[network][asset] = t
		}
	}
	for network, assets := range override {
		for asset, ot := range assets {
			if merged[network] == nil {
				merged[network] = map[TransferAssetRef]ThresholdsV1{}
			}
			t := merged[network][asset]
			t.ReviewAbove = applyOverrideAmount(t.ReviewAbove, ot.ReviewAbove)
			t.RejectAbove = applyOverrideAmount(t.RejectAbove, ot.RejectAbove)
			if t.ReviewAbove == nil && t.RejectAbove == nil {
				delete(merged[network], asset)
			} else {
				merged[network][asset] = t
			}
			if len(merged[network]) == 0 {
				delete(merged, network)
			}
		}
	}
	return merged
}

func applyOverrideAmount(inherited *uint64, o OverrideAmountV1) *uint64 {
	switch {
	case !o.Set:
		return inherited
	case o.Null:
		return nil
	default:
		v := o.Value
		return &v
	}
}

func assetRefString(asset TransferAssetRef) string {
	if asset.Algo {
		return "algo"
	}
	return "asa:" + strconv.FormatUint(asset.ASAID, 10)
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
