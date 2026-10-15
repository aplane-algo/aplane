// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/policyschema"
)

// This file decodes and validates policy documents in format v1
// (docs/ARCH_POLICY.md). One format serves both node roles: the
// document's "role" field says which, and fields the role does not support
// are rejected. Decoding enforces every syntax and semantic rule, so a
// document that decodes is one the node may sign and enforce.

const maxPolicyDescriptionLength = 1024

// DefaultKey is the reserved document key of a node's default policy, the
// rulebook for every key without a policy of its own.
const DefaultKey = "default"

var (
	policyTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	policySetPattern   = regexp.MustCompile(`^[a-z0-9_-]+$`)
)

// TransactionTypeVerdict is a transaction type's verdict in a document's
// transaction_types map.
type TransactionTypeVerdict string

const (
	// TransactionTypeAllow lets the type continue through every other phase.
	TransactionTypeAllow TransactionTypeVerdict = "allow"
	// TransactionTypeReview is Always Review for the type.
	TransactionTypeReview TransactionTypeVerdict = "review"
	// TransactionTypeReject is Always Deny for the type.
	TransactionTypeReject TransactionTypeVerdict = "reject"
)

// TransactionTypeWildcard is the transaction_types entry for every type the
// map does not name. It is required whenever the map is present.
const TransactionTypeWildcard = "*"

// TransactionTypeNames lists every Algorand transaction type a policy can
// name, in a fixed order.
var TransactionTypeNames = []string{
	string(types.PaymentTx),
	string(types.AssetTransferTx),
	string(types.AssetConfigTx),
	string(types.AssetFreezeTx),
	string(types.KeyRegistrationTx),
	string(types.ApplicationCallTx),
	string(types.StateProofTx),
	string(types.HeartbeatTx),
}

// transferTransactionTypes are the types transfer routing governs, and the
// only types a cosigner document may allow.
var transferTransactionTypes = map[string]bool{
	string(types.PaymentTx):       true,
	string(types.AssetTransferTx): true,
}

// TransactionTypesV1 maps a transaction type, or "*", to its verdict.
type TransactionTypesV1 map[string]TransactionTypeVerdict

// Verdict resolves txType: the type's own entry, then "*", then reject, so an
// empty or nil map fails closed.
func (t TransactionTypesV1) Verdict(txType string) TransactionTypeVerdict {
	if v, ok := t[txType]; ok {
		return v
	}
	if v, ok := t[TransactionTypeWildcard]; ok {
		return v
	}
	return TransactionTypeReject
}

// Clone returns a copy of the map.
func (t TransactionTypesV1) Clone() TransactionTypesV1 {
	if t == nil {
		return nil
	}
	out := make(TransactionTypesV1, len(t))
	for k, v := range t {
		out[k] = v
	}
	return out
}

// ThresholdsV1 is one asset's review and reject thresholds in base units.
type ThresholdsV1 struct {
	ReviewAbove *uint64
	RejectAbove *uint64
}

// LimitsV1 maps network, then asset, to thresholds.
type LimitsV1 map[string]map[TransferAssetRef]ThresholdsV1

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

// RekeyRuleV1 is one allowed sender-to-targets rekey edge (cosigner only).
type RekeyRuleV1 struct {
	Sender  string
	Targets []string
}

// PolicyV1 is a decoded and validated policy document: a node's default
// (Key == DefaultKey) or one key's own policy. Every verdict-bearing field is
// required in the document, so none of these fields is a pointer; fields a
// role does not support are left at their zero value.
type PolicyV1 struct {
	Role        noderole.Role
	Key         string
	Description string

	// Common to both roles.
	RejectCloseRemainder bool
	RejectAssetClose     bool
	RejectClawback       bool
	MaxFeeMicroAlgos     uint64
	TransactionTypes     TransactionTypesV1
	Limits               LimitsV1
	AddressSets          map[string]AddressSetV1
	AssetSets            map[string]AssetSetV1
	BlockedDestinations  []types.Address
	Routes               []RouteV1

	// Signer only. A cosigner document rejects every route miss.
	RejectForeignRekey          bool
	AlwaysReviewWarnings        bool
	AutoApproveSelfNoOpTransfer bool
	OnNoRoute                   TransferOnNoRoute
	CloseOnNoRoute              TransferOnNoRoute
	ClawbackOnNoRoute           TransferOnNoRoute

	// Cosigner only.
	RejectRekey bool
	RekeyPolicy []RekeyRuleV1
}

// IsDefault reports whether the document is a node default.
func (d *PolicyV1) IsDefault() bool { return d.Key == DefaultKey }

// ValidateDocumentKey checks that key is DefaultKey or the canonical selector
// of a key the role holds: an Algorand address on a signer node, a Witness
// Key ID on a cosigner node.
func ValidateDocumentKey(role noderole.Role, key string) error {
	if key == DefaultKey {
		return nil
	}
	switch role {
	case noderole.RoleSigner:
		if addr, err := types.DecodeAddress(key); err != nil || addr.String() != key {
			return fmt.Errorf("a signer policy key must be %q or an Algorand address, not %q", DefaultKey, key)
		}
	case noderole.RoleCosigner:
		if id, err := witness.NormalizeID(key); err != nil || id != key {
			return fmt.Errorf("a cosigner policy key must be %q or a Witness Key ID, not %q", DefaultKey, key)
		}
	default:
		return fmt.Errorf("unsupported node role %q", role)
	}
	return nil
}

// DecodePolicyV1 decodes and validates one policy document for role. key is
// the document's file name (DefaultKey or a key selector); the signed "key"
// field must equal it, and the signed "role" field must equal role.
func DecodePolicyV1(data []byte, key string, role noderole.Role) (*PolicyV1, error) {
	if role != noderole.RoleSigner && role != noderole.RoleCosigner {
		return nil, fmt.Errorf("unsupported node role %q", role)
	}
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
	if format != policyschema.FormatV1 {
		return nil, docErrorf(formatNode.pointer, "unsupported format %q; expected %q", format, policyschema.FormatV1)
	}
	doc := &PolicyV1{}
	roleNode, err := r.required("role")
	if err != nil {
		return nil, err
	}
	rawRole, err := jsonString(roleNode)
	if err != nil {
		return nil, err
	}
	switch noderole.Role(rawRole) {
	case noderole.RoleSigner, noderole.RoleCosigner:
		doc.Role = noderole.Role(rawRole)
	default:
		return nil, docErrorf(roleNode.pointer, "role must be %q or %q", noderole.RoleSigner, noderole.RoleCosigner)
	}
	if doc.Role != role {
		return nil, docErrorf(roleNode.pointer, "a %s document is not accepted on a %s node", doc.Role, role)
	}
	signer := role == noderole.RoleSigner

	keyNode, err := r.required("key")
	if err != nil {
		return nil, err
	}
	if doc.Key, err = jsonString(keyNode); err != nil {
		return nil, err
	}
	if err := ValidateDocumentKey(role, doc.Key); err != nil {
		return nil, docErrorf(keyNode.pointer, "%v", err)
	}
	if doc.Key != key {
		return nil, docErrorf(keyNode.pointer, "key %q does not match its file name %q", doc.Key, key)
	}
	if doc.Description, err = optionalDescription(r); err != nil {
		return nil, err
	}

	// Scalars: required on both roles, required on one role and rejected on
	// the other.
	for _, f := range []struct {
		name string
		dst  *bool
		on   bool // accepted (and required) on this node role
	}{
		{"reject_foreign_rekey", &doc.RejectForeignRekey, signer},
		{"reject_close_remainder", &doc.RejectCloseRemainder, true},
		{"reject_asset_close", &doc.RejectAssetClose, true},
		{"reject_clawback", &doc.RejectClawback, true},
		{"reject_rekey", &doc.RejectRekey, !signer},
		{"always_review_warnings", &doc.AlwaysReviewWarnings, signer},
		{"auto_approve_self_noop_transfer", &doc.AutoApproveSelfNoOpTransfer, signer},
	} {
		if !f.on {
			if err := rejectRoleField(r, f.name, role); err != nil {
				return nil, err
			}
			continue
		}
		n, err := r.required(f.name)
		if err != nil {
			return nil, err
		}
		if *f.dst, err = jsonBool(n); err != nil {
			return nil, err
		}
	}
	feeNode, err := r.required("max_fee_microalgos")
	if err != nil {
		return nil, err
	}
	if doc.MaxFeeMicroAlgos, err = decodeAmount(feeNode); err != nil {
		return nil, err
	}

	typesNode, err := r.required("transaction_types")
	if err != nil {
		return nil, err
	}
	if doc.TransactionTypes, err = decodeTransactionTypes(typesNode, role); err != nil {
		return nil, err
	}
	if n := r.field("limits"); n != nil {
		if doc.Limits, err = decodeLimits(n, !signer); err != nil {
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
	for _, f := range []struct {
		name string
		dst  *TransferOnNoRoute
	}{
		{"on_no_route", &doc.OnNoRoute},
		{"close_on_no_route", &doc.CloseOnNoRoute},
		{"clawback_on_no_route", &doc.ClawbackOnNoRoute},
	} {
		if !signer {
			if err := rejectRoleField(tp, f.name, role); err != nil {
				return nil, err
			}
			*f.dst = TransferOnNoRouteReject
			continue
		}
		n, err := tp.required(f.name)
		if err != nil {
			return nil, err
		}
		if *f.dst, err = decodeRouteMissAction(n); err != nil {
			return nil, err
		}
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
	if doc.Routes, err = decodeRoutes(routesNode, !signer); err != nil {
		return nil, err
	}
	if err := tp.finish(); err != nil {
		return nil, err
	}

	if signer {
		if err := rejectRoleField(r, "rekey_policy", role); err != nil {
			return nil, err
		}
	} else if n := r.field("rekey_policy"); n != nil {
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

// rejectRoleField fails when a field the role does not support is present.
func rejectRoleField(r *jsonObjectReader, name string, role noderole.Role) error {
	if n := r.field(name); n != nil {
		return docErrorf(n.pointer, "%s is not accepted in a %s document", name, role)
	}
	return nil
}

func decodeRouteMissAction(n *jsonNode) (TransferOnNoRoute, error) {
	raw, err := jsonString(n)
	if err != nil {
		return "", err
	}
	action := TransferOnNoRoute(raw)
	switch action {
	case TransferOnNoRouteReject, TransferOnNoRouteReview, TransferOnNoRouteOperatorDefault:
		return action, nil
	default:
		return "", docErrorf(n.pointer, "must be one of reject, review, operator_default")
	}
}

// decodeTransactionTypes decodes the verdict map. A cosigner document may
// allow only pay and axfer, the types routing governs, and never reviews. "*"
// is required on a signer, where it is a choice; on a cosigner its only legal
// value is reject, so it may be omitted and Verdict resolves a missing entry
// to reject.
func decodeTransactionTypes(node *jsonNode, role noderole.Role) (TransactionTypesV1, error) {
	r, err := readJSONObject(node, "transaction_types")
	if err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(TransactionTypeNames))
	for _, name := range TransactionTypeNames {
		known[name] = true
	}
	out := make(TransactionTypesV1, len(node.keys))
	for _, name := range node.keys {
		n := r.field(name)
		if name != TransactionTypeWildcard && !known[name] {
			return nil, docErrorf(n.pointer, "unknown transaction type %q; expected %s or \"*\"", name, strings.Join(TransactionTypeNames, ", "))
		}
		raw, err := jsonString(n)
		if err != nil {
			return nil, err
		}
		verdict := TransactionTypeVerdict(raw)
		switch verdict {
		case TransactionTypeAllow, TransactionTypeReview, TransactionTypeReject:
		default:
			return nil, docErrorf(n.pointer, "must be one of allow, review, reject")
		}
		if role == noderole.RoleCosigner {
			switch {
			case verdict == TransactionTypeReview:
				return nil, docErrorf(n.pointer, "cosigner policy cannot produce review verdicts")
			case verdict == TransactionTypeAllow && !transferTransactionTypes[name]:
				return nil, docErrorf(n.pointer, "a cosigner document may allow only pay and axfer; routing is its only authorization surface")
			}
		}
		out[name] = verdict
	}
	if _, ok := out[TransactionTypeWildcard]; !ok && role != noderole.RoleCosigner {
		return nil, docErrorf(node.pointer, "missing required field %q", TransactionTypeWildcard)
	}
	return out, r.finish()
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

func (d *PolicyV1) validate() error {
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
