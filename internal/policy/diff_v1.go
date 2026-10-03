// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// This file compares decoded v1 policy documents and describes each
// difference in operator terms, so a change can be reviewed before it is
// applied. Comparing decoded documents ignores formatting and key order.

// PolicyChangeEffect says whether a change makes the policy allow less or
// more.
type PolicyChangeEffect string

const (
	PolicyChangeTightened PolicyChangeEffect = "tightened"
	PolicyChangeLoosened  PolicyChangeEffect = "loosened"
	PolicyChangeNeutral   PolicyChangeEffect = "changed"
)

// PolicyChange is one difference between two policy documents. Path locates
// it, naming routes by id and key overrides by address.
type PolicyChange struct {
	Path    string
	Effect  PolicyChangeEffect
	Summary string
}

// DiffSignerPolicyV1 describes how next differs from current.
func DiffSignerPolicyV1(current, next *SignerPolicyV1) []PolicyChange {
	var d policyDiff
	d.text("/description", current.Description, next.Description)
	d.signerSettings("", current.SignerSettingsV1, next.SignerSettingsV1, current.SignerSettingsV1, next.SignerSettingsV1, nil)
	d.limits("/limits", current.Limits, next.Limits, nil)
	d.sets(current.AddressSets, next.AddressSets, current.AssetSets, next.AssetSets, signerRoutes(current), signerRoutes(next), nil, nil)
	d.signerTransferPolicy(current.TransferPolicy, next.TransferPolicy)
	d.keyOverrides(current, next)
	return d.sorted()
}

// DiffCosignerPolicyV1 describes how next differs from current for one
// cosigner key. A nil current means the key had no policy and rejected every
// request; a nil next means the policy is being removed.
func DiffCosignerPolicyV1(current, next *CosignerPolicyV1) []PolicyChange {
	switch {
	case current == nil && next == nil:
		return nil
	case current == nil:
		return []PolicyChange{{Path: "/", Effect: PolicyChangeLoosened, Summary: "new policy; the key rejected every request without one"}}
	case next == nil:
		return []PolicyChange{{Path: "/", Effect: PolicyChangeTightened, Summary: "policy removed; the key will reject every request"}}
	}
	var d policyDiff
	d.text("/description", current.Description, next.Description)
	for _, f := range []struct {
		name     string
		cur, nxt *bool
	}{
		{"reject_close_remainder", current.RejectCloseRemainder, next.RejectCloseRemainder},
		{"reject_asset_close", current.RejectAssetClose, next.RejectAssetClose},
		{"reject_clawback", current.RejectClawback, next.RejectClawback},
		{"reject_rekey", current.RejectRekey, next.RejectRekey},
	} {
		d.boolSetting("/"+f.name, effectiveBool(f.cur, false), effectiveBool(f.nxt, false), true)
	}
	d.feeCap("/max_fee_microalgos", current.MaxFeeMicroAlgos, next.MaxFeeMicroAlgos)
	d.limits("/limits", current.Limits, next.Limits, nil)
	d.sets(current.AddressSets, next.AddressSets, current.AssetSets, next.AssetSets, current.Routes, next.Routes, current.RekeyPolicy, next.RekeyPolicy)
	d.addresses("/transfer_policy/blocked_destinations", current.BlockedDestinations, next.BlockedDestinations, PolicyChangeTightened)
	d.routes(current.Routes, next.Routes)
	d.rekeyRules(current.RekeyPolicy, next.RekeyPolicy)
	return d.sorted()
}

type policyDiff struct {
	changes []PolicyChange
}

func (d *policyDiff) add(path string, effect PolicyChangeEffect, format string, args ...any) {
	d.changes = append(d.changes, PolicyChange{Path: path, Effect: effect, Summary: fmt.Sprintf(format, args...)})
}

func (d *policyDiff) sorted() []PolicyChange {
	slices.SortStableFunc(d.changes, func(a, b PolicyChange) int { return strings.Compare(a.Path, b.Path) })
	return d.changes
}

func (d *policyDiff) text(path, current, next string) {
	if current != next {
		d.add(path, PolicyChangeNeutral, "%q → %q", current, next)
	}
}

// boolSetting reports a flag change. strictWhenTrue says whether true is the
// stricter value.
func (d *policyDiff) boolSetting(path string, current, next, strictWhenTrue bool) {
	if current == next {
		return
	}
	effect := PolicyChangeLoosened
	if next == strictWhenTrue {
		effect = PolicyChangeTightened
	}
	d.add(path, effect, "%t → %t", current, next)
}

func effectiveBool(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func (d *policyDiff) feeCap(path string, current, next *uint64) {
	// A cap of zero is enforced as no cap.
	if current != nil && *current == 0 {
		current = nil
	}
	if next != nil && *next == 0 {
		next = nil
	}
	switch {
	case current == nil && next == nil:
	case current == nil:
		d.add(path, PolicyChangeTightened, "no cap → %s", formatAlgoAmount(*next))
	case next == nil:
		d.add(path, PolicyChangeLoosened, "%s → no cap", formatAlgoAmount(*current))
	case *current != *next:
		d.amountChange(path, algoAssetRef, *current, *next)
	}
}

func (d *policyDiff) amountChange(path string, asset TransferAssetRef, current, next uint64) {
	effect := PolicyChangeTightened
	if next > current {
		effect = PolicyChangeLoosened
	}
	d.add(path, effect, "%s → %s", formatAssetAmount(asset, current), formatAssetAmount(asset, next))
}

// algoAssetRef is the ALGO asset reference.
var algoAssetRef = TransferAssetRef{Algo: true}

func formatAssetAmount(asset TransferAssetRef, amount uint64) string {
	if asset.Algo {
		return formatAlgoAmount(amount)
	}
	return fmt.Sprintf("%d base units", amount)
}

// limits compares thresholds. only, when non-nil, restricts the comparison
// to the listed network/asset/threshold entries.
func (d *policyDiff) limits(prefix string, current, next LimitsV1, only map[string]bool) {
	type entry struct {
		network string
		asset   TransferAssetRef
		name    string
	}
	values := func(l LimitsV1) map[entry]uint64 {
		out := map[entry]uint64{}
		for network, assets := range l {
			for asset, t := range assets {
				if t.ReviewAbove != nil {
					out[entry{network, asset, "review_above"}] = *t.ReviewAbove
				}
				if t.RejectAbove != nil {
					out[entry{network, asset, "reject_above"}] = *t.RejectAbove
				}
			}
		}
		return out
	}
	cur, nxt := values(current), values(next)
	keys := map[entry]bool{}
	for k := range cur {
		keys[k] = true
	}
	for k := range nxt {
		keys[k] = true
	}
	for k := range keys {
		path := fmt.Sprintf("%s/%s/%s/%s", prefix, k.network, assetRefString(k.asset), k.name)
		if only != nil && !only[path] {
			continue
		}
		c, hadC := cur[k]
		n, hasN := nxt[k]
		switch {
		case hadC && !hasN:
			d.add(path, PolicyChangeLoosened, "%s → none", formatAssetAmount(k.asset, c))
		case !hadC && hasN:
			d.add(path, PolicyChangeTightened, "none → %s", formatAssetAmount(k.asset, n))
		case c != n:
			d.amountChange(path, k.asset, c, n)
		}
	}
}

func (d *policyDiff) signerSettings(prefix string, cur, nxt SignerSettingsV1, curBase, nxtBase SignerSettingsV1, only map[string]bool) {
	for _, f := range []struct {
		name           string
		c, n, cb, nb   *bool
		def            bool
		strictWhenTrue bool
	}{
		{"reject_foreign_rekey", cur.RejectForeignRekey, nxt.RejectForeignRekey, curBase.RejectForeignRekey, nxtBase.RejectForeignRekey, true, true},
		{"reject_close_remainder", cur.RejectCloseRemainder, nxt.RejectCloseRemainder, curBase.RejectCloseRemainder, nxtBase.RejectCloseRemainder, false, true},
		{"reject_asset_close", cur.RejectAssetClose, nxt.RejectAssetClose, curBase.RejectAssetClose, nxtBase.RejectAssetClose, false, true},
		{"reject_clawback", cur.RejectClawback, nxt.RejectClawback, curBase.RejectClawback, nxtBase.RejectClawback, false, true},
		{"always_review_warnings", cur.AlwaysReviewWarnings, nxt.AlwaysReviewWarnings, curBase.AlwaysReviewWarnings, nxtBase.AlwaysReviewWarnings, false, true},
		{"auto_approve_self_noop_transfer", cur.AutoApproveSelfNoOpTransfer, nxt.AutoApproveSelfNoOpTransfer, curBase.AutoApproveSelfNoOpTransfer, nxtBase.AutoApproveSelfNoOpTransfer, false, false},
	} {
		if only != nil && f.c == nil && f.n == nil {
			continue
		}
		c := effectiveBool(f.c, effectiveBool(f.cb, f.def))
		n := effectiveBool(f.n, effectiveBool(f.nb, f.def))
		d.boolSetting(prefix+"/"+f.name, c, n, f.strictWhenTrue)
		if only != nil && c == n && (f.c == nil) != (f.n == nil) {
			d.pinChange(prefix+"/"+f.name, f.n != nil, fmt.Sprint(n))
		}
	}
	if only == nil || cur.MaxFeeMicroAlgos != nil || nxt.MaxFeeMicroAlgos != nil {
		c, n := cur.MaxFeeMicroAlgos, nxt.MaxFeeMicroAlgos
		if c == nil {
			c = curBase.MaxFeeMicroAlgos
		}
		if n == nil {
			n = nxtBase.MaxFeeMicroAlgos
		}
		before := len(d.changes)
		d.feeCap(prefix+"/max_fee_microalgos", c, n)
		if only != nil && len(d.changes) == before && (cur.MaxFeeMicroAlgos == nil) != (nxt.MaxFeeMicroAlgos == nil) {
			value := "no cap"
			if n != nil && *n != 0 {
				value = formatAlgoAmount(*n)
			}
			d.pinChange(prefix+"/max_fee_microalgos", nxt.MaxFeeMicroAlgos != nil, value)
		}
	}
}

// pinChange reports an override field moving between inherited and set
// explicitly while its value stays the same. It changes nothing today but
// decides whether later document changes reach the key.
func (d *policyDiff) pinChange(path string, explicit bool, value string) {
	if explicit {
		d.add(path, PolicyChangeNeutral, "inherited %s → set explicitly to %s", value, value)
	} else {
		d.add(path, PolicyChangeNeutral, "set explicitly to %s → inherited %s", value, value)
	}
}

// noRouteStrictness ranks route-miss actions from strictest.
func noRouteStrictness(action TransferOnNoRoute) int {
	switch action {
	case TransferOnNoRouteReview:
		return 1
	case TransferOnNoRouteOperatorDefault:
		return 0
	default:
		return 2
	}
}

func (d *policyDiff) noRoute(path string, current, next, def TransferOnNoRoute) {
	if current == "" {
		current = def
	}
	if next == "" {
		next = def
	}
	if current == next {
		return
	}
	effect := PolicyChangeLoosened
	if noRouteStrictness(next) > noRouteStrictness(current) {
		effect = PolicyChangeTightened
	}
	d.add(path, effect, "%s → %s", current, next)
}

func (d *policyDiff) signerTransferPolicy(current, next *SignerTransferPolicyV1) {
	cur, nxt := SignerTransferPolicyV1{}, SignerTransferPolicyV1{}
	if current != nil {
		cur = *current
	}
	if next != nil {
		nxt = *next
	}
	d.boolSetting("/transfer_policy/enabled", cur.Enabled, nxt.Enabled, true)
	d.noRoute("/transfer_policy/on_no_route", cur.OnNoRoute, nxt.OnNoRoute, TransferOnNoRouteReject)
	d.noRoute("/transfer_policy/close_on_no_route", cur.CloseOnNoRoute, nxt.CloseOnNoRoute, TransferOnNoRouteReject)
	d.noRoute("/transfer_policy/clawback_on_no_route", cur.ClawbackOnNoRoute, nxt.ClawbackOnNoRoute, TransferOnNoRouteReject)
	d.addresses("/transfer_policy/blocked_destinations", cur.BlockedDestinations, nxt.BlockedDestinations, PolicyChangeTightened)
	d.routes(cur.Routes, nxt.Routes)
}

func signerRoutes(doc *SignerPolicyV1) []RouteV1 {
	if doc.TransferPolicy == nil {
		return nil
	}
	return doc.TransferPolicy.Routes
}

// addresses reports addresses added to or removed from a list. addEffect is
// the effect of adding one.
func (d *policyDiff) addresses(path string, current, next []types.Address, addEffect PolicyChangeEffect) {
	cur := make([]string, 0, len(current))
	for _, a := range current {
		cur = append(cur, a.String())
	}
	nxt := make([]string, 0, len(next))
	for _, a := range next {
		nxt = append(nxt, a.String())
	}
	d.members(path, cur, nxt, addEffect)
}

func (d *policyDiff) members(path string, current, next []string, addEffect PolicyChangeEffect) {
	removeEffect := opposite(addEffect)
	for _, m := range sortedDifference(next, current) {
		d.add(path, addEffect, "added %s", m)
	}
	for _, m := range sortedDifference(current, next) {
		d.add(path, removeEffect, "removed %s", m)
	}
}

func opposite(effect PolicyChangeEffect) PolicyChangeEffect {
	switch effect {
	case PolicyChangeTightened:
		return PolicyChangeLoosened
	case PolicyChangeLoosened:
		return PolicyChangeTightened
	default:
		return PolicyChangeNeutral
	}
}

func sortedDifference(a, b []string) []string {
	var out []string
	for _, v := range a {
		if !slices.Contains(b, v) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

// sets compares named sets. Membership changes in a set some route or rekey
// rule references loosen when they add and tighten when they remove.
func (d *policyDiff) sets(curAddr, nxtAddr map[string]AddressSetV1, curAsset, nxtAsset map[string]AssetSetV1, curRoutes, nxtRoutes []RouteV1, curRekey, nxtRekey []RekeyRuleV1) {
	used := map[string]bool{}
	for _, routes := range [][]RouteV1{curRoutes, nxtRoutes} {
		for _, r := range routes {
			for _, terms := range [][]string{r.Sources, r.Destinations, r.AssetSources, r.Assets} {
				for _, term := range terms {
					if name, ok := strings.CutPrefix(term, "@"); ok {
						used[name] = true
					}
				}
			}
		}
	}
	for _, rules := range [][]RekeyRuleV1{curRekey, nxtRekey} {
		for _, rule := range rules {
			for _, term := range append([]string{rule.Sender}, rule.Targets...) {
				if name, ok := strings.CutPrefix(term, "@"); ok {
					used[name] = true
				}
			}
		}
	}
	effectFor := func(name string) PolicyChangeEffect {
		if used[name] {
			return PolicyChangeLoosened
		}
		return PolicyChangeNeutral
	}
	for _, name := range unionKeys(curAddr, nxtAddr) {
		path := "/address_sets/" + name
		c, hadC := curAddr[name]
		n, hasN := nxtAddr[name]
		switch {
		case !hadC:
			d.add(path, PolicyChangeNeutral, "set added")
		case !hasN:
			d.add(path, PolicyChangeNeutral, "set removed")
		default:
			for _, network := range addressSetNetworks(c, n) {
				p := path
				switch network {
				case "":
				case otherNetworks:
					p += "/(other networks)"
				default:
					p += "/" + network
				}
				d.addresses(p, addressSetMembers(c, network), addressSetMembers(n, network), effectFor(name))
			}
		}
	}
	for _, name := range unionKeys(curAsset, nxtAsset) {
		path := "/asset_sets/" + name
		c, hadC := curAsset[name]
		n, hasN := nxtAsset[name]
		switch {
		case !hadC:
			d.add(path, PolicyChangeNeutral, "set added")
		case !hasN:
			d.add(path, PolicyChangeNeutral, "set removed")
		default:
			for _, network := range unionKeys(c, n) {
				d.members(path+"/"+network, assetRefStrings(c[network]), assetRefStrings(n[network]), effectFor(name))
			}
		}
	}
}

// otherNetworks stands for every network a per-network set does not name.
const otherNetworks = "\x00other"

// addressSetNetworks lists the networks to compare two address sets on. Two
// flat sets compare once (""). When either is per-network, each named network
// is compared, plus otherNetworks, where a flat set's members still apply.
func addressSetNetworks(a, b AddressSetV1) []string {
	if a.ByNetwork == nil && b.ByNetwork == nil {
		return []string{""}
	}
	return append(unionKeys(a.ByNetwork, b.ByNetwork), otherNetworks)
}

// addressSetMembers returns the members a set covers on network.
func addressSetMembers(set AddressSetV1, network string) []types.Address {
	if set.ByNetwork == nil {
		return set.Flat
	}
	if network == otherNetworks {
		return nil
	}
	return set.ByNetwork[network]
}

func assetRefStrings(refs []TransferAssetRef) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, assetRefString(ref))
	}
	return out
}

func unionKeys[V any](a, b map[string]V) []string {
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (d *policyDiff) routes(current, next []RouteV1) {
	byID := func(routes []RouteV1) map[string]RouteV1 {
		out := make(map[string]RouteV1, len(routes))
		for _, r := range routes {
			out[r.ID] = r
		}
		return out
	}
	cur, nxt := byID(current), byID(next)
	for _, id := range unionKeys(cur, nxt) {
		path := "/transfer_policy/routes/" + id
		c, hadC := cur[id]
		n, hasN := nxt[id]
		switch {
		case !hadC:
			d.add(path, PolicyChangeLoosened, "route added")
			continue
		case !hasN:
			d.add(path, PolicyChangeTightened, "route removed")
			continue
		}
		d.text(path+"/description", c.Description, n.Description)
		d.members(path+"/networks", routeNetworks(c), routeNetworks(n), PolicyChangeLoosened)
		d.members(path+"/sources", c.Sources, n.Sources, PolicyChangeLoosened)
		d.members(path+"/assets", c.Assets, n.Assets, PolicyChangeLoosened)
		d.members(path+"/destinations", c.Destinations, n.Destinations, PolicyChangeLoosened)
		d.members(path+"/asset_sources", c.AssetSources, n.AssetSources, PolicyChangeLoosened)
		d.limits(path+"/limits", c.Limits, n.Limits, nil)
		d.boolSetting(path+"/allow_close", c.AllowClose, n.AllowClose, false)
		d.boolSetting(path+"/allow_clawback", c.AllowClawback, n.AllowClawback, false)
	}
}

func routeNetworks(r RouteV1) []string {
	if r.NetworkWildcard {
		return []string{"*"}
	}
	return r.Networks
}

func (d *policyDiff) rekeyRules(current, next []RekeyRuleV1) {
	edges := func(rules []RekeyRuleV1) []string {
		var out []string
		for _, rule := range rules {
			for _, target := range rule.Targets {
				out = append(out, rule.Sender+" → "+target)
			}
		}
		return out
	}
	d.members("/rekey_policy/allowed", edges(current), edges(next), PolicyChangeLoosened)
}

// keyOverrides compares each key's effective settings and limits, limited to
// the fields its override sets in either document.
func (d *policyDiff) keyOverrides(current, next *SignerPolicyV1) {
	for _, key := range unionKeys(current.KeyOverrides, next.KeyOverrides) {
		path := "/key_overrides/" + key
		c, hadC := current.KeyOverrides[key]
		n, hasN := next.KeyOverrides[key]
		switch {
		case !hadC:
			d.add(path, PolicyChangeNeutral, "override added")
		case !hasN:
			d.add(path, PolicyChangeNeutral, "override removed; the key follows the document settings")
		}
		d.text(path+"/description", c.Description, n.Description)
		d.signerSettings(path, c.SignerSettingsV1, n.SignerSettingsV1, current.SignerSettingsV1, next.SignerSettingsV1, map[string]bool{})
		mentioned := map[string]bool{}
		for _, ov := range []OverrideLimitsV1{c.Limits, n.Limits} {
			for network, assets := range ov {
				for asset, t := range assets {
					base := fmt.Sprintf("%s/limits/%s/%s/", path, network, assetRefString(asset))
					if t.ReviewAbove.Set {
						mentioned[base+"review_above"] = true
					}
					if t.RejectAbove.Set {
						mentioned[base+"reject_above"] = true
					}
				}
			}
		}
		if len(mentioned) > 0 {
			before := map[string]bool{}
			for _, ch := range d.changes {
				before[ch.Path] = true
			}
			d.limits(path+"/limits", mergeOverrideLimits(current.Limits, c.Limits), mergeOverrideLimits(next.Limits, n.Limits), mentioned)
			reported := map[string]bool{}
			for _, ch := range d.changes {
				if !before[ch.Path] {
					reported[ch.Path] = true
				}
			}
			for _, p := range sortedSetKeys(mentioned) {
				if reported[p] {
					continue
				}
				if was, now := overrideThresholdState(c.Limits, p, path), overrideThresholdState(n.Limits, p, path); was != now {
					d.add(p, PolicyChangeNeutral, "%s → %s", was, now)
				}
			}
		}
	}
}

func sortedSetKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// overrideThresholdState describes how an override treats one threshold
// path: inherited, removed with null, or set to a value.
func overrideThresholdState(limits OverrideLimitsV1, path, overridePath string) string {
	rest := strings.TrimPrefix(path, overridePath+"/limits/")
	parts := strings.Split(rest, "/")
	if len(parts) != 3 {
		return "inherited"
	}
	asset, err := parseAssetRefV1("", parts[1])
	if err != nil {
		return "inherited"
	}
	t, ok := limits[parts[0]][asset]
	if !ok {
		return "inherited"
	}
	amount := t.ReviewAbove
	if parts[2] == "reject_above" {
		amount = t.RejectAbove
	}
	switch {
	case !amount.Set:
		return "inherited"
	case amount.Null:
		return "removed explicitly"
	default:
		return "set explicitly to " + formatAssetAmount(asset, amount.Value)
	}
}
