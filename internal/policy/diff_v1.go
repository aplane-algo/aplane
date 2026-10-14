// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// This file compares two decoded policy documents and describes each
// difference in operator terms, so a change can be reviewed before it is
// applied. Comparing decoded documents ignores formatting and key order.
//
// A key is governed by exactly one document, so an effective comparison is
// always between two documents: the one that governs the key now (its own,
// or the node default) and the one that will. Callers choose the pair; see
// policyreview.

// PolicyChangeEffect says whether a change makes the policy allow less or
// more.
type PolicyChangeEffect string

const (
	PolicyChangeTightened PolicyChangeEffect = "tightened"
	PolicyChangeLoosened  PolicyChangeEffect = "loosened"
	PolicyChangeNeutral   PolicyChangeEffect = "changed"
)

// PolicyChange is one difference between two policy documents. Path locates
// it, naming routes by id.
type PolicyChange struct {
	Path    string
	Effect  PolicyChangeEffect
	Summary string
}

// DiffPolicyV1 describes how next differs from current. Both documents must
// decode for the same role; the key may differ, as when a key's new policy
// is compared with the default it followed.
func DiffPolicyV1(current, next *PolicyV1) []PolicyChange {
	var d policyDiff
	d.text("/description", current.Description, next.Description)
	for _, f := range []struct {
		name           string
		cur, nxt       bool
		strictWhenTrue bool
	}{
		{"reject_foreign_rekey", current.RejectForeignRekey, next.RejectForeignRekey, true},
		{"reject_close_remainder", current.RejectCloseRemainder, next.RejectCloseRemainder, true},
		{"reject_asset_close", current.RejectAssetClose, next.RejectAssetClose, true},
		{"reject_clawback", current.RejectClawback, next.RejectClawback, true},
		{"reject_rekey", current.RejectRekey, next.RejectRekey, true},
		{"always_review_warnings", current.AlwaysReviewWarnings, next.AlwaysReviewWarnings, true},
		{"auto_approve_self_noop_transfer", current.AutoApproveSelfNoOpTransfer, next.AutoApproveSelfNoOpTransfer, false},
	} {
		d.boolSetting("/"+f.name, f.cur, f.nxt, f.strictWhenTrue)
	}
	d.feeCap("/max_fee_microalgos", current.MaxFeeMicroAlgos, next.MaxFeeMicroAlgos)
	d.transactionTypes(current.TransactionTypes, next.TransactionTypes)
	d.limits("/limits", current.Limits, next.Limits)
	d.sets(current.AddressSets, next.AddressSets, current.AssetSets, next.AssetSets, current.Routes, next.Routes, current.RekeyPolicy, next.RekeyPolicy)
	d.noRoute("/transfer_policy/on_no_route", current.OnNoRoute, next.OnNoRoute)
	d.noRoute("/transfer_policy/close_on_no_route", current.CloseOnNoRoute, next.CloseOnNoRoute)
	d.noRoute("/transfer_policy/clawback_on_no_route", current.ClawbackOnNoRoute, next.ClawbackOnNoRoute)
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

// feeCap reports a fee cap change. A cap of zero is enforced as no cap.
func (d *policyDiff) feeCap(path string, current, next uint64) {
	switch {
	case current == next:
	case current == 0:
		d.add(path, PolicyChangeTightened, "no cap → %s", formatAlgoAmount(next))
	case next == 0:
		d.add(path, PolicyChangeLoosened, "%s → no cap", formatAlgoAmount(current))
	default:
		d.amountChange(path, algoAssetRef, current, next)
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

// verdictStrictness ranks transaction type verdicts from loosest.
func verdictStrictness(v TransactionTypeVerdict) int {
	switch v {
	case TransactionTypeReview:
		return 1
	case TransactionTypeReject:
		return 2
	default:
		return 0
	}
}

// transactionTypes compares the effective verdict of every transaction type,
// so a change to "*" is reported on each type it reaches.
func (d *policyDiff) transactionTypes(current, next TransactionTypesV1) {
	for _, txType := range TransactionTypeNames {
		c, n := current.Verdict(txType), next.Verdict(txType)
		if c == n {
			continue
		}
		effect := PolicyChangeLoosened
		if verdictStrictness(n) > verdictStrictness(c) {
			effect = PolicyChangeTightened
		}
		d.add("/transaction_types/"+txType, effect, "%s → %s", c, n)
	}
}

// limits compares thresholds.
func (d *policyDiff) limits(prefix string, current, next LimitsV1) {
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

// noRouteStrictness ranks route-miss actions from loosest.
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

func (d *policyDiff) noRoute(path string, current, next TransferOnNoRoute) {
	if current == "" {
		current = TransferOnNoRouteReject
	}
	if next == "" {
		next = TransferOnNoRouteReject
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
		d.limits(path+"/limits", c.Limits, n.Limits)
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
