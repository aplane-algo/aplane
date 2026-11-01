// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policyadmission checks a policy document against the node it is
// submitted to: every network it names must be one the node knows, every
// specific asset it names must be in the node's ASA set, a direct asa:<id>
// route term must sit in a route over exactly one network, and every route
// must be able to match some asset on each network it applies to.
//
// The checks are about what a document means on a node, not about what a
// transaction may do: they never change a verdict. They apply to documents
// as they are submitted; a stored document is only warned about. This
// package is pure.
package policyadmission

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policycontext"
)

// Rule IDs.
const (
	RuleUnknownNetwork        = "admission:unknown_network"
	RuleAmbiguousRouteAsset   = "admission:ambiguous_route_asset"
	RuleAssetNotInSet         = "admission:asset_not_in_set"
	RuleRouteNetworkUncovered = "admission:route_network_uncovered"
)

// Problem is one admission finding at a JSON Pointer in the document.
type Problem struct {
	RuleID  string
	Pointer string
	Message string
}

// Check returns doc's admission problems on the node ctx describes, sorted
// by pointer, then rule.
func Check(doc *policy.PolicyV1, ctx *policycontext.Context) []Problem {
	if doc == nil || ctx == nil {
		return nil
	}
	refs := doc.References()
	var out []Problem
	add := func(rule, pointer, format string, args ...any) {
		out = append(out, Problem{RuleID: rule, Pointer: pointer, Message: fmt.Sprintf(format, args...)})
	}

	// 1. Every network named is one the node knows.
	for _, n := range refs.Networks {
		if _, ok := ctx.Chain(n.Network); !ok {
			add(RuleUnknownNetwork, n.Pointer, "network %q is not one this node knows; map it in the node's networks config, or correct the name", n.Network)
		}
	}

	// 2. A direct asa:<id> term names one asset only in a single-network
	// route: the same ID is another asset, or none, on each chain.
	for _, d := range refs.DirectRouteAssets {
		if d.NetworkWildcard || len(d.Networks) != 1 {
			where := `"*"`
			if !d.NetworkWildcard {
				where = strings.Join(quoted(d.Networks), ", ")
			}
			add(RuleAmbiguousRouteAsset, d.Pointer, "route %q names asa:%d over networks %s; an asset ID names an asset on one chain only, so list one network, or use an asset set with a member per network", d.Route, d.AssetID, where)
		}
	}

	// 3. Every network/ASA pair named is in the node's ASA set.
	for _, a := range refs.Assets {
		if _, known := ctx.Chain(a.Network); !known {
			continue // rule 1 reports the network
		}
		if _, ok := ctx.Asset(a.Network, a.AssetID); !ok {
			add(RuleAssetNotInSet, a.Pointer, "asset %d on %s is not in this node's ASA set; add it with apadmin asa add %s %d", a.AssetID, a.Network, a.Network, a.AssetID)
		}
	}

	// 4. Every route can match some asset on each network it applies to:
	// the union of its alternatives covers the network.
	nodeNetworks := sortedTokens(ctx.Networks())
	for _, r := range refs.Routes {
		if r.AnyAsset {
			continue
		}
		networks := r.Networks
		if r.NetworkWildcard {
			networks = nodeNetworks
		}
		for _, net := range networks {
			if _, known := ctx.Chain(net); !known {
				continue // rule 1 reports the network
			}
			if len(r.DirectAssets) > 0 || setsCover(doc, r.Sets, net) {
				continue
			}
			via := ""
			if r.NetworkWildcard {
				via = ` (through "*")`
			}
			add(RuleRouteNetworkUncovered, r.Pointer+"/assets", "route %q applies to %s%s, but none of its assets has a member there; add one to its asset sets, or list only the networks it covers", r.Route, net, via)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Pointer != out[j].Pointer {
			return out[i].Pointer < out[j].Pointer
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// setsCover reports whether any of the named asset sets has a member on
// network.
func setsCover(doc *policy.PolicyV1, sets []string, network string) bool {
	for _, name := range sets {
		if len(doc.AssetSets[name][network]) > 0 {
			return true
		}
	}
	return false
}

func sortedTokens(networks map[string]asaset.GenesisHash) []string {
	out := make([]string, 0, len(networks))
	for token := range networks {
		out = append(out, token)
	}
	sort.Strings(out)
	return out
}

func quoted(list []string) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}
