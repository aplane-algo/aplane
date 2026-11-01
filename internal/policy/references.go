// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// References is everything a document names that only means something on a
// node: network tokens, and specific assets on a network. Each comes with the
// JSON Pointer it was named at. Admission checks them against the node's
// networks and ASA set; editors label them.
type References struct {
	// Networks is every network token the document names: route networks,
	// limits keys (top-level and per route), asset set keys and network-keyed
	// address set keys.
	Networks []NetworkRef
	// Assets is every explicit network/ASA pair: limits keys, asset set
	// members, and direct route terms in a route that lists one network.
	Assets []AssetRef
	// DirectRouteAssets is every direct asa:<id> route term with the networks
	// its route applies to. A term under more than one network, or under "*",
	// does not name one asset (the same ID is another asset, or none, on each
	// chain), and is also listed here.
	DirectRouteAssets []DirectRouteAsset
	// Routes holds each route's asset alternatives, for checking that a route
	// can match some asset on every network it applies to.
	Routes []RouteAssets
}

// NetworkRef is a network token and where it is named.
type NetworkRef struct {
	Network string
	Pointer string
}

// AssetRef is a specific ASA on a network and where it is named.
type AssetRef struct {
	Network string
	AssetID uint64
	Pointer string
	// Set names the asset set the reference is a member of, if any.
	Set string
}

// DirectRouteAsset is an asa:<id> term written directly in a route.
type DirectRouteAsset struct {
	AssetID         uint64
	Pointer         string
	Route           string // the route's id
	NetworkWildcard bool
	Networks        []string
}

// RouteAssets is one route's networks and asset alternatives.
type RouteAssets struct {
	Route           string
	Pointer         string
	NetworkWildcard bool
	Networks        []string
	// AnyAsset is set when an alternative means the same on every network:
	// "*" or "algo".
	AnyAsset bool
	// Sets are the asset sets the route uses, and DirectAssets its direct
	// asa:<id> terms.
	Sets         []string
	DirectAssets []uint64
}

// References lists what d names that only a node can resolve, sorted by
// pointer within each kind.
func (d *PolicyV1) References() References {
	var refs References
	if d == nil {
		return refs
	}
	network := func(token, pointer string) {
		refs.Networks = append(refs.Networks, NetworkRef{Network: token, Pointer: pointer})
	}
	limits := func(base string, l LimitsV1) {
		for net, assets := range l {
			network(net, base+"/"+escapeJSONPointer(net))
			for asset := range assets {
				if asset.ASAID != 0 {
					refs.Assets = append(refs.Assets, AssetRef{
						Network: net,
						AssetID: asset.ASAID,
						Pointer: base + "/" + escapeJSONPointer(net) + "/" + escapeJSONPointer(assetKey(asset)),
					})
				}
			}
		}
	}

	limits("/limits", d.Limits)
	for name, set := range d.AssetSets {
		base := "/asset_sets/" + escapeJSONPointer(name)
		for net, members := range set {
			network(net, base+"/"+escapeJSONPointer(net))
			for i, asset := range members {
				if asset.ASAID != 0 {
					refs.Assets = append(refs.Assets, AssetRef{
						Network: net,
						AssetID: asset.ASAID,
						Pointer: base + "/" + escapeJSONPointer(net) + "/" + strconv.Itoa(i),
						Set:     name,
					})
				}
			}
		}
	}
	for name, set := range d.AddressSets {
		for net := range set.ByNetwork {
			network(net, "/address_sets/"+escapeJSONPointer(name)+"/"+escapeJSONPointer(net))
		}
	}
	for i, route := range d.Routes {
		base := "/transfer_policy/routes/" + strconv.Itoa(i)
		for j, net := range route.Networks {
			network(net, base+"/networks/"+strconv.Itoa(j))
		}
		limits(base+"/limits", route.Limits)
		ra := RouteAssets{Route: route.ID, Pointer: base, NetworkWildcard: route.NetworkWildcard, Networks: append([]string(nil), route.Networks...)}
		for j, term := range route.Assets {
			pointer := base + "/assets/" + strconv.Itoa(j)
			switch {
			case term == "*" || term == "algo":
				ra.AnyAsset = true
			case strings.HasPrefix(term, "@"):
				ra.Sets = append(ra.Sets, strings.TrimPrefix(term, "@"))
			case strings.HasPrefix(term, "asa:"):
				id, err := strconv.ParseUint(strings.TrimPrefix(term, "asa:"), 10, 64)
				if err != nil {
					// The decoder accepted the term, so this cannot happen.
					panic(fmt.Sprintf("policy: decoded route asset term %q: %v", term, err))
				}
				ra.DirectAssets = append(ra.DirectAssets, id)
				refs.DirectRouteAssets = append(refs.DirectRouteAssets, DirectRouteAsset{
					AssetID: id, Pointer: pointer, Route: route.ID,
					NetworkWildcard: route.NetworkWildcard, Networks: append([]string(nil), route.Networks...),
				})
				if !route.NetworkWildcard && len(route.Networks) == 1 {
					refs.Assets = append(refs.Assets, AssetRef{Network: route.Networks[0], AssetID: id, Pointer: pointer})
				}
			}
		}
		refs.Routes = append(refs.Routes, ra)
	}

	sort.Slice(refs.Networks, func(i, j int) bool { return refs.Networks[i].Pointer < refs.Networks[j].Pointer })
	sort.Slice(refs.Assets, func(i, j int) bool { return refs.Assets[i].Pointer < refs.Assets[j].Pointer })
	return refs
}

// assetKey is an asset's spelling as a limits key.
func assetKey(a TransferAssetRef) string {
	if a.Algo {
		return "algo"
	}
	return "asa:" + strconv.FormatUint(a.ASAID, 10)
}
