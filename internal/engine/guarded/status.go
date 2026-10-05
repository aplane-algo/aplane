// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package guarded

import (
	"context"
	"sort"

	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// Connection and account observation states. They are display text as well as
// classifications, so callers compare against these names rather than literals.
const (
	ConnectionStateNotChecked      = "not checked"
	ConnectionStateReachable       = "reachable; authenticated"
	ConnectionStateHostKeyMismatch = "SSH host-key mismatch"

	AccountRouteAvailable       = "cosigner route available"
	AccountRouteMissing         = "no matching live route observed"
	AccountRouteDuplicate       = "duplicate witness route"
	AccountRouteCheckIncomplete = "route check incomplete"
	AccountRouteInvalidMetadata = "invalid metadata"
)

// RouteStatus is a point-in-time observation, not permission to sign.
type RouteStatus struct {
	Connections     []ConnectionObservation   `json:"connections"`
	Accounts        []AccountRouteObservation `json:"accounts"`
	DuplicateRoutes map[string][]string       `json:"duplicate_routes,omitempty"`
	DiscoveryError  string                    `json:"discovery_error,omitempty"`
}

type ConnectionObservation struct {
	Alias     string   `json:"alias"`
	URL       string   `json:"url"`
	State     string   `json:"state"`
	Witnesses []string `json:"witness_key_ids"`
	Error     string   `json:"error,omitempty"`
}

type AccountRouteObservation struct {
	Address      string   `json:"address"`
	WitnessKeyID string   `json:"witness_key_id,omitempty"`
	Routes       []string `json:"routes"`
	State        string   `json:"state"`
	Error        string   `json:"error,omitempty"`
}

// InspectRoutes uses the signing resolver's sweep and uniqueness rules, then
// closes all connections. It never caches inventories or asks for host trust.
func (s *Signer) InspectRoutes(ctx context.Context, keys []signerapi.KeyInfo) RouteStatus {
	aliases, states, sweepErr := s.probeCosignerEndpoints(ctx)
	defer closeProbeResults(states, nil)
	result := RouteStatus{Connections: []ConnectionObservation{}, Accounts: []AccountRouteObservation{}}
	if sweepErr != nil {
		result.DiscoveryError = sweepErr.Error()
	}
	for i, alias := range aliases {
		row := ConnectionObservation{Alias: alias, URL: s.endpointRegistry.Endpoints[alias].URL, State: ConnectionStateNotChecked, Witnesses: []string{}}
		if i < len(states) && states[i] != nil {
			state := states[i]
			if state.err != nil {
				row.State = cosignerDiscoveryFailureLabel(state.err)
				row.Error = state.err.Error()
			} else {
				row.State = ConnectionStateReachable
				for _, key := range state.keys {
					row.Witnesses = append(row.Witnesses, key.ComponentKey)
				}
				sort.Strings(row.Witnesses)
			}
		}
		result.Connections = append(result.Connections, row)
	}
	published := map[string][]string{}
	for _, connection := range result.Connections {
		for _, id := range connection.Witnesses {
			published[id] = append(published[id], connection.Alias)
		}
	}
	for id, routes := range published {
		if len(routes) > 1 {
			if result.DuplicateRoutes == nil {
				result.DuplicateRoutes = map[string][]string{}
			}
			result.DuplicateRoutes[id] = routes
		}
	}
	for _, key := range keys {
		route := routeForSigningFlow(key.SigningFlow)
		if route == flowRoutePlain {
			continue
		}
		row := AccountRouteObservation{Address: key.Address, Routes: []string{}, State: AccountRouteInvalidMetadata}
		if route != flowRouteGuarded && route != flowRouteBoundedCosigner {
			row.Error = "unsupported signing flow: " + key.SigningFlow
			result.Accounts = append(result.Accounts, row)
			continue
		}
		publicKey := key.Parameters["cosigner_public_key"]
		if publicKey == "" && key.BoundedAuthorization != nil && key.BoundedAuthorization.Cosigner != nil {
			publicKey = key.BoundedAuthorization.Cosigner.PublicKeyHex
		}
		canonical, err := normalizeCosignerPublicKeyHex(publicKey)
		if err == nil {
			row.WitnessKeyID, err = cosignerComponentSelector(key.CosignerComponentKeyType, canonical)
		}
		if err != nil {
			row.Error = err.Error()
		} else {
			required := cosignerRequestKey{ComponentKeyType: key.CosignerComponentKeyType, PublicKey: canonical}
			for _, index := range matchingCosignerEndpointIndices(required, states) {
				row.Routes = append(row.Routes, states[index].alias)
			}
			_, matched, selectionErr := uniqueCosignerSelections([]cosignerRequestKey{required}, states)
			switch {
			case sweepErr != nil:
				row.State = AccountRouteCheckIncomplete
				row.Error = sweepErr.Error()
			case selectionErr != nil:
				row.State = AccountRouteDuplicate
				row.Error = selectionErr.Error()
			case matched:
				row.State = AccountRouteAvailable
			default:
				row.State = AccountRouteMissing
			}
		}
		result.Accounts = append(result.Accounts, row)
	}
	sort.Slice(result.Accounts, func(i, j int) bool { return result.Accounts[i].Address < result.Accounts[j].Address })
	return result
}
