// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package guarded

import (
	"context"
	"sort"

	"github.com/aplane-algo/aplane/internal/signerapi"
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
	aliases, states, sweepErr := s.probeSentryEndpoints(ctx)
	defer closeProbeResults(states, nil)
	result := RouteStatus{Connections: []ConnectionObservation{}, Accounts: []AccountRouteObservation{}}
	if sweepErr != nil {
		result.DiscoveryError = sweepErr.Error()
	}
	for i, alias := range aliases {
		row := ConnectionObservation{Alias: alias, URL: s.endpointRegistry.Endpoints[alias].URL, State: "not checked", Witnesses: []string{}}
		if i < len(states) && states[i] != nil {
			state := states[i]
			if state.err != nil {
				row.State = sentryDiscoveryFailureLabel(state.err)
				row.Error = state.err.Error()
			} else {
				row.State = "reachable; authenticated"
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
		row := AccountRouteObservation{Address: key.Address, Routes: []string{}, State: "invalid metadata"}
		if route != flowRouteGuarded && route != flowRouteBoundedSentry {
			row.Error = "unsupported signing flow: " + key.SigningFlow
			result.Accounts = append(result.Accounts, row)
			continue
		}
		publicKey := key.Parameters["sentry_public_key"]
		if publicKey == "" && key.BoundedAuthorization != nil && key.BoundedAuthorization.Sentry != nil {
			publicKey = key.BoundedAuthorization.Sentry.PublicKeyHex
		}
		canonical, err := normalizeSentryPublicKeyHex(publicKey)
		if err == nil {
			row.WitnessKeyID, err = sentryComponentSelector(key.SentryComponentKeyType, canonical)
		}
		if err != nil {
			row.Error = err.Error()
		} else {
			required := sentryRequestKey{ComponentKeyType: key.SentryComponentKeyType, PublicKey: canonical}
			for _, index := range matchingSentryEndpointIndices(required, states) {
				row.Routes = append(row.Routes, states[index].alias)
			}
			_, matched, selectionErr := uniqueSentrySelections([]sentryRequestKey{required}, states)
			switch {
			case sweepErr != nil:
				row.State = "route check incomplete"
				row.Error = sweepErr.Error()
			case selectionErr != nil:
				row.State = "duplicate witness route"
				row.Error = selectionErr.Error()
			case matched:
				row.State = "sentry route available"
			default:
				row.State = "no matching live route observed"
			}
		}
		result.Accounts = append(result.Accounts, row)
	}
	sort.Slice(result.Accounts, func(i, j int) bool { return result.Accounts[i].Address < result.Accounts[j].Address })
	return result
}
