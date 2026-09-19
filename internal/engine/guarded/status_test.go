// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package guarded

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

func TestInspectRoutesMatchesResolverAndClosesConnections(t *testing.T) {
	for _, tc := range []struct {
		name      string
		otherErr  error
		duplicate bool
		want      string
	}{
		{"unique", ErrSentryDiscoveryUnavailable, false, "sentry route available"},
		{"unauthorized unrelated", ErrSentryDiscoveryAuth, false, "sentry route available"},
		{"duplicate", nil, true, "duplicate witness route"},
		{"host mismatch", connect.ErrSSHHostKeyMismatch, false, "route check incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var closes atomic.Int32
			s := &Signer{endpointRegistry: resolverTestRegistry("a", "b")}
			s.probeEndpoint = func(_ context.Context, alias string, _ config.ClientEndpointConfig) (*resolvedSentryEndpoint, []DiscoveredSentryComponentKey, error) {
				ep := &resolvedSentryEndpoint{cleanup: func() { closes.Add(1) }}
				if alias == "b" && !tc.duplicate {
					return ep, nil, tc.otherErr
				}
				return ep, []DiscoveredSentryComponentKey{{KeyType: "test.v1", PublicKey: "aa", ComponentKey: "key"}}, nil
			}
			key := signerapi.KeyInfo{Address: "account", SigningFlow: signerapi.SigningFlowSentry1, SentryComponentKeyType: "test.v1", Parameters: map[string]string{"sentry_public_key": "AA"}}
			result := s.InspectRoutes(t.Context(), []signerapi.KeyInfo{key})
			if len(result.Accounts) != 1 || result.Accounts[0].State != tc.want {
				t.Fatalf("status = %+v", result)
			}
			if closes.Load() != int32(lenNonNilObservations(result)) {
				t.Fatalf("leaked connections: %d", closes.Load())
			}
			snapshot, err := s.resolveSentryEndpoints(t.Context(), []sentryRequestKey{{ComponentKeyType: "test.v1", PublicKey: "aa"}})
			if snapshot != nil {
				snapshot.close()
			}
			if (err == nil) != (tc.want == "sentry route available") {
				t.Fatalf("resolver and status disagree: %v", err)
			}
		})
	}
}
func lenNonNilObservations(result RouteStatus) int {
	n := 0
	for _, row := range result.Connections {
		if row.State != "not checked" {
			n++
		}
	}
	return n
}

func TestInspectRoutesRetainsUnmatchedAndInvalidRequirements(t *testing.T) {
	s := &Signer{endpointRegistry: resolverTestRegistry("a"), probeEndpoint: func(context.Context, string, config.ClientEndpointConfig) (*resolvedSentryEndpoint, []DiscoveredSentryComponentKey, error) {
		return resolverTestEndpoint("a"), nil, nil
	}}
	keys := []signerapi.KeyInfo{
		{Address: "a", SigningFlow: signerapi.SigningFlowSentry1, SentryComponentKeyType: "test.v1", Parameters: map[string]string{"sentry_public_key": "aa"}},
		{Address: "b", SigningFlow: signerapi.SigningFlowBoundedSentry1, SentryComponentKeyType: "test.v1", BoundedAuthorization: &signerapi.BoundedAuthorizationInfo{Sentry: &signerapi.BoundedSentryAuthorizationInfo{PublicKeyHex: "bb"}}},
		{Address: "c", SigningFlow: signerapi.SigningFlowSentry1},
		{Address: "d", SigningFlow: "future-flow"},
		{Address: "plain"},
	}
	result := s.InspectRoutes(t.Context(), keys)
	if len(result.Accounts) != 4 {
		t.Fatalf("accounts=%+v", result.Accounts)
	}
	for i, row := range result.Accounts {
		want := "no matching live route observed"
		if i >= 2 {
			want = "invalid metadata"
		}
		if row.State != want {
			t.Fatalf("row=%+v", row)
		}
	}
}

func TestInspectRoutesCancellationPreservesPartialObservations(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var closes atomic.Int32
	s := &Signer{endpointRegistry: resolverTestRegistry("a"), probeEndpoint: func(context.Context, string, config.ClientEndpointConfig) (*resolvedSentryEndpoint, []DiscoveredSentryComponentKey, error) {
		cancel()
		return &resolvedSentryEndpoint{cleanup: func() { closes.Add(1) }}, []DiscoveredSentryComponentKey{{KeyType: "test.v1", PublicKey: "aa"}}, nil
	}}
	result := s.InspectRoutes(ctx, []signerapi.KeyInfo{{Address: "account", SigningFlow: signerapi.SigningFlowSentry1, SentryComponentKeyType: "test.v1", Parameters: map[string]string{"sentry_public_key": "aa"}}})
	if len(result.Connections) != 1 || result.Accounts[0].State != "route check incomplete" || result.DiscoveryError != context.Canceled.Error() || closes.Load() != 1 {
		t.Fatalf("result=%+v closes=%d", result, closes.Load())
	}
	_, _, err := s.probeSentryEndpoints(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled sweep = %v", err)
	}
}

func TestInspectRoutesReportsEachEndpointFailure(t *testing.T) {
	for _, failure := range []error{ErrSentryDiscoveryLocked, ErrSentryDiscoveryAuth, ErrSentryDiscoveryInvalidMetadata, ErrSentryDiscoveryConfig, connect.ErrSSHUnknownHostKey, context.DeadlineExceeded} {
		s := &Signer{endpointRegistry: resolverTestRegistry("a"), probeEndpoint: func(context.Context, string, config.ClientEndpointConfig) (*resolvedSentryEndpoint, []DiscoveredSentryComponentKey, error) {
			return nil, nil, failure
		}}
		result := s.InspectRoutes(t.Context(), nil)
		if len(result.Connections) != 1 || result.Connections[0].Error != failure.Error() || result.Connections[0].State == "reachable; authenticated" {
			t.Fatalf("failure %v: %+v", failure, result)
		}
	}
}
