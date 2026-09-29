// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package guarded

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

func TestCompletedCosignerSweepIgnoresInternalDeadlineButHonorsCallerCancellation(t *testing.T) {
	aliases := []string{"a"}
	states := []*cosignerEndpointProbeResult{{alias: "a", err: context.DeadlineExceeded}}
	if err := completedCosignerSweepError(t.Context(), aliases, states, context.DeadlineExceeded); err != nil {
		t.Fatalf("completed sweep = %v, want nil", err)
	}
	if err := completedCosignerSweepError(t.Context(), []string{"a", "b"}, append(states, nil), context.DeadlineExceeded); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("incomplete sweep = %v, want deadline error", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := completedCosignerSweepError(ctx, aliases, states, context.DeadlineExceeded); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller = %v, want cancellation", err)
	}
}

func TestLiveCosignerResolverReusesOneProbeForSeveralKeys(t *testing.T) {
	first := cosignerRequestKey{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}
	second := cosignerRequestKey{ComponentKeyType: "test.witness.v1", PublicKey: "bb"}
	var probes atomic.Int32
	s := &Signer{
		endpointRegistry: resolverTestRegistry("only"),
		probeEndpoint: func(context.Context, string, config.ClientEndpointConfig) (*resolvedCosignerEndpoint, []DiscoveredCosignerComponentKey, error) {
			probes.Add(1)
			return resolverTestEndpoint("only"), []DiscoveredCosignerComponentKey{
				{PublicKey: first.PublicKey, KeyType: first.ComponentKeyType},
				{PublicKey: second.PublicKey, KeyType: second.ComponentKeyType},
			}, nil
		},
	}

	snapshot, err := s.resolveCosignerEndpoints(t.Context(), []cosignerRequestKey{first, second, first})
	if err != nil {
		t.Fatalf("resolveCosignerEndpoints() error = %v", err)
	}
	defer snapshot.close()
	if got := probes.Load(); got != 1 {
		t.Fatalf("endpoint probes = %d, want 1", got)
	}
	if snapshot.routes[first] != snapshot.routes[second] {
		t.Fatal("keys advertised by one endpoint did not reuse the live connection")
	}
}

func TestLiveCosignerResolverRejectsDuplicateAdvertisers(t *testing.T) {
	key := cosignerRequestKey{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}
	var closes atomic.Int32
	s := &Signer{
		endpointRegistry: resolverTestRegistry("z-later", "a-first"),
		probeEndpoint: func(_ context.Context, alias string, _ config.ClientEndpointConfig) (*resolvedCosignerEndpoint, []DiscoveredCosignerComponentKey, error) {
			return &resolvedCosignerEndpoint{
				source:  alias,
				cleanup: func() { closes.Add(1) },
			}, []DiscoveredCosignerComponentKey{{PublicKey: key.PublicKey, KeyType: key.ComponentKeyType}}, nil
		},
	}
	snapshot, err := s.resolveCosignerEndpoints(t.Context(), []cosignerRequestKey{key})
	if snapshot != nil {
		snapshot.close()
	}
	if !errors.Is(err, errCosignerDiscoveryDuplicateRoute) {
		t.Fatalf("resolveCosignerEndpoints() error = %v, want duplicate-route failure", err)
	}
	if got := err.Error(); !strings.Contains(got, `endpoints "a-first", "z-later"`) {
		t.Fatalf("resolveCosignerEndpoints() error = %v, want sorted duplicate aliases", err)
	}
	if got := closes.Load(); got != 2 {
		t.Fatalf("closed endpoint connections = %d, want 2", got)
	}
}

func TestLiveCosignerResolverDoesNotAcceptRouteAfterDiscoveryCancellation(t *testing.T) {
	key := cosignerRequestKey{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var probes atomic.Int32
	s := &Signer{
		endpointRegistry: resolverTestRegistry("a", "b"),
		probeEndpoint: func(context.Context, string, config.ClientEndpointConfig) (*resolvedCosignerEndpoint, []DiscoveredCosignerComponentKey, error) {
			probes.Add(1)
			return resolverTestEndpoint("unexpected"), []DiscoveredCosignerComponentKey{{
				PublicKey: key.PublicKey, KeyType: key.ComponentKeyType,
			}}, nil
		},
	}

	snapshot, err := s.resolveCosignerEndpoints(ctx, []cosignerRequestKey{key})
	if snapshot != nil {
		snapshot.close()
		t.Fatal("resolveCosignerEndpoints() returned a snapshot after cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("resolveCosignerEndpoints() error = %v, want context cancellation", err)
	}
	if got := probes.Load(); got != 0 {
		t.Fatalf("endpoint probes = %d, want 0 for pre-canceled discovery", got)
	}
}

func TestLiveCosignerResolverLimitsConcurrentProbes(t *testing.T) {
	aliases := []string{"a", "b", "c", "d", "e", "f"}
	started := make(chan struct{}, len(aliases))
	release := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	s := &Signer{
		endpointRegistry: resolverTestRegistry(aliases...),
		probeEndpoint: func(ctx context.Context, alias string, _ config.ClientEndpointConfig) (*resolvedCosignerEndpoint, []DiscoveredCosignerComponentKey, error) {
			current := active.Add(1)
			defer active.Add(-1)
			for {
				seen := maximum.Load()
				if current <= seen || maximum.CompareAndSwap(seen, current) {
					break
				}
			}
			started <- struct{}{}
			select {
			case <-release:
				return resolverTestEndpoint(alias), nil, nil
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		},
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.resolveCosignerEndpoints(t.Context(), []cosignerRequestKey{{ComponentKeyType: "test.witness.v1", PublicKey: "missing"}})
		done <- err
	}()
	for range cosignerDiscoveryWorkers {
		<-started
	}
	select {
	case <-started:
		t.Fatal("more than four endpoint probes started concurrently")
	default:
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("resolveCosignerEndpoints() error = nil, want missing-key failure")
	}
	if got := maximum.Load(); got != cosignerDiscoveryWorkers {
		t.Fatalf("maximum concurrent probes = %d, want %d", got, cosignerDiscoveryWorkers)
	}
}

func TestLiveCosignerResolverClosesEveryUnusedEndpoint(t *testing.T) {
	var closes atomic.Int32
	s := &Signer{
		endpointRegistry: resolverTestRegistry("a", "b", "c"),
		probeEndpoint: func(_ context.Context, alias string, _ config.ClientEndpointConfig) (*resolvedCosignerEndpoint, []DiscoveredCosignerComponentKey, error) {
			return &resolvedCosignerEndpoint{source: alias, cleanup: func() { closes.Add(1) }}, nil, nil
		},
	}
	_, err := s.resolveCosignerEndpoints(t.Context(), []cosignerRequestKey{{ComponentKeyType: "test.witness.v1", PublicKey: "missing"}})
	if err == nil {
		t.Fatal("resolveCosignerEndpoints() error = nil, want missing-key failure")
	}
	if got := closes.Load(); got != 3 {
		t.Fatalf("closed endpoint connections = %d, want 3", got)
	}
}

func TestLiveCosignerResolverHostKeyMismatchAbortsGlobalSearch(t *testing.T) {
	key := cosignerRequestKey{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	s := &Signer{
		endpointRegistry: resolverTestRegistry("a-match", "b-mismatch"),
		probeEndpoint: func(_ context.Context, alias string, _ config.ClientEndpointConfig) (*resolvedCosignerEndpoint, []DiscoveredCosignerComponentKey, error) {
			started <- struct{}{}
			<-release
			if alias == "b-mismatch" {
				return nil, nil, fmt.Errorf("dial: %w", sshtunnel.ErrHostKeyMismatch)
			}
			return resolverTestEndpoint(alias), []DiscoveredCosignerComponentKey{{PublicKey: key.PublicKey, KeyType: key.ComponentKeyType}}, nil
		},
	}
	done := make(chan error, 1)
	go func() {
		snapshot, err := s.resolveCosignerEndpoints(t.Context(), []cosignerRequestKey{key})
		if snapshot != nil {
			snapshot.close()
		}
		done <- err
	}()
	<-started
	<-started
	close(release)
	err := <-done
	if !errors.Is(err, errCosignerDiscoveryHostKeyMismatch) {
		t.Fatalf("resolveCosignerEndpoints() error = %v, want host-key mismatch", err)
	}
}

func TestLiveCosignerResolverWarnsWhenEarlierEndpointFails(t *testing.T) {
	key := cosignerRequestKey{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}
	var progress bytes.Buffer
	conn := connect.NewState()
	conn.SetSignerProgressWriter(&progress)
	s := &Signer{
		conn:             conn,
		endpointRegistry: resolverTestRegistry("a-offline", "b-match"),
		probeEndpoint: func(_ context.Context, alias string, _ config.ClientEndpointConfig) (*resolvedCosignerEndpoint, []DiscoveredCosignerComponentKey, error) {
			if alias == "a-offline" {
				return nil, nil, fmt.Errorf("%w: refused", ErrCosignerDiscoveryUnavailable)
			}
			return resolverTestEndpoint(alias), []DiscoveredCosignerComponentKey{{PublicKey: key.PublicKey, KeyType: key.ComponentKeyType}}, nil
		},
	}
	snapshot, err := s.resolveCosignerEndpoints(t.Context(), []cosignerRequestKey{key})
	if err != nil {
		t.Fatalf("resolveCosignerEndpoints() error = %v", err)
	}
	defer snapshot.close()
	if got := progress.String(); !strings.Contains(got, "a-offline: unavailable") {
		t.Fatalf("progress = %q, want sanitized skipped-endpoint warning", got)
	}
}

func TestLiveCosignerResolverRejectsEndpointOverflowBeforeProbing(t *testing.T) {
	aliases := make([]string, 0, maxCosignerDiscoveryEndpoints+1)
	for i := 0; i <= maxCosignerDiscoveryEndpoints; i++ {
		aliases = append(aliases, fmt.Sprintf("cosigner-%02d", i))
	}
	var probes atomic.Int32
	s := &Signer{
		endpointRegistry: resolverTestRegistry(aliases...),
		probeEndpoint: func(context.Context, string, config.ClientEndpointConfig) (*resolvedCosignerEndpoint, []DiscoveredCosignerComponentKey, error) {
			probes.Add(1)
			return nil, nil, nil
		},
	}
	_, err := s.resolveCosignerEndpoints(t.Context(), []cosignerRequestKey{{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}})
	if !errors.Is(err, ErrCosignerDiscoveryConfig) || !strings.Contains(err.Error(), "configured 13 cosigner endpoints; maximum is 12") {
		t.Fatalf("resolveCosignerEndpoints() error = %v, want explicit endpoint ceiling", err)
	}
	if got := probes.Load(); got != 0 {
		t.Fatalf("endpoint probes = %d, want 0", got)
	}
}

func TestLiveCosignerResolverRemovesImplicitPrimarySignerFallback(t *testing.T) {
	s := &Signer{endpointRegistry: config.ClientEndpointRegistry{Endpoints: map[string]config.ClientEndpointConfig{}}}
	_, err := s.resolveCosignerEndpoints(t.Context(), []cosignerRequestKey{{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}})
	if !errors.Is(err, ErrCosignerDiscoveryConfig) || !strings.Contains(err.Error(), "no cosigner endpoints configured") {
		t.Fatalf("resolveCosignerEndpoints() error = %v, want explicit cosigner endpoint requirement", err)
	}
}

func resolverTestRegistry(aliases ...string) config.ClientEndpointRegistry {
	registry := config.ClientEndpointRegistry{
		SchemaVersion: config.ClientEndpointSchemaVersion,
		Endpoints:     make(map[string]config.ClientEndpointConfig, len(aliases)),
	}
	for _, alias := range aliases {
		registry.Endpoints[alias] = config.ClientEndpointConfig{Role: config.ClientEndpointRoleCosigner, URL: "https://" + alias + ".example"}
	}
	return registry
}

func resolverTestEndpoint(source string) *resolvedCosignerEndpoint {
	return &resolvedCosignerEndpoint{source: source}
}

func TestCosignerDiscoveryFailureLabelsDistinguishSSHTrustFailures(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{err: sshtunnel.ErrUnknownHostKey, want: "SSH host is not enrolled"},
		{err: sshtunnel.ErrKnownHostsFile, want: "invalid known_hosts configuration"},
		{err: sshtunnel.ErrHostKeyMismatch, want: "SSH host-key mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := cosignerDiscoveryFailureLabel(tt.err); got != tt.want {
				t.Fatalf("cosignerDiscoveryFailureLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLiveCosignerResolverPublishesEachCleanupOnce(t *testing.T) {
	key := cosignerRequestKey{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}
	var mu sync.Mutex
	closes := map[string]int{}
	s := &Signer{
		endpointRegistry: resolverTestRegistry("a"),
		probeEndpoint: func(_ context.Context, alias string, _ config.ClientEndpointConfig) (*resolvedCosignerEndpoint, []DiscoveredCosignerComponentKey, error) {
			return &resolvedCosignerEndpoint{source: alias, cleanup: func() {
				mu.Lock()
				closes[alias]++
				mu.Unlock()
			}}, []DiscoveredCosignerComponentKey{{PublicKey: key.PublicKey, KeyType: key.ComponentKeyType}}, nil
		},
	}
	snapshot, err := s.resolveCosignerEndpoints(t.Context(), []cosignerRequestKey{key, key})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.close()
	mu.Lock()
	defer mu.Unlock()
	if closes["a"] != 1 {
		t.Fatalf("cleanup calls = %d, want 1", closes["a"])
	}
}
