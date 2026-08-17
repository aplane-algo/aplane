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

func TestLiveSentryResolverReusesOneProbeForSeveralKeys(t *testing.T) {
	first := sentryRequestKey{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}
	second := sentryRequestKey{ComponentKeyType: "test.witness.v1", PublicKey: "bb"}
	var probes atomic.Int32
	s := &Signer{
		endpointRegistry: resolverTestRegistry("only"),
		probeEndpoint: func(context.Context, string, config.ClientEndpointConfig) (*resolvedSentryEndpoint, []DiscoveredSentryComponentKey, error) {
			probes.Add(1)
			return resolverTestEndpoint("only"), []DiscoveredSentryComponentKey{
				{PublicKey: first.PublicKey, KeyType: first.ComponentKeyType},
				{PublicKey: second.PublicKey, KeyType: second.ComponentKeyType},
			}, nil
		},
	}

	snapshot, err := s.resolveSentryEndpoints(t.Context(), []sentryRequestKey{first, second, first})
	if err != nil {
		t.Fatalf("resolveSentryEndpoints() error = %v", err)
	}
	defer snapshot.close()
	if got := probes.Load(); got != 1 {
		t.Fatalf("endpoint probes = %d, want 1", got)
	}
	if snapshot.routes[first] != snapshot.routes[second] {
		t.Fatal("keys advertised by one endpoint did not reuse the live connection")
	}
}

func TestLiveSentryResolverUsesDeterministicAliasPrefix(t *testing.T) {
	key := sentryRequestKey{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}
	releaseFirst := make(chan struct{})
	laterDone := make(chan struct{})
	s := &Signer{
		endpointRegistry: resolverTestRegistry("z-later", "a-first"),
		probeEndpoint: func(_ context.Context, alias string, _ config.ClientEndpointConfig) (*resolvedSentryEndpoint, []DiscoveredSentryComponentKey, error) {
			if alias == "a-first" {
				<-releaseFirst
			} else {
				close(laterDone)
			}
			return resolverTestEndpoint(alias), []DiscoveredSentryComponentKey{{PublicKey: key.PublicKey, KeyType: key.ComponentKeyType}}, nil
		},
	}
	type outcome struct {
		snapshot *sentryEndpointSnapshot
		err      error
	}
	result := make(chan outcome, 1)
	go func() {
		snapshot, err := s.resolveSentryEndpoints(t.Context(), []sentryRequestKey{key})
		result <- outcome{snapshot: snapshot, err: err}
	}()
	<-laterDone
	select {
	case got := <-result:
		if got.snapshot != nil {
			got.snapshot.close()
		}
		t.Fatalf("resolver selected a later response before the earlier alias terminated: %v", got.err)
	default:
	}
	close(releaseFirst)
	got := <-result
	if got.err != nil {
		t.Fatalf("resolveSentryEndpoints() error = %v", got.err)
	}
	defer got.snapshot.close()
	if source := got.snapshot.routes[key].source; source != "a-first" {
		t.Fatalf("selected endpoint = %q, want a-first", source)
	}
}

func TestLiveSentryResolverLimitsConcurrentProbes(t *testing.T) {
	aliases := []string{"a", "b", "c", "d", "e", "f"}
	started := make(chan struct{}, len(aliases))
	release := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	s := &Signer{
		endpointRegistry: resolverTestRegistry(aliases...),
		probeEndpoint: func(ctx context.Context, alias string, _ config.ClientEndpointConfig) (*resolvedSentryEndpoint, []DiscoveredSentryComponentKey, error) {
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
		_, err := s.resolveSentryEndpoints(t.Context(), []sentryRequestKey{{ComponentKeyType: "test.witness.v1", PublicKey: "missing"}})
		done <- err
	}()
	for range sentryDiscoveryWorkers {
		<-started
	}
	select {
	case <-started:
		t.Fatal("more than four endpoint probes started concurrently")
	default:
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("resolveSentryEndpoints() error = nil, want missing-key failure")
	}
	if got := maximum.Load(); got != sentryDiscoveryWorkers {
		t.Fatalf("maximum concurrent probes = %d, want %d", got, sentryDiscoveryWorkers)
	}
}

func TestLiveSentryResolverClosesEveryUnusedEndpoint(t *testing.T) {
	var closes atomic.Int32
	s := &Signer{
		endpointRegistry: resolverTestRegistry("a", "b", "c"),
		probeEndpoint: func(_ context.Context, alias string, _ config.ClientEndpointConfig) (*resolvedSentryEndpoint, []DiscoveredSentryComponentKey, error) {
			return &resolvedSentryEndpoint{source: alias, cleanup: func() { closes.Add(1) }}, nil, nil
		},
	}
	_, err := s.resolveSentryEndpoints(t.Context(), []sentryRequestKey{{ComponentKeyType: "test.witness.v1", PublicKey: "missing"}})
	if err == nil {
		t.Fatal("resolveSentryEndpoints() error = nil, want missing-key failure")
	}
	if got := closes.Load(); got != 3 {
		t.Fatalf("closed endpoint connections = %d, want 3", got)
	}
}

func TestLiveSentryResolverHostKeyMismatchAbortsGlobalSearch(t *testing.T) {
	key := sentryRequestKey{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	s := &Signer{
		endpointRegistry: resolverTestRegistry("a-match", "b-mismatch"),
		probeEndpoint: func(_ context.Context, alias string, _ config.ClientEndpointConfig) (*resolvedSentryEndpoint, []DiscoveredSentryComponentKey, error) {
			started <- struct{}{}
			<-release
			if alias == "b-mismatch" {
				return nil, nil, fmt.Errorf("dial: %w", sshtunnel.ErrHostKeyMismatch)
			}
			return resolverTestEndpoint(alias), []DiscoveredSentryComponentKey{{PublicKey: key.PublicKey, KeyType: key.ComponentKeyType}}, nil
		},
	}
	done := make(chan error, 1)
	go func() {
		snapshot, err := s.resolveSentryEndpoints(t.Context(), []sentryRequestKey{key})
		if snapshot != nil {
			snapshot.close()
		}
		done <- err
	}()
	<-started
	<-started
	close(release)
	err := <-done
	if !errors.Is(err, errSentryDiscoveryHostKeyMismatch) {
		t.Fatalf("resolveSentryEndpoints() error = %v, want host-key mismatch", err)
	}
}

func TestLiveSentryResolverWarnsWhenEarlierEndpointFails(t *testing.T) {
	key := sentryRequestKey{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}
	var progress bytes.Buffer
	conn := connect.NewState()
	conn.SetSignerProgressWriter(&progress)
	s := &Signer{
		conn:             conn,
		endpointRegistry: resolverTestRegistry("a-offline", "b-match"),
		probeEndpoint: func(_ context.Context, alias string, _ config.ClientEndpointConfig) (*resolvedSentryEndpoint, []DiscoveredSentryComponentKey, error) {
			if alias == "a-offline" {
				return nil, nil, fmt.Errorf("%w: refused", ErrSentryDiscoveryUnavailable)
			}
			return resolverTestEndpoint(alias), []DiscoveredSentryComponentKey{{PublicKey: key.PublicKey, KeyType: key.ComponentKeyType}}, nil
		},
	}
	snapshot, err := s.resolveSentryEndpoints(t.Context(), []sentryRequestKey{key})
	if err != nil {
		t.Fatalf("resolveSentryEndpoints() error = %v", err)
	}
	defer snapshot.close()
	if got := progress.String(); !strings.Contains(got, "a-offline: unavailable") {
		t.Fatalf("progress = %q, want sanitized skipped-endpoint warning", got)
	}
}

func TestLiveSentryResolverRejectsEndpointOverflowBeforeProbing(t *testing.T) {
	aliases := make([]string, 0, maxSentryDiscoveryEndpoints+1)
	for i := 0; i <= maxSentryDiscoveryEndpoints; i++ {
		aliases = append(aliases, fmt.Sprintf("sentry-%02d", i))
	}
	var probes atomic.Int32
	s := &Signer{
		endpointRegistry: resolverTestRegistry(aliases...),
		probeEndpoint: func(context.Context, string, config.ClientEndpointConfig) (*resolvedSentryEndpoint, []DiscoveredSentryComponentKey, error) {
			probes.Add(1)
			return nil, nil, nil
		},
	}
	_, err := s.resolveSentryEndpoints(t.Context(), []sentryRequestKey{{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}})
	if !errors.Is(err, ErrSentryDiscoveryConfig) || !strings.Contains(err.Error(), "configured 13 sentry endpoints; maximum is 12") {
		t.Fatalf("resolveSentryEndpoints() error = %v, want explicit endpoint ceiling", err)
	}
	if got := probes.Load(); got != 0 {
		t.Fatalf("endpoint probes = %d, want 0", got)
	}
}

func TestLiveSentryResolverRemovesImplicitPrimarySignerFallback(t *testing.T) {
	s := &Signer{endpointRegistry: config.ClientEndpointRegistry{Endpoints: map[string]config.ClientEndpointConfig{}}}
	_, err := s.resolveSentryEndpoints(t.Context(), []sentryRequestKey{{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}})
	if !errors.Is(err, ErrSentryDiscoveryConfig) || !strings.Contains(err.Error(), "no sentry endpoints configured") {
		t.Fatalf("resolveSentryEndpoints() error = %v, want explicit sentry endpoint requirement", err)
	}
}

func resolverTestRegistry(aliases ...string) config.ClientEndpointRegistry {
	registry := config.ClientEndpointRegistry{SchemaVersion: 1, Endpoints: make(map[string]config.ClientEndpointConfig, len(aliases))}
	for _, alias := range aliases {
		registry.Endpoints[alias] = config.ClientEndpointConfig{Role: config.ClientEndpointRoleSentry, URL: "https://" + alias + ".example"}
	}
	return registry
}

func resolverTestEndpoint(source string) *resolvedSentryEndpoint {
	return &resolvedSentryEndpoint{source: source}
}

func TestSentryDiscoveryFailureLabelsDistinguishSSHTrustFailures(t *testing.T) {
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
			if got := sentryDiscoveryFailureLabel(tt.err); got != tt.want {
				t.Fatalf("sentryDiscoveryFailureLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLiveSentryResolverPublishesEachCleanupOnce(t *testing.T) {
	key := sentryRequestKey{ComponentKeyType: "test.witness.v1", PublicKey: "aa"}
	var mu sync.Mutex
	closes := map[string]int{}
	s := &Signer{
		endpointRegistry: resolverTestRegistry("a"),
		probeEndpoint: func(_ context.Context, alias string, _ config.ClientEndpointConfig) (*resolvedSentryEndpoint, []DiscoveredSentryComponentKey, error) {
			return &resolvedSentryEndpoint{source: alias, cleanup: func() {
				mu.Lock()
				closes[alias]++
				mu.Unlock()
			}}, []DiscoveredSentryComponentKey{{PublicKey: key.PublicKey, KeyType: key.ComponentKeyType}}, nil
		},
	}
	snapshot, err := s.resolveSentryEndpoints(t.Context(), []sentryRequestKey{key, key})
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
