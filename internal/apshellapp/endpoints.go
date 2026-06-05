// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/attestor/attrefs"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

// EndpointImportRequest imports one public endpoint handoff envelope.
type EndpointImportRequest struct {
	Alias  string
	Path   string
	DryRun bool
}

// EndpointDiscoverAttestorsRequest rebuilds endpoint-published attestor
// inventory by querying configured endpoint inventories.
type EndpointDiscoverAttestorsRequest struct {
	DryRun bool
}

// EndpointSyncAttestorsRequest syncs endpoint-published attestor inventory into
// the connected signer identity's public attestor reference catalog.
type EndpointSyncAttestorsRequest struct {
	DryRun bool
}

// EndpointsList returns the resolved client endpoint registry plus local
// attestor mappings.
func (a *App) EndpointsList(_ context.Context) (*EndpointsListResult, error) {
	cfg, registry, mappings, err := a.loadEndpointView()
	if err != nil {
		return nil, err
	}
	a.Config = cfg

	aliases := make([]string, 0, len(registry.Endpoints))
	for alias := range registry.Endpoints {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)

	defaultAlias, _, _ := registry.DefaultEndpoint()
	entries := make([]EndpointEntry, 0, len(aliases))
	for _, alias := range aliases {
		entries = append(entries, a.endpointEntry(alias, registry.Endpoints[alias], alias == defaultAlias, mappings[alias]))
	}
	return &EndpointsListResult{Endpoints: entries}, nil
}

// EndpointShow returns one resolved endpoint profile.
func (a *App) EndpointShow(_ context.Context, alias string) (*EndpointShowResult, error) {
	if err := config.ValidateClientEndpointAlias(alias); err != nil {
		return nil, err
	}
	cfg, registry, mappings, err := a.loadEndpointView()
	if err != nil {
		return nil, err
	}
	a.Config = cfg

	endpoint, ok := registry.Endpoint(alias)
	if !ok {
		return nil, fmt.Errorf("unknown endpoint alias %q", alias)
	}
	defaultAlias, _, _ := registry.DefaultEndpoint()
	return &EndpointShowResult{
		Endpoint: a.endpointEntry(alias, endpoint, alias == defaultAlias, mappings[alias]),
	}, nil
}

// EndpointImport imports an apstore-exported public endpoint envelope into the
// local client registry. It does not copy tokens or host-key trust.
func (a *App) EndpointImport(_ context.Context, req EndpointImportRequest) (*EndpointImportResult, error) {
	if err := config.ValidateClientEndpointAlias(req.Alias); err != nil {
		return nil, fmt.Errorf("endpoint alias is required: %w", err)
	}
	if req.Path == "" {
		return nil, fmt.Errorf("endpoint envelope path is required")
	}
	data, err := os.ReadFile(req.Path)
	if err != nil {
		return nil, fmt.Errorf("read endpoint envelope %s: %w", req.Path, err)
	}
	env, err := endpointrefs.Parse(data)
	if err != nil {
		return nil, err
	}

	endpointPlan, err := config.PlanStoredClientEndpointUpsert(a.DataDir, req.Alias, config.ClientEndpointConfig{
		URL:        env.URL,
		SignerPort: env.SignerPort,
		LocalPort:  env.LocalPort,
	}, true)
	if err != nil {
		return nil, err
	}

	result := &EndpointImportResult{
		Alias:          req.Alias,
		URL:            endpointPlan.Endpoint.URL,
		SignerPort:     endpointPlan.Endpoint.SignerPort,
		LocalPort:      endpointPlan.Endpoint.LocalPort,
		TokenFile:      endpointPlan.Endpoint.TokenFile,
		DryRun:         req.DryRun,
		Created:        endpointPlan.Created,
		Updated:        endpointPlan.Updated,
		DefaultChanged: endpointPlan.DefaultChanged,
	}

	if !req.DryRun {
		if err := config.ApplyStoredClientEndpointUpsert(a.DataDir, endpointPlan); err != nil {
			return nil, err
		}
		if cfg, err := config.LoadConfig(a.DataDir); err == nil {
			a.Config = cfg
		}
	}
	result.RenderLines = endpointImportRenderLines(result)
	return result, nil
}

// EndpointDiscoverAttestors queries configured endpoint /keys inventories and
// atomically rebuilds reachable endpoint published_attestors inventory.
// Unreachable endpoints are preserved as no-ops so temporary outages do not
// erase client routing state.
func (a *App) EndpointDiscoverAttestors(ctx context.Context, req EndpointDiscoverAttestorsRequest) (*EndpointDiscoverAttestorsResult, error) {
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return nil, err
	}
	a.Config = cfg

	aliases := make([]string, 0, len(cfg.Endpoints.Endpoints))
	for alias := range cfg.Endpoints.Endpoints {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	if len(aliases) == 0 {
		return nil, fmt.Errorf("no endpoints configured")
	}

	lastSeenAt := time.Now().UTC().Format(time.RFC3339)
	publications := map[string]map[string]config.ClientEndpointPublishedAttestor{}
	discoveries := make([]EndpointAttestorDiscovery, 0, len(aliases))
	for _, alias := range aliases {
		endpoint := cfg.Endpoints.Endpoints[alias]
		keys, err := a.eng.DiscoverAttestorComponentKeysWithContext(ctx, endpoint)
		if err != nil {
			if !errors.Is(err, engine.ErrAttestorDiscoveryUnavailable) &&
				!errors.Is(err, engine.ErrAttestorDiscoveryLocked) {
				return nil, fmt.Errorf("endpoint %q discovery failed: %w", alias, err)
			}
			preserved := clonePublishedAttestors(endpoint.PublishedAttestors)
			publications[alias] = preserved
			discoveries = append(discoveries, EndpointAttestorDiscovery{
				Alias:          alias,
				Skipped:        true,
				PreservedCount: len(preserved),
				Error:          err.Error(),
			})
			continue
		}
		publications[alias] = map[string]config.ClientEndpointPublishedAttestor{}
		discovery := EndpointAttestorDiscovery{Alias: alias}
		for _, key := range keys {
			discovery.Keys = append(discovery.Keys, DiscoveredEndpointAttestorKey{
				PublicKey:    key.PublicKey,
				ComponentKey: key.ComponentKey,
				KeyType:      key.KeyType,
			})
			publications[alias][key.PublicKey] = config.ClientEndpointPublishedAttestor{
				ComponentKey: key.ComponentKey,
				KeyType:      key.KeyType,
				LastSeenAt:   lastSeenAt,
			}
		}
		discoveries = append(discoveries, discovery)
	}

	plan, err := config.PlanStoredClientEndpointPublishedAttestorRebuild(a.DataDir, publications)
	if err != nil {
		return nil, err
	}
	result := &EndpointDiscoverAttestorsResult{
		DryRun:                 req.DryRun,
		Endpoints:              discoveries,
		PublicKeyCount:         plan.PublicKeyCount,
		PreviousPublishedCount: plan.PreviousPublishedCount,
	}
	if !req.DryRun {
		if err := config.ApplyStoredClientEndpointPublishedAttestorRebuild(a.DataDir, plan); err != nil {
			return nil, err
		}
		if cfg, err := config.LoadConfig(a.DataDir); err == nil {
			a.Config = cfg
			a.eng.AttestorEndpoints = cfg.AttestorEndpoints.Clone()
		}
	}
	result.RenderLines = endpointDiscoverAttestorsRenderLines(result)
	return result, nil
}

// EndpointSyncAttestors publishes endpoint-discovered attestor metadata into
// the connected signer identity so signer-side key generation can select those
// attestors by name.
func (a *App) EndpointSyncAttestors(ctx context.Context, req EndpointSyncAttestorsRequest) (*EndpointSyncAttestorsResult, error) {
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return nil, err
	}
	a.Config = cfg

	candidates := endpointAttestorCandidates(cfg.Endpoints)
	result := &EndpointSyncAttestorsResult{
		DryRun:         req.DryRun,
		CandidateCount: len(candidates),
	}
	if req.DryRun {
		for _, candidate := range candidates {
			name, err := attrefs.SyncedReferenceName(candidate.EndpointAlias, candidate.ComponentKey)
			if err != nil {
				return nil, err
			}
			result.Records = append(result.Records, SyncedEndpointAttestorReference{
				Name:          name,
				EndpointAlias: candidate.EndpointAlias,
				PublicKey:     candidate.PublicKeyHex,
				ComponentKey:  candidate.ComponentKey,
				KeyType:       candidate.KeyType,
			})
		}
		result.RenderLines = endpointSyncAttestorsRenderLines(result)
		return result, nil
	}

	if !a.eng.IsConnected() {
		return nil, fmt.Errorf("not connected to Signer")
	}
	resp, err := a.eng.AdminSyncAttestorReferencesWithContext(ctx, candidates)
	if err != nil {
		return nil, err
	}
	result.Added = resp.Added
	result.Updated = resp.Updated
	result.Removed = resp.Removed
	for _, rec := range resp.Records {
		result.Records = append(result.Records, SyncedEndpointAttestorReference{
			Name:          rec.Name,
			EndpointAlias: rec.EndpointAlias,
			PublicKey:     rec.PublicKeyHex,
			ComponentKey:  rec.ComponentKey,
			KeyType:       rec.KeyType,
		})
	}
	result.RenderLines = endpointSyncAttestorsRenderLines(result)
	return result, nil
}

// EndpointDefault sets the default signing endpoint alias.
func (a *App) EndpointDefault(_ context.Context, alias string) (*EndpointDefaultResult, error) {
	if err := config.ValidateClientEndpointAlias(alias); err != nil {
		return nil, err
	}
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return nil, err
	}
	if _, ok := cfg.Endpoints.Endpoint(alias); !ok {
		return nil, fmt.Errorf("unknown endpoint alias %q", alias)
	}
	previousAlias, _, _ := cfg.Endpoints.DefaultEndpoint()
	if _, err := config.SetStoredClientEndpointDefault(a.DataDir, alias); err != nil {
		return nil, err
	}
	if cfg, err := config.LoadConfig(a.DataDir); err == nil {
		a.Config = cfg
	}
	return &EndpointDefaultResult{
		Alias:         alias,
		PreviousAlias: previousAlias,
		RenderLines:   []string{fmt.Sprintf("Default endpoint set to %s", alias)},
	}, nil
}

// EndpointDelete deletes a stored endpoint alias when it is not the default and
// no local attestor routes still reference it.
func (a *App) EndpointDelete(_ context.Context, alias string) (*EndpointDeleteResult, error) {
	if err := config.ValidateClientEndpointAlias(alias); err != nil {
		return nil, err
	}
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return nil, err
	}
	blocking := append([]string(nil), attestorEndpointMappingsByAlias(cfg.AttestorEndpoints)[alias]...)
	sort.Strings(blocking)
	if len(blocking) > 0 {
		return nil, fmt.Errorf("endpoint alias %q is referenced by attestor mappings:\n  %s", alias, strings.Join(blocking, "\n  "))
	}
	if _, err := config.DeleteStoredClientEndpoint(a.DataDir, alias); err != nil {
		return nil, err
	}
	if cfg, err := config.LoadConfig(a.DataDir); err == nil {
		a.Config = cfg
	}
	return &EndpointDeleteResult{
		Alias:       alias,
		RenderLines: []string{fmt.Sprintf("Deleted endpoint %s", alias)},
	}, nil
}

func (a *App) loadEndpointView() (config.Config, config.ClientEndpointRegistry, map[string][]string, error) {
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return config.Config{}, config.ClientEndpointRegistry{}, nil, err
	}
	mappings := cfg.Endpoints.PublishedAttestorPublicKeysByAlias()
	return cfg, cfg.Endpoints, mappings, nil
}

func attestorEndpointMappingsByAlias(routes config.AttestorEndpointConfigs) map[string][]string {
	out := map[string][]string{}
	for publicKey, route := range routes {
		if route.Endpoint == "" {
			continue
		}
		out[route.Endpoint] = append(out[route.Endpoint], publicKey)
	}
	for alias := range out {
		sort.Strings(out[alias])
	}
	return out
}

func clonePublishedAttestors(in map[string]config.ClientEndpointPublishedAttestor) map[string]config.ClientEndpointPublishedAttestor {
	out := make(map[string]config.ClientEndpointPublishedAttestor, len(in))
	for publicKey, published := range in {
		out[publicKey] = published
	}
	return out
}

func endpointAttestorCandidates(registry config.ClientEndpointRegistry) []signerapi.AttestorReferenceCandidate {
	aliases := make([]string, 0, len(registry.Endpoints))
	for alias := range registry.Endpoints {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)

	candidates := make([]signerapi.AttestorReferenceCandidate, 0)
	for _, alias := range aliases {
		endpoint := registry.Endpoints[alias]
		publicKeys := make([]string, 0, len(endpoint.PublishedAttestors))
		for publicKey := range endpoint.PublishedAttestors {
			publicKeys = append(publicKeys, publicKey)
		}
		sort.Strings(publicKeys)
		for _, publicKey := range publicKeys {
			published := endpoint.PublishedAttestors[publicKey]
			candidates = append(candidates, signerapi.AttestorReferenceCandidate{
				EndpointAlias: alias,
				ComponentKey:  published.ComponentKey,
				KeyType:       published.KeyType,
				PublicKeyHex:  publicKey,
				LastSeenAt:    published.LastSeenAt,
			})
		}
	}
	return candidates
}

func (a *App) endpointEntry(alias string, endpoint config.ClientEndpointConfig, isDefault bool, publicKeys []string) EndpointEntry {
	tokenPresent, tokenError := endpointTokenStatus(endpoint.TokenFile)
	keys := append([]string(nil), publicKeys...)
	sort.Strings(keys)
	return EndpointEntry{
		Alias:                       alias,
		URL:                         endpoint.URL,
		SignerPort:                  endpoint.SignerPort,
		LocalPort:                   endpoint.LocalPort,
		IdentityFile:                endpoint.IdentityFile,
		KnownHostsPath:              endpoint.KnownHostsPath,
		TokenFile:                   endpoint.TokenFile,
		TokenPresent:                tokenPresent,
		TokenError:                  tokenError,
		IsDefault:                   isDefault,
		PublishedAttestorPublicKeys: keys,
	}
}

func endpointTokenStatus(path string) (bool, string) {
	if path == "" {
		return false, ""
	}
	token, err := tokenfile.ReadToken(path)
	if err != nil {
		return false, err.Error()
	}
	return token != "", ""
}

func endpointImportRenderLines(result *EndpointImportResult) []string {
	action := "Imported"
	if result.DryRun {
		action = "Would import"
	}
	state := "unchanged"
	switch {
	case result.Created:
		state = "created"
	case result.Updated:
		state = "updated"
	}

	lines := []string{
		fmt.Sprintf("%s endpoint %s (%s)", action, result.Alias, state),
		fmt.Sprintf("  url: %s", result.URL),
		fmt.Sprintf("  token file: %s", result.TokenFile),
	}
	if result.DefaultChanged {
		lines = append(lines, "  default: yes")
	}
	return lines
}

func endpointSyncAttestorsRenderLines(result *EndpointSyncAttestorsResult) []string {
	action := "Synced"
	if result.DryRun {
		action = "Would sync"
	}
	lines := []string{
		fmt.Sprintf("%s %d endpoint-discovered attestor reference(s) to signer", action, result.CandidateCount),
	}
	if !result.DryRun {
		lines = append(lines,
			fmt.Sprintf("  added: %d", result.Added),
			fmt.Sprintf("  updated: %d", result.Updated),
			fmt.Sprintf("  removed stale: %d", result.Removed),
		)
	}
	for _, rec := range result.Records {
		lines = append(lines, fmt.Sprintf("  %s: %s (%s, %s)", rec.Name, rec.PublicKey, rec.KeyType, rec.EndpointAlias))
	}
	return lines
}

func endpointDiscoverAttestorsRenderLines(result *EndpointDiscoverAttestorsResult) []string {
	action := "Rebuilt"
	if result.DryRun {
		action = "Would rebuild"
	}
	lines := []string{
		fmt.Sprintf("%s endpoint-published attestor inventory from %d endpoint(s): %d key(s)",
			action, len(result.Endpoints), result.PublicKeyCount),
		fmt.Sprintf("  previous published keys: %d", result.PreviousPublishedCount),
	}
	for _, endpoint := range result.Endpoints {
		if endpoint.Skipped {
			lines = append(lines, fmt.Sprintf("  %s: skipped, preserved %d key(s): %s", endpoint.Alias, endpoint.PreservedCount, endpoint.Error))
			continue
		}
		if len(endpoint.Keys) == 0 {
			lines = append(lines, fmt.Sprintf("  %s: none", endpoint.Alias))
			continue
		}
		lines = append(lines, fmt.Sprintf("  %s:", endpoint.Alias))
		for _, key := range endpoint.Keys {
			lines = append(lines, fmt.Sprintf("    %s (%s, %s)", key.PublicKey, key.KeyType, key.ComponentKey))
		}
	}
	return lines
}
