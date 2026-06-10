// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

// EndpointImportRequest imports one public endpoint handoff envelope.
type EndpointImportRequest struct {
	Alias  string
	Role   string
	Path   string
	DryRun bool
}

// EndpointCreateSentryRequest creates or replaces one client-local sentry
// endpoint profile without requiring an exported endpoint envelope.
type EndpointCreateSentryRequest struct {
	Alias      string
	URL        string
	SentryPort int
	DryRun     bool
}

// EndpointDiscoverSentriesRequest rebuilds endpoint-published sentry
// inventory by querying configured endpoint inventories.
type EndpointDiscoverSentriesRequest struct {
	DryRun bool
}

// EndpointSyncSentriesRequest syncs endpoint-published sentry inventory into
// the connected signer identity's public sentry reference catalog.
type EndpointSyncSentriesRequest struct {
	DryRun            bool
	ApproveSignerSync bool
}

// EndpointsList returns the resolved client endpoint registry plus local
// sentry mappings.
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
		Role:       req.Role,
		URL:        env.URL,
		SignerPort: env.SignerPort,
		LocalPort:  env.LocalPort,
	}, true)
	if err != nil {
		return nil, err
	}

	result := &EndpointImportResult{
		Alias:          req.Alias,
		Role:           endpointPlan.Endpoint.Role,
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

// EndpointCreateSentry creates or replaces a client-local sentry endpoint
// profile. It does not copy tokens, host-key trust, or sentry key inventory.
func (a *App) EndpointCreateSentry(_ context.Context, req EndpointCreateSentryRequest) (*EndpointCreateSentryResult, error) {
	if err := config.ValidateClientEndpointAlias(req.Alias); err != nil {
		return nil, fmt.Errorf("endpoint alias is required: %w", err)
	}
	if req.URL == "" {
		return nil, fmt.Errorf("endpoint URL is required")
	}
	if req.SentryPort <= 0 || req.SentryPort > 65535 {
		return nil, fmt.Errorf("sentry port must be 1-65535")
	}

	endpointPlan, err := config.PlanStoredClientEndpointUpsert(a.DataDir, req.Alias, config.ClientEndpointConfig{
		Role:       config.ClientEndpointRoleSentry,
		URL:        req.URL,
		SignerPort: req.SentryPort,
	}, true)
	if err != nil {
		return nil, err
	}

	result := &EndpointCreateSentryResult{
		Alias:      req.Alias,
		Role:       endpointPlan.Endpoint.Role,
		URL:        endpointPlan.Endpoint.URL,
		SentryPort: endpointPlan.Endpoint.SignerPort,
		TokenFile:  endpointPlan.Endpoint.TokenFile,
		DryRun:     req.DryRun,
		Created:    endpointPlan.Created,
		Updated:    endpointPlan.Updated,
	}

	if !req.DryRun {
		if err := config.ApplyStoredClientEndpointUpsert(a.DataDir, endpointPlan); err != nil {
			return nil, err
		}
		if cfg, err := config.LoadConfig(a.DataDir); err == nil {
			a.Config = cfg
		}
	}
	result.RenderLines = endpointCreateSentryRenderLines(result)
	return result, nil
}

// EndpointDiscoverSentries queries configured endpoint /keys inventories and
// atomically rebuilds reachable endpoint published_sentries inventory.
// Unreachable endpoints are preserved as no-ops so temporary outages do not
// erase client routing state.
func (a *App) EndpointDiscoverSentries(ctx context.Context, req EndpointDiscoverSentriesRequest) (*EndpointDiscoverSentriesResult, error) {
	result, _, err := a.discoverEndpointSentries(ctx, req.DryRun)
	if err != nil {
		return nil, err
	}
	result.RenderLines = endpointDiscoverSentriesRenderLines(result)
	return result, nil
}

func (a *App) discoverEndpointSentries(ctx context.Context, dryRun bool) (*EndpointDiscoverSentriesResult, config.ClientEndpointRegistry, error) {
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return nil, config.ClientEndpointRegistry{}, err
	}
	a.Config = cfg

	aliases := make([]string, 0, len(cfg.Endpoints.Endpoints))
	for alias, endpoint := range cfg.Endpoints.Endpoints {
		if endpoint.Role == config.ClientEndpointRoleSentry {
			aliases = append(aliases, alias)
		}
	}
	sort.Strings(aliases)
	if len(aliases) == 0 {
		return nil, config.ClientEndpointRegistry{}, fmt.Errorf("no sentry endpoints configured")
	}

	lastSeenAt := time.Now().UTC().Format(time.RFC3339)
	publications := map[string]map[string]config.ClientEndpointPublishedSentry{}
	discoveries := make([]EndpointSentryDiscovery, 0, len(aliases))
	for _, alias := range aliases {
		endpoint := cfg.Endpoints.Endpoints[alias]
		keys, err := a.eng.DiscoverSentryComponentKeys(ctx, endpoint)
		if err != nil {
			if !errors.Is(err, engine.ErrSentryDiscoveryUnavailable) &&
				!errors.Is(err, engine.ErrSentryDiscoveryLocked) {
				return nil, config.ClientEndpointRegistry{}, fmt.Errorf("endpoint %q discovery failed: %w", alias, err)
			}
			preserved := clonePublishedSentries(endpoint.PublishedSentries)
			publications[alias] = preserved
			discoveries = append(discoveries, EndpointSentryDiscovery{
				Alias:          alias,
				Skipped:        true,
				PreservedCount: len(preserved),
				Error:          err.Error(),
			})
			continue
		}
		publications[alias] = map[string]config.ClientEndpointPublishedSentry{}
		discovery := EndpointSentryDiscovery{Alias: alias}
		for _, key := range keys {
			discovery.Keys = append(discovery.Keys, DiscoveredEndpointSentryKey{
				PublicKey:    key.PublicKey,
				ComponentKey: key.ComponentKey,
				KeyType:      key.KeyType,
			})
			publications[alias][key.PublicKey] = config.ClientEndpointPublishedSentry{
				ComponentKey: key.ComponentKey,
				KeyType:      key.KeyType,
				LastSeenAt:   lastSeenAt,
			}
		}
		discoveries = append(discoveries, discovery)
	}

	plan, err := config.PlanStoredClientEndpointPublishedSentryRebuild(a.DataDir, publications)
	if err != nil {
		return nil, config.ClientEndpointRegistry{}, err
	}
	result := &EndpointDiscoverSentriesResult{
		DryRun:                 dryRun,
		Endpoints:              discoveries,
		PublicKeyCount:         plan.PublicKeyCount,
		PreviousPublishedCount: plan.PreviousPublishedCount,
	}
	if !dryRun {
		if err := config.ApplyStoredClientEndpointPublishedSentryRebuild(a.DataDir, plan); err != nil {
			return nil, config.ClientEndpointRegistry{}, err
		}
		if cfg, err := config.LoadConfig(a.DataDir); err == nil {
			a.Config = cfg
			a.eng.SentryEndpoints = cfg.SentryEndpoints.Clone()
		}
	}
	return result, plan.Registry, nil
}

// EndpointSyncSentries publishes endpoint-discovered sentry metadata into
// the connected signer identity so signer-side key generation can select those
// sentries by name.
func (a *App) EndpointSyncSentries(ctx context.Context, req EndpointSyncSentriesRequest) (*EndpointSyncSentriesResult, error) {
	discovery, registry, err := a.discoverEndpointSentries(ctx, req.DryRun)
	if err != nil {
		return nil, err
	}

	candidates := endpointSentryCandidates(registry)
	result := &EndpointSyncSentriesResult{
		DryRun:         req.DryRun,
		Discovery:      discovery,
		CandidateCount: len(candidates),
	}
	for _, candidate := range candidates {
		name, err := sentryrefs.SyncedReferenceName(candidate.EndpointAlias, candidate.ComponentKey)
		if err != nil {
			return nil, err
		}
		result.Records = append(result.Records, SyncedEndpointSentryReference{
			Name:          name,
			EndpointAlias: candidate.EndpointAlias,
			PublicKey:     candidate.PublicKeyHex,
			ComponentKey:  candidate.ComponentKey,
			KeyType:       candidate.KeyType,
		})
	}
	if req.DryRun {
		result.RenderLines = endpointSyncSentriesRenderLines(result)
		return result, nil
	}
	if !req.ApproveSignerSync {
		result.NeedsConfirmation = true
		result.RenderLines = endpointSyncSentriesRenderLines(result)
		return result, nil
	}
	if err := a.syncEndpointSentriesToSigner(ctx, result); err != nil {
		return nil, err
	}
	result.RenderLines = endpointSyncSentriesRenderLines(result)
	return result, nil
}

func (a *App) syncEndpointSentriesToSigner(ctx context.Context, result *EndpointSyncSentriesResult) error {
	if !a.eng.IsConnected() {
		return fmt.Errorf("not connected to Signer")
	}
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return err
	}
	a.Config = cfg
	candidates := endpointSentryCandidates(cfg.Endpoints)
	resp, err := a.eng.AdminSyncSentryReferencesWithContext(ctx, candidates)
	if err != nil {
		return err
	}
	result.CandidateCount = len(candidates)
	result.Added = resp.Added
	result.Updated = resp.Updated
	result.Removed = resp.Removed
	result.Records = nil
	for _, rec := range resp.Records {
		result.Records = append(result.Records, SyncedEndpointSentryReference{
			Name:          rec.Name,
			EndpointAlias: rec.EndpointAlias,
			PublicKey:     rec.PublicKeyHex,
			ComponentKey:  rec.ComponentKey,
			KeyType:       rec.KeyType,
		})
	}
	return nil
}

// EndpointConfirmSyncSentries publishes the current endpoint-discovered
// sentry inventory to the connected signer identity after user confirmation.
func (a *App) EndpointConfirmSyncSentries(ctx context.Context) (*EndpointSyncSentriesResult, error) {
	result := &EndpointSyncSentriesResult{}
	if err := a.syncEndpointSentriesToSigner(ctx, result); err != nil {
		return nil, err
	}
	result.RenderLines = endpointSyncSentriesRenderLines(result)
	return result, nil
}

// EndpointSentries returns the client-local sentry inventory learned from
// endpoint discovery.
func (a *App) EndpointSentries(_ context.Context) (*EndpointSentriesResult, error) {
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return nil, err
	}
	a.Config = cfg
	candidates := endpointSentryCandidates(cfg.Endpoints)
	result := &EndpointSentriesResult{
		Sentries: make([]EndpointSentryEntry, 0, len(candidates)),
	}
	for _, candidate := range candidates {
		result.Sentries = append(result.Sentries, EndpointSentryEntry{
			EndpointAlias: candidate.EndpointAlias,
			ComponentKey:  candidate.ComponentKey,
			KeyType:       candidate.KeyType,
			LastSeenAt:    candidate.LastSeenAt,
		})
	}
	result.RenderLines = endpointSentriesRenderLines(result)
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
// no local sentry routes still reference it.
func (a *App) EndpointDelete(_ context.Context, alias string) (*EndpointDeleteResult, error) {
	if err := config.ValidateClientEndpointAlias(alias); err != nil {
		return nil, err
	}
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return nil, err
	}
	blocking := append([]string(nil), sentryEndpointMappingsByAlias(cfg.SentryEndpoints)[alias]...)
	sort.Strings(blocking)
	if len(blocking) > 0 {
		return nil, fmt.Errorf("endpoint alias %q is referenced by %d sentry mapping(s)", alias, len(blocking))
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
	mappings := cfg.Endpoints.PublishedSentryPublicKeysByAlias()
	return cfg, cfg.Endpoints, mappings, nil
}

func sentryEndpointMappingsByAlias(routes config.SentryEndpointConfigs) map[string][]string {
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

func clonePublishedSentries(in map[string]config.ClientEndpointPublishedSentry) map[string]config.ClientEndpointPublishedSentry {
	out := make(map[string]config.ClientEndpointPublishedSentry, len(in))
	for publicKey, published := range in {
		out[publicKey] = published
	}
	return out
}

func endpointSentryCandidates(registry config.ClientEndpointRegistry) []signerapi.SentryReferenceCandidate {
	aliases := make([]string, 0, len(registry.Endpoints))
	for alias := range registry.Endpoints {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)

	candidates := make([]signerapi.SentryReferenceCandidate, 0)
	for _, alias := range aliases {
		endpoint := registry.Endpoints[alias]
		if endpoint.Role != config.ClientEndpointRoleSentry {
			continue
		}
		publicKeys := make([]string, 0, len(endpoint.PublishedSentries))
		for publicKey := range endpoint.PublishedSentries {
			publicKeys = append(publicKeys, publicKey)
		}
		sort.Strings(publicKeys)
		for _, publicKey := range publicKeys {
			published := endpoint.PublishedSentries[publicKey]
			candidates = append(candidates, signerapi.SentryReferenceCandidate{
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
	sentries := endpointPublishedSentries(alias, endpoint)
	components := endpointPublishedSentryComponents(sentries)
	return EndpointEntry{
		Alias:                     alias,
		Role:                      endpoint.Role,
		URL:                       endpoint.URL,
		SignerPort:                endpoint.SignerPort,
		LocalPort:                 endpoint.LocalPort,
		IdentityFile:              endpoint.IdentityFile,
		KnownHostsPath:            endpoint.KnownHostsPath,
		TokenFile:                 endpoint.TokenFile,
		TokenPresent:              tokenPresent,
		TokenError:                tokenError,
		IsDefault:                 isDefault,
		PublishedSentryPublicKeys: keys,
		PublishedSentryComponents: components,
		PublishedSentries:         sentries,
	}
}

func endpointPublishedSentries(alias string, endpoint config.ClientEndpointConfig) []EndpointSentryEntry {
	publicKeys := make([]string, 0, len(endpoint.PublishedSentries))
	for publicKey := range endpoint.PublishedSentries {
		publicKeys = append(publicKeys, publicKey)
	}
	sort.Strings(publicKeys)
	sentries := make([]EndpointSentryEntry, 0, len(publicKeys))
	for _, publicKey := range publicKeys {
		published := endpoint.PublishedSentries[publicKey]
		if published.ComponentKey == "" {
			continue
		}
		sentries = append(sentries, EndpointSentryEntry{
			EndpointAlias: alias,
			ComponentKey:  published.ComponentKey,
			KeyType:       published.KeyType,
			LastSeenAt:    published.LastSeenAt,
		})
	}
	return sentries
}

func endpointPublishedSentryComponents(sentries []EndpointSentryEntry) []string {
	components := make([]string, 0, len(sentries))
	for _, sentry := range sentries {
		components = append(components, sentry.ComponentKey)
	}
	sort.Strings(components)
	return components
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
		fmt.Sprintf("%s %s endpoint %s (%s)", action, result.Role, result.Alias, state),
		fmt.Sprintf("  url: %s", result.URL),
		fmt.Sprintf("  token file: %s", result.TokenFile),
	}
	if result.DefaultChanged {
		lines = append(lines, "  default: yes")
	}
	return lines
}

func endpointCreateSentryRenderLines(result *EndpointCreateSentryResult) []string {
	action := "Configured"
	if result.DryRun {
		action = "Would configure"
	}
	state := "unchanged"
	switch {
	case result.Created:
		state = "created"
	case result.Updated:
		state = "updated"
	}

	return []string{
		fmt.Sprintf("%s %s endpoint %s (%s)", action, result.Role, result.Alias, state),
		fmt.Sprintf("  url: %s", result.URL),
		fmt.Sprintf("  sentry port: %d", result.SentryPort),
		fmt.Sprintf("  token file: %s", result.TokenFile),
	}
}

func endpointSyncSentriesRenderLines(result *EndpointSyncSentriesResult) []string {
	action := "Synced"
	if result.DryRun {
		action = "Would sync"
	}
	lines := []string{
		fmt.Sprintf("%s %d endpoint-discovered sentry reference(s) to signer", action, result.CandidateCount),
	}
	if result.Discovery != nil {
		lines = append(lines, endpointDiscoverSentriesRenderLines(result.Discovery)...)
	}
	if result.NeedsConfirmation {
		lines = append(lines, "Confirm before syncing these sentries to the signer library.")
	}
	if !result.DryRun && !result.NeedsConfirmation {
		lines = append(lines,
			fmt.Sprintf("  added: %d", result.Added),
			fmt.Sprintf("  updated: %d", result.Updated),
			fmt.Sprintf("  removed stale: %d", result.Removed),
		)
	}
	lines = append(lines, endpointSyncSentrySummaryLines(result.Records)...)
	return lines
}

func endpointDiscoverSentriesRenderLines(result *EndpointDiscoverSentriesResult) []string {
	action := "Rebuilt"
	if result.DryRun {
		action = "Would rebuild"
	}
	lines := []string{
		fmt.Sprintf("%s endpoint-published sentry inventory from %d endpoint(s): %d key(s)",
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
		lines = append(lines, fmt.Sprintf("  %s: %d key(s)", endpoint.Alias, len(endpoint.Keys)))
		lines = append(lines, endpointDiscoveredComponentLines(endpoint.Keys)...)
	}
	return lines
}

func endpointSyncSentrySummaryLines(records []SyncedEndpointSentryReference) []string {
	if len(records) == 0 {
		return nil
	}
	counts := map[string]map[string]int{}
	for _, rec := range records {
		if counts[rec.EndpointAlias] == nil {
			counts[rec.EndpointAlias] = map[string]int{}
		}
		counts[rec.EndpointAlias][rec.KeyType]++
	}
	aliases := make([]string, 0, len(counts))
	for alias := range counts {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)

	lines := make([]string, 0, len(records)+len(aliases))
	for _, alias := range aliases {
		total := 0
		for _, count := range counts[alias] {
			total += count
		}
		lines = append(lines, fmt.Sprintf("  %s: %d key(s)", alias, total))
		for _, rec := range records {
			if rec.EndpointAlias == alias {
				lines = append(lines, fmt.Sprintf("    %s (%s)", rec.ComponentKey, rec.KeyType))
			}
		}
	}
	return lines
}

func endpointDiscoveredComponentLines(keys []DiscoveredEndpointSentryKey) []string {
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ComponentKey == keys[j].ComponentKey {
			return keys[i].KeyType < keys[j].KeyType
		}
		return keys[i].ComponentKey < keys[j].ComponentKey
	})
	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("    %s (%s)", key.ComponentKey, key.KeyType))
	}
	return lines
}

func endpointSentriesRenderLines(result *EndpointSentriesResult) []string {
	if len(result.Sentries) == 0 {
		return []string{"No endpoint-discovered sentries"}
	}
	lines := []string{fmt.Sprintf("Endpoint-discovered sentries: %d", len(result.Sentries))}
	for _, sentry := range result.Sentries {
		lines = append(lines, fmt.Sprintf("  %s: %s (%s)", sentry.EndpointAlias, sentry.ComponentKey, sentry.KeyType))
	}
	return lines
}
