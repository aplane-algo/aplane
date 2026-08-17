// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/engine"
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

// EndpointDiscoverSentriesRequest requests a read-only sweep of configured
// sentry endpoint inventories.
type EndpointDiscoverSentriesRequest struct{}

// EndpointsList returns the resolved client endpoint registry.
func (a *App) EndpointsList(_ context.Context) (*EndpointsListResult, error) {
	cfg, registry, err := a.loadEndpointView()
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
		entries = append(entries, a.endpointEntry(alias, registry.Endpoints[alias], alias == defaultAlias))
	}
	return &EndpointsListResult{Endpoints: entries}, nil
}

// EndpointShow returns one resolved endpoint profile.
func (a *App) EndpointShow(_ context.Context, alias string) (*EndpointShowResult, error) {
	if err := config.ValidateClientEndpointAlias(alias); err != nil {
		return nil, err
	}
	cfg, registry, err := a.loadEndpointView()
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
		Endpoint: a.endpointEntry(alias, endpoint, alias == defaultAlias),
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
			a.eng.EndpointRegistry = cfg.Endpoints.Clone()
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
			a.eng.EndpointRegistry = cfg.Endpoints.Clone()
		}
	}
	result.RenderLines = endpointCreateSentryRenderLines(result)
	return result, nil
}

// EndpointDiscoverSentries performs a read-only diagnostic sweep of configured
// endpoint /keys inventories.
func (a *App) EndpointDiscoverSentries(ctx context.Context, _ EndpointDiscoverSentriesRequest) (*EndpointDiscoverSentriesResult, error) {
	result, err := a.discoverEndpointSentries(ctx)
	if err != nil {
		return nil, err
	}
	result.RenderLines = endpointDiscoverSentriesRenderLines(result)
	return result, nil
}

func (a *App) discoverEndpointSentries(ctx context.Context) (*EndpointDiscoverSentriesResult, error) {
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("no sentry endpoints configured")
	}

	discoveries := make([]EndpointSentryDiscovery, 0, len(aliases))
	seenPublicKeys := map[string]string{}
	publicKeyCount := 0
	for _, alias := range aliases {
		endpoint := cfg.Endpoints.Endpoints[alias]
		keys, err := a.eng.DiscoverSentryComponentKeys(ctx, endpoint)
		if err != nil {
			if !errors.Is(err, engine.ErrSentryDiscoveryUnavailable) &&
				!errors.Is(err, engine.ErrSentryDiscoveryLocked) {
				return nil, fmt.Errorf("endpoint %q discovery failed: %w", alias, err)
			}
			discoveries = append(discoveries, EndpointSentryDiscovery{
				Alias:   alias,
				Skipped: true,
				Error:   err.Error(),
			})
			continue
		}
		discovery := EndpointSentryDiscovery{Alias: alias}
		for _, key := range keys {
			if previousAlias, exists := seenPublicKeys[key.PublicKey]; exists {
				return nil, fmt.Errorf("sentry public key advertised by both endpoint aliases %q and %q", previousAlias, alias)
			}
			seenPublicKeys[key.PublicKey] = alias
			discovery.Keys = append(discovery.Keys, DiscoveredEndpointSentryKey{
				PublicKey:    key.PublicKey,
				ComponentKey: key.ComponentKey,
				KeyType:      key.KeyType,
			})
			publicKeyCount++
		}
		discoveries = append(discoveries, discovery)
	}
	result := &EndpointDiscoverSentriesResult{
		Endpoints:      discoveries,
		PublicKeyCount: publicKeyCount,
	}
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
		a.eng.EndpointRegistry = cfg.Endpoints.Clone()
	}
	return &EndpointDefaultResult{
		Alias:         alias,
		PreviousAlias: previousAlias,
		RenderLines:   []string{fmt.Sprintf("Default endpoint set to %s", alias)},
	}, nil
}

// EndpointDelete deletes a stored endpoint alias when it is not the default.
func (a *App) EndpointDelete(_ context.Context, alias string) (*EndpointDeleteResult, error) {
	if err := config.ValidateClientEndpointAlias(alias); err != nil {
		return nil, err
	}
	if _, err := config.DeleteStoredClientEndpoint(a.DataDir, alias); err != nil {
		return nil, err
	}
	if cfg, err := config.LoadConfig(a.DataDir); err == nil {
		a.Config = cfg
		a.eng.EndpointRegistry = cfg.Endpoints.Clone()
	}
	return &EndpointDeleteResult{
		Alias:       alias,
		RenderLines: []string{fmt.Sprintf("Deleted endpoint %s", alias)},
	}, nil
}

func (a *App) loadEndpointView() (config.Config, config.ClientEndpointRegistry, error) {
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return config.Config{}, config.ClientEndpointRegistry{}, err
	}
	return cfg, cfg.Endpoints, nil
}

func (a *App) endpointEntry(alias string, endpoint config.ClientEndpointConfig, isDefault bool) EndpointEntry {
	tokenPresent, tokenError := endpointTokenStatus(endpoint.TokenFile)
	return EndpointEntry{
		Alias:          alias,
		Role:           endpoint.Role,
		URL:            endpoint.URL,
		SignerPort:     endpoint.SignerPort,
		LocalPort:      endpoint.LocalPort,
		IdentityFile:   endpoint.IdentityFile,
		KnownHostsPath: endpoint.KnownHostsPath,
		TokenFile:      endpoint.TokenFile,
		TokenPresent:   tokenPresent,
		TokenError:     tokenError,
		IsDefault:      isDefault,
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

func endpointDiscoverSentriesRenderLines(result *EndpointDiscoverSentriesResult) []string {
	lines := []string{
		fmt.Sprintf("Discovered sentry inventory from %d endpoint(s): %d key(s)", len(result.Endpoints), result.PublicKeyCount),
	}
	for _, endpoint := range result.Endpoints {
		if endpoint.Skipped {
			lines = append(lines, fmt.Sprintf("  %s: skipped: %s", endpoint.Alias, endpoint.Error))
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
