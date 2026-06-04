// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

// EndpointImportRequest imports one public endpoint handoff envelope.
type EndpointImportRequest struct {
	Alias  string
	Path   string
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
		Role:       env.Role,
		URL:        env.URL,
		SignerPort: env.SignerPort,
		LocalPort:  env.LocalPort,
	}, false)
	if err != nil {
		return nil, err
	}

	publicKeys := endpointImportAttestorPublicKeys(env)
	mappingPlan, err := config.PlanClientAttestorEndpointAliases(a.DataDir, req.Alias, publicKeys)
	if err != nil {
		return nil, err
	}

	result := &EndpointImportResult{
		Alias:              req.Alias,
		Role:               env.Role,
		URL:                endpointPlan.Endpoint.URL,
		SignerPort:         endpointPlan.Endpoint.SignerPort,
		LocalPort:          endpointPlan.Endpoint.LocalPort,
		TokenFile:          endpointPlan.Endpoint.TokenFile,
		DryRun:             req.DryRun,
		Created:            endpointPlan.Created,
		Updated:            endpointPlan.Updated,
		DefaultChanged:     endpointPlan.DefaultChanged,
		AttestorPublicKeys: append([]string(nil), mappingPlan.PublicKeys...),
	}

	if !req.DryRun {
		if err := config.ApplyStoredClientEndpointUpsert(a.DataDir, endpointPlan); err != nil {
			return nil, err
		}
		if len(mappingPlan.PublicKeys) > 0 {
			if err := config.ApplyClientAttestorEndpointAliases(a.DataDir, mappingPlan); err != nil {
				return nil, err
			}
		}
		if cfg, err := config.LoadConfig(a.DataDir); err == nil {
			a.Config = cfg
		}
	}
	result.RenderLines = endpointImportRenderLines(result)
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
	endpoint, ok := cfg.Endpoints.Endpoint(alias)
	if !ok {
		return nil, fmt.Errorf("unknown endpoint alias %q", alias)
	}
	if endpoint.Role == endpointrefs.RoleAttestation {
		return nil, fmt.Errorf("endpoint alias %q has role attestation and cannot be the default signing endpoint", alias)
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
	mappings, err := config.ClientAttestorEndpointMappingsByAlias(a.DataDir)
	if err != nil {
		return nil, err
	}
	blocking := append([]string(nil), mappings[alias]...)
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
	mappings, err := config.ClientAttestorEndpointMappingsByAlias(a.DataDir)
	if err != nil {
		return config.Config{}, config.ClientEndpointRegistry{}, nil, err
	}
	return cfg, cfg.Endpoints, mappings, nil
}

func (a *App) endpointEntry(alias string, endpoint config.ClientEndpointConfig, isDefault bool, publicKeys []string) EndpointEntry {
	tokenPresent, tokenError := endpointTokenStatus(endpoint.TokenFile)
	keys := append([]string(nil), publicKeys...)
	sort.Strings(keys)
	return EndpointEntry{
		Alias:                   alias,
		Role:                    endpoint.Role,
		URL:                     endpoint.URL,
		SignerPort:              endpoint.SignerPort,
		LocalPort:               endpoint.LocalPort,
		IdentityFile:            endpoint.IdentityFile,
		KnownHostsPath:          endpoint.KnownHostsPath,
		TokenFile:               endpoint.TokenFile,
		TokenPresent:            tokenPresent,
		TokenError:              tokenError,
		IsDefault:               isDefault,
		LocalAttestorPublicKeys: keys,
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

func endpointImportAttestorPublicKeys(env endpointrefs.Envelope) []string {
	if env.Role == endpointrefs.RoleSigning {
		return nil
	}
	publicKeys := make([]string, 0, len(env.AttestorPublicKeys))
	for _, key := range env.AttestorPublicKeys {
		publicKeys = append(publicKeys, key.PublicKeyHex)
	}
	return publicKeys
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
		fmt.Sprintf("  role: %s", result.Role),
		fmt.Sprintf("  url: %s", result.URL),
		fmt.Sprintf("  token file: %s", result.TokenFile),
	}
	if result.DefaultChanged {
		lines = append(lines, "  default: yes")
	}
	if len(result.AttestorPublicKeys) > 0 {
		lines = append(lines, fmt.Sprintf("  attestor mappings: %d", len(result.AttestorPublicKeys)))
		for _, publicKey := range result.AttestorPublicKeys {
			lines = append(lines, fmt.Sprintf("    %s", publicKey))
		}
	}
	return lines
}
