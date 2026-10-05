// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/aplane-algo/aplane/internal/clientdata"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/cosigner/enrollment"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/tokenfile"
	"github.com/aplane-algo/aplane/internal/witness"
)

// EndpointImportRequest imports one public endpoint handoff envelope.
type EndpointImportRequest struct {
	Alias  string
	Role   string
	Path   string
	DryRun bool
}

// EndpointCreateCosignerRequest creates or replaces one client-local cosigner
// endpoint profile without requiring an exported endpoint envelope.
type EndpointCreateCosignerRequest struct {
	Alias        string
	URL          string
	CosignerPort int
	DryRun       bool
}

// EndpointDiscoverCosignersRequest requests a read-only sweep of configured
// cosigner endpoint inventories.
type EndpointDiscoverCosignersRequest struct{}

// EndpointsList returns the resolved client endpoint registry.
func (a *App) EndpointsList(_ context.Context) (*EndpointsListResult, error) {
	registry, err := a.loadEndpointView()
	if err != nil {
		return nil, err
	}

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
	registry, err := a.loadEndpointView()
	if err != nil {
		return nil, err
	}

	endpoint, ok := registry.Endpoint(alias)
	if !ok {
		return nil, fmt.Errorf("unknown endpoint alias %q", alias)
	}
	defaultAlias, _, _ := registry.DefaultEndpoint()
	return &EndpointShowResult{
		Endpoint: a.endpointEntry(alias, endpoint, alias == defaultAlias),
	}, nil
}

// EndpointImport imports an apadmin-exported public endpoint envelope into the
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
		if isCosignerEnrollmentDocument(data) {
			return nil, fmt.Errorf("%s is a cosigner key document, not an endpoint envelope; "+
				"use 'endpoints add %s --alias %s' instead", req.Path, req.Path, req.Alias)
		}
		return nil, err
	}

	endpoint := config.ClientEndpointConfig{
		Role: req.Role, URL: env.URL, SignerPort: env.SignerPort, LocalPort: env.LocalPort,
	}
	var endpointPlan config.StoredClientEndpointUpsertPlan
	if req.DryRun {
		endpointPlan, err = config.PlanStoredClientEndpointUpsert(a.DataDir, req.Alias, endpoint, true)
	} else {
		endpointPlan, err = lockedEndpointUpsert(a.DataDir, req.Alias, endpoint, true)
	}
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
		TokenRetired:   endpointPlan.RetiresExistingToken,
	}

	if !req.DryRun {
		if err := a.reloadConfigAfterEndpointChange(); err != nil {
			return nil, err
		}
	}
	result.RenderLines = endpointImportRenderLines(result)
	return result, nil
}

// isCosignerEnrollmentDocument reports whether data carries one of the public
// cosigner key schemas that 'endpoints add' accepts, so a misdirected endpoint
// import can point at the right command.
func isCosignerEnrollmentDocument(data []byte) bool {
	var discriminator struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &discriminator); err != nil {
		return false
	}
	return discriminator.Schema == enrollment.Schema || discriminator.Schema == witness.PublicReferenceSchema
}

// EndpointCreateCosigner creates or replaces a client-local cosigner endpoint
// profile. It does not copy tokens, host-key trust, or cosigner key inventory.
func (a *App) EndpointCreateCosigner(_ context.Context, req EndpointCreateCosignerRequest) (*EndpointCreateCosignerResult, error) {
	if err := config.ValidateClientEndpointAlias(req.Alias); err != nil {
		return nil, fmt.Errorf("endpoint alias is required: %w", err)
	}
	if req.URL == "" {
		return nil, fmt.Errorf("endpoint URL is required")
	}
	if req.CosignerPort <= 0 || req.CosignerPort > 65535 {
		return nil, fmt.Errorf("cosigner port must be 1-65535")
	}

	endpoint := config.ClientEndpointConfig{
		Role:       config.ClientEndpointRoleCosigner,
		URL:        req.URL,
		SignerPort: req.CosignerPort,
	}
	var (
		endpointPlan config.StoredClientEndpointUpsertPlan
		err          error
	)
	if req.DryRun {
		endpointPlan, err = config.PlanStoredClientEndpointUpsert(a.DataDir, req.Alias, endpoint, true)
	} else {
		endpointPlan, err = lockedEndpointUpsert(a.DataDir, req.Alias, endpoint, true)
	}
	if err != nil {
		return nil, err
	}

	result := &EndpointCreateCosignerResult{
		Alias:        req.Alias,
		Role:         endpointPlan.Endpoint.Role,
		URL:          endpointPlan.Endpoint.URL,
		CosignerPort: endpointPlan.Endpoint.SignerPort,
		TokenFile:    endpointPlan.Endpoint.TokenFile,
		DryRun:       req.DryRun,
		Created:      endpointPlan.Created,
		Updated:      endpointPlan.Updated,
		TokenRetired: endpointPlan.RetiresExistingToken,
	}

	if !req.DryRun {
		if err := a.reloadConfigAfterEndpointChange(); err != nil {
			return nil, err
		}
	}
	result.RenderLines = endpointCreateCosignerRenderLines(result)
	return result, nil
}

// EndpointDiscoverCosigners performs a read-only diagnostic sweep of configured
// endpoint /keys inventories.
func (a *App) EndpointDiscoverCosigners(ctx context.Context, _ EndpointDiscoverCosignersRequest) (*EndpointDiscoverCosignersResult, error) {
	result, err := a.discoverEndpointCosigners(ctx)
	if err != nil {
		return nil, err
	}
	result.RenderLines = endpointDiscoverCosignersRenderLines(result)
	return result, nil
}

func (a *App) discoverEndpointCosigners(ctx context.Context) (*EndpointDiscoverCosignersResult, error) {
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return nil, err
	}
	a.adoptConfig(cfg)

	aliases := make([]string, 0, len(cfg.Endpoints.Endpoints))
	for alias, endpoint := range cfg.Endpoints.Endpoints {
		if endpoint.Role == config.ClientEndpointRoleCosigner {
			aliases = append(aliases, alias)
		}
	}
	sort.Strings(aliases)
	if len(aliases) == 0 {
		return nil, fmt.Errorf("no cosigner endpoints configured")
	}

	discoveries := make([]EndpointCosignerDiscovery, 0, len(aliases))
	seenPublicKeys := map[string]string{}
	publicKeyCount := 0
	for _, alias := range aliases {
		endpoint := cfg.Endpoints.Endpoints[alias]
		keys, err := a.eng.DiscoverCosignerComponentKeys(ctx, endpoint)
		if err != nil {
			if !errors.Is(err, engine.ErrCosignerDiscoveryUnavailable) &&
				!errors.Is(err, engine.ErrCosignerDiscoveryLocked) {
				return nil, fmt.Errorf("endpoint %q discovery failed: %w", alias, err)
			}
			discoveries = append(discoveries, EndpointCosignerDiscovery{
				Alias:   alias,
				Skipped: true,
				Error:   err.Error(),
			})
			continue
		}
		discovery := EndpointCosignerDiscovery{Alias: alias}
		for _, key := range keys {
			if previousAlias, exists := seenPublicKeys[key.PublicKey]; exists {
				return nil, fmt.Errorf("cosigner public key advertised by both endpoint aliases %q and %q", previousAlias, alias)
			}
			seenPublicKeys[key.PublicKey] = alias
			discovery.Keys = append(discovery.Keys, DiscoveredEndpointCosignerKey{
				PublicKey:    key.PublicKey,
				ComponentKey: key.ComponentKey,
				KeyType:      key.KeyType,
			})
			publicKeyCount++
		}
		discoveries = append(discoveries, discovery)
	}
	result := &EndpointDiscoverCosignersResult{
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
	if err := clientdata.WithExclusiveLock(a.DataDir, func() error {
		_, err := config.SetStoredClientEndpointDefault(a.DataDir, alias)
		return err
	}); err != nil {
		return nil, err
	}
	if err := a.reloadConfigAfterEndpointChange(); err != nil {
		return nil, err
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
	if err := clientdata.WithExclusiveLock(a.DataDir, func() error {
		_, err := config.DeleteStoredClientEndpoint(a.DataDir, alias)
		return err
	}); err != nil {
		return nil, err
	}
	if err := a.reloadConfigAfterEndpointChange(); err != nil {
		return nil, err
	}
	return &EndpointDeleteResult{
		Alias:       alias,
		RenderLines: []string{fmt.Sprintf("Deleted endpoint %s", alias)},
	}, nil
}

func lockedEndpointUpsert(dataDir, alias string, endpoint config.ClientEndpointConfig, replace bool) (config.StoredClientEndpointUpsertPlan, error) {
	var applied config.StoredClientEndpointUpsertPlan
	err := clientdata.WithExclusiveLock(dataDir, func() error {
		plan, err := config.PlanStoredClientEndpointUpsert(dataDir, alias, endpoint, replace)
		if err != nil {
			return err
		}
		if err := config.ApplyStoredClientEndpointUpsert(dataDir, plan); err != nil {
			return err
		}
		applied = plan
		return nil
	})
	return applied, err
}

// loadEndpointView reads the stored endpoint registry and adopts the loaded
// config, so later commands see the same endpoints the view showed.
func (a *App) loadEndpointView() (config.ClientEndpointRegistry, error) {
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return config.ClientEndpointRegistry{}, err
	}
	a.adoptConfig(cfg)
	return cfg.Endpoints, nil
}

// adoptConfig makes cfg the app's config and the engine's endpoint registry,
// keeping alias resolution and guarded routing on one view of endpoints.yaml.
func (a *App) adoptConfig(cfg config.Config) {
	a.Config = cfg
	if a.eng != nil {
		a.eng.EndpointRegistry = cfg.Endpoints.Clone()
	}
}

// reloadConfigAfterEndpointChange adopts the stored config after a saved
// endpoint change. A failed reload is reported rather than leaving the app on
// the pre-change endpoints.
func (a *App) reloadConfigAfterEndpointChange() error {
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return fmt.Errorf("endpoint change was saved, but reloading the client config failed: %w", err)
	}
	a.adoptConfig(cfg)
	return nil
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
	return append(lines, endpointTokenRetiredLines(result.TokenRetired, result.DryRun)...)
}

// endpointTokenRetiredLines explains why a stored token is gone after an alias
// moved to another destination: it was issued by the previous one.
func endpointTokenRetiredLines(retired, dryRun bool) []string {
	if !retired {
		return nil
	}
	if dryRun {
		return []string{"  token: the stored token was issued by the previous destination and would be removed"}
	}
	return []string{"  token: the stored token was issued by the previous destination and was removed"}
}

func endpointCreateCosignerRenderLines(result *EndpointCreateCosignerResult) []string {
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

	return append([]string{
		fmt.Sprintf("%s %s endpoint %s (%s)", action, result.Role, result.Alias, state),
		fmt.Sprintf("  url: %s", result.URL),
		fmt.Sprintf("  cosigner port: %d", result.CosignerPort),
		fmt.Sprintf("  token file: %s", result.TokenFile),
	}, endpointTokenRetiredLines(result.TokenRetired, result.DryRun)...)
}

func endpointDiscoverCosignersRenderLines(result *EndpointDiscoverCosignersResult) []string {
	lines := []string{
		fmt.Sprintf("Discovered cosigner inventory from %d endpoint(s): %d key(s)", len(result.Endpoints), result.PublicKeyCount),
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

func endpointDiscoveredComponentLines(keys []DiscoveredEndpointCosignerKey) []string {
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
