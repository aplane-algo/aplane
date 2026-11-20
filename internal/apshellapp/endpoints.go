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
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
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
	Alias  string
	URL    string
	DryRun bool
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

	signerAlias, _, _ := registry.SignerEndpoint()
	entries := make([]EndpointEntry, 0, len(aliases))
	for _, alias := range aliases {
		entries = append(entries, a.endpointEntry(alias, registry.Endpoints[alias], alias == signerAlias))
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
	signerAlias, _, _ := registry.SignerEndpoint()
	return &EndpointShowResult{
		Endpoint: a.endpointEntry(alias, endpoint, alias == signerAlias),
	}, nil
}

// EndpointPublicKey returns the public key of an endpoint's SSH identity, for an
// operator to import, or of the signer endpoint's if alias is empty. It reads the
// existing key and never creates one, so it works at any time and repeatedly.
func (a *App) EndpointPublicKey(_ context.Context, alias string) (*EndpointPublicKeyResult, error) {
	registry, err := a.loadEndpointView()
	if err != nil {
		return nil, err
	}
	var endpoint config.ClientEndpointConfig
	if alias == "" {
		var ok bool
		alias, endpoint, ok = registry.SignerEndpoint()
		if !ok {
			return nil, fmt.Errorf("no default endpoint; name one with: endpoints public-key <alias>")
		}
	} else {
		if err := config.ValidateClientEndpointAlias(alias); err != nil {
			return nil, err
		}
		var ok bool
		endpoint, ok = registry.Endpoint(alias)
		if !ok {
			return nil, fmt.Errorf("unknown endpoint alias %q", alias)
		}
	}

	// Loading endpoints gives each one an identity file.
	identityFile := endpoint.IdentityFile
	key, err := sshtunnel.ReadIdentityPublicKey(identityFile)
	switch {
	case errors.Is(err, sshtunnel.ErrNoIdentityKey):
		return nil, fmt.Errorf("endpoint %q has no SSH key yet at %s; one is created the first time it connects", alias, identityFile)
	case errors.Is(err, sshtunnel.ErrIdentityKeyEncrypted):
		return nil, fmt.Errorf("the SSH key at %s is encrypted, so apshell can't read it; "+
			"ssh-keygen -y -f %s prints its public key after asking for the passphrase", identityFile, identityFile)
	case err != nil:
		return nil, err
	}
	return &EndpointPublicKeyResult{Alias: alias, PublicKey: key.AuthorizedKey, Fingerprint: key.Fingerprint}, nil
}

// EndpointImport imports an apadmin-exported public endpoint envelope into the
// local client registry. It does not copy host-key trust.
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
		if isCosignerKeyDocument(data) {
			return nil, fmt.Errorf("%s is a cosigner key file, not an endpoint envelope; "+
				"the signer imports it (apadmin cosigner import); on this client run 'endpoints add <cosigner-url> --alias %s'", req.Path, req.Alias)
		}
		return nil, err
	}

	endpointPlan, err := a.upsertEndpoint(req.Alias, config.ClientEndpointConfig{Role: req.Role, URL: env.URL}, req.DryRun)
	if err != nil {
		return nil, err
	}

	result := &EndpointImportResult{
		Alias:   req.Alias,
		Role:    endpointPlan.Endpoint.Role,
		URL:     endpointPlan.Endpoint.URL,
		DryRun:  req.DryRun,
		Created: endpointPlan.Created,
		Updated: endpointPlan.Updated,
	}
	action := "Imported"
	if result.DryRun {
		action = "Would import"
	}
	result.RenderLines = endpointUpsertLines(action, endpointPlan)
	return result, nil
}

// isCosignerKeyDocument reports whether data is a cosigner's public key file,
// which belongs on the signer, so a misdirected endpoint import can say where
// it goes.
func isCosignerKeyDocument(data []byte) bool {
	var discriminator struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &discriminator); err != nil {
		return false
	}
	return discriminator.Schema == witness.PublicReferenceSchema
}

// EndpointCreateCosigner creates or replaces a client-local cosigner endpoint
// profile. It does not copy host-key trust or cosigner key inventory.
func (a *App) EndpointCreateCosigner(_ context.Context, req EndpointCreateCosignerRequest) (*EndpointCreateCosignerResult, error) {
	if err := config.ValidateClientEndpointAlias(req.Alias); err != nil {
		return nil, fmt.Errorf("endpoint alias is required: %w", err)
	}
	if req.URL == "" {
		return nil, fmt.Errorf("endpoint URL is required")
	}

	endpointPlan, err := a.upsertEndpoint(req.Alias, config.ClientEndpointConfig{Role: config.ClientEndpointRoleCosigner, URL: req.URL}, req.DryRun)
	if err != nil {
		return nil, err
	}

	result := &EndpointCreateCosignerResult{
		Alias:   req.Alias,
		Role:    endpointPlan.Endpoint.Role,
		URL:     endpointPlan.Endpoint.URL,
		DryRun:  req.DryRun,
		Created: endpointPlan.Created,
		Updated: endpointPlan.Updated,
	}
	action := "Configured"
	if result.DryRun {
		action = "Would configure"
	}
	result.RenderLines = endpointUpsertLines(action, endpointPlan)
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
	// A component key is its key type and public key together, as routing
	// matches it: one endpoint may advertise a public key under two key types.
	type componentIdentity struct{ keyType, publicKey string }
	seen := map[componentIdentity]string{}
	cosignerKeyCount := 0
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
			identity := componentIdentity{keyType: key.KeyType, publicKey: key.PublicKey}
			if previousAlias, exists := seen[identity]; exists {
				return nil, fmt.Errorf("cosigner public key under key type %s advertised by both endpoint aliases %q and %q", key.KeyType, previousAlias, alias)
			}
			seen[identity] = alias
			discovery.Keys = append(discovery.Keys, DiscoveredEndpointCosignerKey{
				PublicKey:    key.PublicKey,
				ComponentKey: key.ComponentKey,
				KeyType:      key.KeyType,
			})
			cosignerKeyCount++
		}
		discoveries = append(discoveries, discovery)
	}
	result := &EndpointDiscoverCosignersResult{
		Endpoints:        discoveries,
		CosignerKeyCount: cosignerKeyCount,
	}
	return result, nil
}

// EndpointDelete deletes a stored endpoint alias when it is not the signer
// endpoint.
// The node keeps its own enrollment of this client's key; deleting the
// endpoint here does not revoke it there.
func (a *App) EndpointDelete(_ context.Context, alias string) (*EndpointDeleteResult, error) {
	if err := config.ValidateClientEndpointAlias(alias); err != nil {
		return nil, err
	}
	if err := clientdata.WithExclusiveLock(a.DataDir, func() error {
		return config.RemoveStoredClientEndpoint(a.DataDir, alias)
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

// upsertEndpoint plans alias's endpoint, replacing any it has. Unless dryRun,
// it saves the plan under the client data lock and adopts the reloaded
// config.
func (a *App) upsertEndpoint(alias string, endpoint config.ClientEndpointConfig, dryRun bool) (config.StoredClientEndpointUpsertPlan, error) {
	if dryRun {
		return config.PlanStoredClientEndpointUpsert(a.DataDir, alias, endpoint, true)
	}
	var applied config.StoredClientEndpointUpsertPlan
	err := clientdata.WithExclusiveLock(a.DataDir, func() error {
		plan, err := config.PlanStoredClientEndpointUpsert(a.DataDir, alias, endpoint, true)
		if err != nil {
			return err
		}
		if err := config.SaveStoredClientEndpointRegistry(a.DataDir, plan.Registry); err != nil {
			return err
		}
		applied = plan
		return nil
	})
	if err != nil {
		return config.StoredClientEndpointUpsertPlan{}, err
	}
	if err := a.reloadConfigAfterEndpointChange(); err != nil {
		return config.StoredClientEndpointUpsertPlan{}, err
	}
	return applied, nil
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
// keeping alias resolution and cosigned routing on one view of endpoints.yaml.
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
	return EndpointEntry{
		Alias:          alias,
		Role:           endpoint.Role,
		URL:            endpoint.URL,
		IdentityFile:   endpoint.IdentityFile,
		KnownHostsPath: endpoint.KnownHostsPath,
		IsDefault:      isDefault,
	}
}

// endpointUpsertLines are the render lines of an endpoint upsert: action,
// what became of the alias, and its URL.
func endpointUpsertLines(action string, plan config.StoredClientEndpointUpsertPlan) []string {
	state := "unchanged"
	switch {
	case plan.Created:
		state = "created"
	case plan.Updated:
		state = "updated"
	}
	return []string{
		fmt.Sprintf("%s %s endpoint %s (%s)", action, plan.Endpoint.Role, plan.Alias, state),
		fmt.Sprintf("  url: %s", plan.Endpoint.URL),
	}
}

func endpointDiscoverCosignersRenderLines(result *EndpointDiscoverCosignersResult) []string {
	lines := []string{
		fmt.Sprintf("Discovered cosigner inventory from %d endpoint(s): %d key(s)", len(result.Endpoints), result.CosignerKeyCount),
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
