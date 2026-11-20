// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/endpointrefs"

	"gopkg.in/yaml.v3"
)

// LoadStoredClientEndpointRegistry loads endpoints.yaml as it is stored, for
// editing: SSH paths keep what the file says.
func LoadStoredClientEndpointRegistry(dataDir string) (ClientEndpointRegistry, error) {
	path := GetClientEndpointsPath(dataDir)
	if path == "" {
		return ClientEndpointRegistry{}, fmt.Errorf("data directory is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return emptyClientEndpointRegistry(), nil
		}
		return ClientEndpointRegistry{}, fmt.Errorf("failed to read %s: %w", path, err)
	}
	registry, err := decodeClientEndpointRegistry(data)
	if err != nil {
		return ClientEndpointRegistry{}, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	if err := normalizeStoredClientEndpointRegistry(&registry); err != nil {
		return ClientEndpointRegistry{}, err
	}
	return registry, nil
}

// SaveStoredClientEndpointRegistry writes endpoints.yaml. Callers hold the
// client-data lock.
func SaveStoredClientEndpointRegistry(dataDir string, registry ClientEndpointRegistry) error {
	if err := normalizeStoredClientEndpointRegistry(&registry); err != nil {
		return err
	}
	data, err := yaml.Marshal(registry)
	if err != nil {
		return fmt.Errorf("failed to encode %s: %w", ClientEndpointsFile, err)
	}
	path := GetClientEndpointsPath(dataDir)
	if path == "" {
		return fmt.Errorf("data directory is required")
	}
	return WriteConfigAtomic(path, data)
}

// StoredClientEndpointUpsertPlan describes the endpoint registry change that
// would be applied for one endpoint alias.
type StoredClientEndpointUpsertPlan struct {
	Registry ClientEndpointRegistry
	Alias    string
	Endpoint ClientEndpointConfig
	Created  bool
	Updated  bool
	// DestinationChanged reports that Alias already existed and now names a
	// different node. A destination is the URL: the node's SSH server
	// forwards to its own REST listener, so no other field selects the
	// service.
	DestinationChanged bool
}

// PlanStoredClientEndpointUpsert validates one endpoint upsert and returns the
// registry that would be written. It does not touch endpoints.yaml.
func PlanStoredClientEndpointUpsert(dataDir, alias string, endpoint ClientEndpointConfig, replace bool) (StoredClientEndpointUpsertPlan, error) {
	registry, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		return StoredClientEndpointUpsertPlan{}, err
	}
	normalized, err := normalizeStoredClientEndpoint(alias, endpoint)
	if err != nil {
		return StoredClientEndpointUpsertPlan{}, fmt.Errorf("endpoint %q: %w", alias, err)
	}
	existing, exists := registry.Endpoints[alias]
	for existingAlias, existingEndpoint := range registry.Endpoints {
		if existingAlias == alias {
			continue
		}
		if existingEndpoint.Role == normalized.Role && existingEndpoint.URL == normalized.URL {
			return StoredClientEndpointUpsertPlan{}, fmt.Errorf("endpoint URL %q already belongs to alias %q", normalized.URL, existingAlias)
		}
	}
	if exists && !storedClientEndpointsEqual(existing, normalized) && !replace {
		return StoredClientEndpointUpsertPlan{}, fmt.Errorf("endpoint alias %q already exists with different settings", alias)
	}
	plan := StoredClientEndpointUpsertPlan{Alias: alias}
	plan.DestinationChanged = exists && existing.URL != normalized.URL
	registry.Endpoints[alias] = normalized
	if err := normalizeStoredClientEndpointRegistry(&registry); err != nil {
		return StoredClientEndpointUpsertPlan{}, err
	}
	plan.Registry = registry
	plan.Endpoint = registry.Endpoints[alias]
	plan.Created = !exists
	plan.Updated = exists && !storedClientEndpointsEqual(existing, normalized)
	return plan, nil
}

// RemoveStoredClientEndpoint removes an endpoint alias. Callers hold the
// client-data lock. Nothing else is retired with the alias: the client's
// credential is its SSH key, which no endpoint owns.
func RemoveStoredClientEndpoint(dataDir, alias string) error {
	if err := ValidateClientEndpointAlias(alias); err != nil {
		return err
	}
	registry, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		return err
	}
	if signerAlias, _, _ := registry.SignerEndpoint(); signerAlias == alias {
		return fmt.Errorf("endpoint alias %q is the signer endpoint", alias)
	}
	if _, ok := registry.Endpoints[alias]; !ok {
		return fmt.Errorf("endpoint alias %q is not defined", alias)
	}
	delete(registry.Endpoints, alias)
	return SaveStoredClientEndpointRegistry(dataDir, registry)
}

// normalizeStoredClientEndpointRegistry checks and canonicalizes a registry
// that was loaded or is about to be saved: every endpoint, then at most one
// signer endpoint and MaxClientCosignerEndpoints cosigner endpoints.
func normalizeStoredClientEndpointRegistry(registry *ClientEndpointRegistry) error {
	// A loaded registry already passed the decode's schema check; this one
	// is for a registry built in memory and handed to the save.
	if registry.SchemaVersion == 0 {
		registry.SchemaVersion = ClientEndpointSchemaVersion
	}
	if registry.SchemaVersion != ClientEndpointSchemaVersion {
		return fmt.Errorf("%s schema_version = %d, want %d", ClientEndpointsFile, registry.SchemaVersion, ClientEndpointSchemaVersion)
	}
	if registry.Endpoints == nil {
		registry.Endpoints = map[string]ClientEndpointConfig{}
	}
	for alias, endpoint := range registry.Endpoints {
		normalized, err := normalizeStoredClientEndpoint(alias, endpoint)
		if err != nil {
			return fmt.Errorf("endpoint %q: %w", alias, err)
		}
		registry.Endpoints[alias] = normalized
	}

	signerAlias := ""
	cosignerCount := 0
	for alias, endpoint := range registry.Endpoints {
		switch endpoint.Role {
		case ClientEndpointRoleCosigner:
			cosignerCount++
		case ClientEndpointRoleSigner:
			if signerAlias != "" {
				return fmt.Errorf("%s may contain at most one %q endpoint (found %q and %q)", ClientEndpointsFile, ClientEndpointRoleSigner, signerAlias, alias)
			}
			signerAlias = alias
		}
	}
	if cosignerCount > MaxClientCosignerEndpoints {
		return fmt.Errorf("%s configures %d cosigner endpoints; maximum is %d; remove or consolidate endpoint profiles", ClientEndpointsFile, cosignerCount, MaxClientCosignerEndpoints)
	}
	return nil
}

func normalizeStoredClientEndpoint(alias string, endpoint ClientEndpointConfig) (ClientEndpointConfig, error) {
	if err := ValidateClientEndpointAlias(alias); err != nil {
		return ClientEndpointConfig{}, err
	}
	endpoint.Role = strings.TrimSpace(endpoint.Role)
	if err := ValidateClientEndpointRole(endpoint.Role); err != nil {
		return ClientEndpointConfig{}, err
	}
	endpoint.URL = strings.TrimRight(strings.TrimSpace(endpoint.URL), "/")
	if _, _, err := endpointrefs.ParseURL(endpoint.URL); err != nil {
		return ClientEndpointConfig{}, err
	}
	return endpoint, nil
}

func storedClientEndpointsEqual(a, b ClientEndpointConfig) bool {
	return a.Role == b.Role &&
		a.URL == b.URL &&
		a.IdentityFile == b.IdentityFile &&
		a.KnownHostsPath == b.KnownHostsPath
}
