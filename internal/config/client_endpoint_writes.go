// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var ErrUnsupportedClientEndpointConfig = errors.New("unsupported apclient endpoint config")

// LoadStoredClientEndpointRegistry loads only endpoints.yaml.
func LoadStoredClientEndpointRegistry(dataDir string) (ClientEndpointRegistry, bool, error) {
	path := GetClientEndpointsPath(dataDir)
	if path == "" {
		return ClientEndpointRegistry{}, false, fmt.Errorf("data directory is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return emptyClientEndpointRegistry(), false, nil
		}
		return ClientEndpointRegistry{}, false, fmt.Errorf("failed to read %s: %w", path, err)
	}
	var registry ClientEndpointRegistry
	if err := unmarshalKnownFields(data, &registry); err != nil {
		return ClientEndpointRegistry{}, false, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	if err := normalizeStoredClientEndpointRegistry(&registry); err != nil {
		return ClientEndpointRegistry{}, false, err
	}
	return registry, true, nil
}

// CheckSupportedClientEndpointConfig rejects pre-endpoint client config. This
// release is new-install-only and does not convert config.yaml ssh routing.
func CheckSupportedClientEndpointConfig(dataDir string) error {
	hasSSH, err := clientConfigHasTopLevelSSH(dataDir)
	if err != nil {
		return err
	}
	if hasSSH {
		return fmt.Errorf("%w: config.yaml contains top-level ssh signer settings; this release is new-install-only, create a fresh apclient data directory or write signer routing in %s", ErrUnsupportedClientEndpointConfig, ClientEndpointsFile)
	}
	_, _, err = LoadStoredClientEndpointRegistry(dataDir)
	return err
}

func clientConfigHasTopLevelSSH(dataDir string) (bool, error) {
	path := GetConfigPath(dataDir)
	if path == "" {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to read %s: %w", path, err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return false, nil
	}
	_, ok := raw["ssh"]
	return ok, nil
}

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
	return writeConfigAtomic(path, data, 0o600)
}

// StoredClientEndpointUpsertPlan describes the endpoint registry change that
// would be applied for one endpoint alias.
type StoredClientEndpointUpsertPlan struct {
	Registry       ClientEndpointRegistry
	Alias          string
	Endpoint       ClientEndpointConfig
	Created        bool
	Updated        bool
	DefaultChanged bool
}

// PlanStoredClientEndpointUpsert validates one endpoint upsert and returns the
// registry that would be written. It does not touch endpoints.yaml.
func PlanStoredClientEndpointUpsert(dataDir, alias string, endpoint ClientEndpointConfig, replace bool) (StoredClientEndpointUpsertPlan, error) {
	registry, _, err := LoadStoredClientEndpointRegistry(dataDir)
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
	oldDefault := registry.Default
	registry.Endpoints[alias] = normalized
	if err := normalizeStoredClientEndpointRegistry(&registry); err != nil {
		return StoredClientEndpointUpsertPlan{}, err
	}
	return StoredClientEndpointUpsertPlan{
		Registry:       registry,
		Alias:          alias,
		Endpoint:       registry.Endpoints[alias],
		Created:        !exists,
		Updated:        exists && !storedClientEndpointsEqual(existing, normalized),
		DefaultChanged: oldDefault != registry.Default,
	}, nil
}

// ApplyStoredClientEndpointUpsert writes a previously planned endpoint
// registry change.
func ApplyStoredClientEndpointUpsert(dataDir string, plan StoredClientEndpointUpsertPlan) error {
	return SaveStoredClientEndpointRegistry(dataDir, plan.Registry)
}

// UpsertStoredClientEndpoint adds one endpoint profile to endpoints.yaml. When
// replace is false, conflicting existing aliases are rejected.
func UpsertStoredClientEndpoint(dataDir, alias string, endpoint ClientEndpointConfig, replace bool) (ClientEndpointRegistry, error) {
	plan, err := PlanStoredClientEndpointUpsert(dataDir, alias, endpoint, replace)
	if err != nil {
		return ClientEndpointRegistry{}, err
	}
	if err := ApplyStoredClientEndpointUpsert(dataDir, plan); err != nil {
		return ClientEndpointRegistry{}, err
	}
	return plan.Registry, nil
}

func SetStoredClientEndpointDefault(dataDir, alias string) (ClientEndpointRegistry, error) {
	if err := ValidateClientEndpointAlias(alias); err != nil {
		return ClientEndpointRegistry{}, err
	}
	registry, _, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		return ClientEndpointRegistry{}, err
	}
	endpoint, ok := registry.Endpoints[alias]
	if !ok {
		return ClientEndpointRegistry{}, fmt.Errorf("endpoint alias %q is not defined", alias)
	}
	if endpoint.Role != ClientEndpointRoleSigner {
		return ClientEndpointRegistry{}, fmt.Errorf("endpoint alias %q has role %q; default endpoint must have role %q", alias, endpoint.Role, ClientEndpointRoleSigner)
	}
	registry.Default = alias
	if err := SaveStoredClientEndpointRegistry(dataDir, registry); err != nil {
		return ClientEndpointRegistry{}, err
	}
	return registry, nil
}

func DeleteStoredClientEndpoint(dataDir, alias string) (ClientEndpointRegistry, error) {
	if err := ValidateClientEndpointAlias(alias); err != nil {
		return ClientEndpointRegistry{}, err
	}
	registry, _, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		return ClientEndpointRegistry{}, err
	}
	if registry.Default == alias {
		return ClientEndpointRegistry{}, fmt.Errorf("endpoint alias %q is the default endpoint", alias)
	}
	if _, ok := registry.Endpoints[alias]; !ok {
		return ClientEndpointRegistry{}, fmt.Errorf("endpoint alias %q is not defined", alias)
	}
	delete(registry.Endpoints, alias)
	if err := SaveStoredClientEndpointRegistry(dataDir, registry); err != nil {
		return ClientEndpointRegistry{}, err
	}
	return registry, nil
}

// ClientEndpointPublishedAttestorRebuildPlan describes an endpoints.yaml
// rewrite that refreshes endpoint-published attestor inventory.
type ClientEndpointPublishedAttestorRebuildPlan struct {
	Registry               ClientEndpointRegistry
	PublicKeyCount         int
	PreviousPublishedCount int
}

// PlanStoredClientEndpointPublishedAttestorRebuild validates and plans a full
// refresh of endpoint-local published_attestors inventory in endpoints.yaml.
func PlanStoredClientEndpointPublishedAttestorRebuild(dataDir string, publications map[string]map[string]ClientEndpointPublishedAttestor) (ClientEndpointPublishedAttestorRebuildPlan, error) {
	registry, _, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		return ClientEndpointPublishedAttestorRebuildPlan{}, err
	}
	previousCount := 0
	for alias, endpoint := range registry.Endpoints {
		if endpoint.Role != ClientEndpointRoleAttestor {
			continue
		}
		previousCount += len(endpoint.PublishedAttestors)
		endpoint.PublishedAttestors = nil
		registry.Endpoints[alias] = endpoint
	}

	aliases := make([]string, 0, len(publications))
	for alias := range publications {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)

	keyToAlias := map[string]string{}
	publicKeyCount := 0
	for _, alias := range aliases {
		if err := ValidateClientEndpointAlias(alias); err != nil {
			return ClientEndpointPublishedAttestorRebuildPlan{}, err
		}
		normalizedPublished, err := normalizeClientEndpointPublishedAttestors(publications[alias])
		if err != nil {
			return ClientEndpointPublishedAttestorRebuildPlan{}, fmt.Errorf("endpoint %q: %w", alias, err)
		}

		endpoint, ok := registry.Endpoints[alias]
		if !ok {
			if len(normalizedPublished) == 0 {
				continue
			}
			return ClientEndpointPublishedAttestorRebuildPlan{}, fmt.Errorf("endpoint alias %q is not defined", alias)
		}
		if endpoint.Role != ClientEndpointRoleAttestor {
			return ClientEndpointPublishedAttestorRebuildPlan{}, fmt.Errorf("endpoint alias %q has role %q; published_attestors require role %q", alias, endpoint.Role, ClientEndpointRoleAttestor)
		}

		for publicKey := range normalizedPublished {
			if existingAlias, exists := keyToAlias[publicKey]; exists && existingAlias != alias {
				return ClientEndpointPublishedAttestorRebuildPlan{}, fmt.Errorf("attestor public key %s advertised by both endpoint aliases %q and %q", publicKey, existingAlias, alias)
			}
			keyToAlias[publicKey] = alias
		}
		if len(normalizedPublished) > 0 {
			publicKeyCount += len(normalizedPublished)
			endpoint.PublishedAttestors = normalizedPublished
			registry.Endpoints[alias] = endpoint
		} else if _, exists := registry.Endpoints[alias]; exists {
			endpoint.PublishedAttestors = nil
			registry.Endpoints[alias] = endpoint
		}
	}

	if err := normalizeStoredClientEndpointRegistry(&registry); err != nil {
		return ClientEndpointPublishedAttestorRebuildPlan{}, err
	}
	return ClientEndpointPublishedAttestorRebuildPlan{
		Registry:               registry,
		PublicKeyCount:         publicKeyCount,
		PreviousPublishedCount: previousCount,
	}, nil
}

// ApplyStoredClientEndpointPublishedAttestorRebuild writes a previously
// planned published_attestors refresh.
func ApplyStoredClientEndpointPublishedAttestorRebuild(dataDir string, plan ClientEndpointPublishedAttestorRebuildPlan) error {
	return SaveStoredClientEndpointRegistry(dataDir, plan.Registry)
}

func RebuildStoredClientEndpointPublishedAttestors(dataDir string, publications map[string]map[string]ClientEndpointPublishedAttestor) (ClientEndpointPublishedAttestorRebuildPlan, error) {
	plan, err := PlanStoredClientEndpointPublishedAttestorRebuild(dataDir, publications)
	if err != nil {
		return ClientEndpointPublishedAttestorRebuildPlan{}, err
	}
	if err := ApplyStoredClientEndpointPublishedAttestorRebuild(dataDir, plan); err != nil {
		return ClientEndpointPublishedAttestorRebuildPlan{}, err
	}
	return plan, nil
}

func normalizeStoredClientEndpointRegistry(registry *ClientEndpointRegistry) error {
	if registry.SchemaVersion == 0 {
		registry.SchemaVersion = 1
	}
	if registry.SchemaVersion != 1 {
		return fmt.Errorf("%s schema_version = %d, want 1", ClientEndpointsFile, registry.SchemaVersion)
	}
	registry.Default = strings.TrimSpace(registry.Default)
	if registry.Default != "" {
		if err := ValidateClientEndpointAlias(registry.Default); err != nil {
			return fmt.Errorf("%s default: %w", ClientEndpointsFile, err)
		}
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
	if err := normalizeClientEndpointRegistryRoleState(registry); err != nil {
		return err
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
	if err := validateClientEndpointURL(alias, endpoint); err != nil {
		return ClientEndpointConfig{}, err
	}
	published, err := normalizeClientEndpointPublishedAttestors(endpoint.PublishedAttestors)
	if err != nil {
		return ClientEndpointConfig{}, err
	}
	endpoint.PublishedAttestors = published
	if endpoint.Role != ClientEndpointRoleAttestor && len(endpoint.PublishedAttestors) > 0 {
		return ClientEndpointConfig{}, fmt.Errorf("published_attestors are only valid on %q endpoints", ClientEndpointRoleAttestor)
	}
	if endpoint.TokenFile == "" && endpoint.URL != "self" {
		if alias == DefaultClientEndpointName {
			endpoint.TokenFile = "aplane.token"
		} else {
			endpoint.TokenFile = filepath.Join("tokens", alias+".token")
		}
	}
	return endpoint, nil
}

func storedClientEndpointsEqual(a, b ClientEndpointConfig) bool {
	if a.Role != b.Role ||
		a.URL != b.URL ||
		a.SignerPort != b.SignerPort ||
		a.LocalPort != b.LocalPort ||
		a.IdentityFile != b.IdentityFile ||
		a.KnownHostsPath != b.KnownHostsPath ||
		a.TokenFile != b.TokenFile {
		return false
	}
	if len(a.PublishedAttestors) != len(b.PublishedAttestors) {
		return false
	}
	for publicKey, aPublished := range a.PublishedAttestors {
		if bPublished, ok := b.PublishedAttestors[publicKey]; !ok || bPublished != aPublished {
			return false
		}
	}
	return true
}
