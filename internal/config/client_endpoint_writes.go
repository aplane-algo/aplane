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

	"github.com/aplane-algo/aplane/internal/tokenfile"
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
	registry, err := decodeClientEndpointRegistry(data)
	if err != nil {
		return ClientEndpointRegistry{}, false, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	if err := normalizeStoredClientEndpointRegistry(&registry); err != nil {
		return ClientEndpointRegistry{}, false, err
	}
	return registry, true, nil
}

// CheckSupportedClientEndpointConfig rejects legacy config.yaml endpoint
// routing. Endpoint routing must be written explicitly in endpoints.yaml;
// startup does not materialize or rewrite routes from top-level settings.
func CheckSupportedClientEndpointConfig(dataDir string) error {
	legacyField, err := clientConfigLegacyRoutingField(dataDir)
	if err != nil {
		return err
	}
	if legacyField != "" {
		return fmt.Errorf("%w: config.yaml contains legacy top-level %s signer routing; automatic endpoint-routing migration is unsupported, remove %s and write signer routing in %s", ErrUnsupportedClientEndpointConfig, legacyField, legacyField, ClientEndpointsFile)
	}
	_, _, err = LoadStoredClientEndpointRegistry(dataDir)
	return err
}

func clientConfigLegacyRoutingField(dataDir string) (string, error) {
	path := GetConfigPath(dataDir)
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read %s: %w", path, err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return "", nil
	}
	for _, field := range []string{"ssh", "signer_port"} {
		if _, ok := raw[field]; ok {
			return field, nil
		}
	}
	return "", nil
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
	return WriteConfigAtomic(path, data)
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
	// DestinationChanged reports that Alias already existed and would now
	// present its token to a different service.
	DestinationChanged bool
	// RetireTokenPath is the resolved token file that applying the plan removes
	// before the new route is written. It is set when the alias is created and
	// when its destination changes: in both cases any token already at that
	// path was issued for some other use of the name.
	RetireTokenPath string
	// RetiresExistingToken reports that RetireTokenPath currently holds a file.
	RetiresExistingToken bool
}

// StoredClientEndpointRemoval describes a completed endpoint deletion.
type StoredClientEndpointRemoval struct {
	Registry ClientEndpointRegistry
	// TokenRetired reports that the alias's token file existed and was removed.
	TokenRetired bool
	// TokenShared reports that the token file was left in place because
	// another alias uses it.
	TokenShared bool
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
	plan := StoredClientEndpointUpsertPlan{Alias: alias}
	plan.DestinationChanged = exists && ClientEndpointDestinationChanged(existing, normalized)
	// A token is only ever presented to the destination that issued it. A token
	// already at this alias's path when the alias is created was left by an
	// earlier profile of the same name, and one that predates a destination
	// change was issued by the previous destination. Neither may reach the new
	// route, so both are retired before it is published.
	if !exists || plan.DestinationChanged {
		tokenPath := resolvedClientEndpointTokenPath(dataDir, normalized)
		if otherAlias, shared := clientEndpointTokenFileUser(dataDir, registry, alias, tokenPath); shared {
			action := "changing its destination"
			if !exists {
				action = "creating it"
			}
			return StoredClientEndpointUpsertPlan{}, fmt.Errorf(
				"endpoint alias %q shares token file %s with alias %q; %s would retire a shared credential, so give %q its own token_file first",
				alias, tokenPath, otherAlias, action, alias,
			)
		}
		plan.RetireTokenPath = tokenPath
		if _, err := os.Lstat(tokenPath); err == nil {
			plan.RetiresExistingToken = true
		}
	}
	oldDefault := registry.Default
	registry.Endpoints[alias] = normalized
	if err := normalizeStoredClientEndpointRegistry(&registry); err != nil {
		return StoredClientEndpointUpsertPlan{}, err
	}
	plan.Registry = registry
	plan.Endpoint = registry.Endpoints[alias]
	plan.Created = !exists
	plan.Updated = exists && !storedClientEndpointsEqual(existing, normalized)
	plan.DefaultChanged = oldDefault != registry.Default
	return plan, nil
}

// ApplyStoredClientEndpointUpsert writes a previously planned endpoint
// registry change. Callers hold the client-data lock.
//
// A token is only ever presented to the destination that issued it. When the
// plan creates an alias or moves one to another destination, any token at its
// path is retired durably before the new route is written, so an interruption
// between the two steps leaves no route with a token it did not issue.
func ApplyStoredClientEndpointUpsert(dataDir string, plan StoredClientEndpointUpsertPlan) error {
	if plan.RetireTokenPath != "" {
		if err := tokenfile.RetireToken(plan.RetireTokenPath); err != nil {
			return fmt.Errorf("retire token for endpoint %q before publishing its route: %w", plan.Alias, err)
		}
	}
	return SaveStoredClientEndpointRegistry(dataDir, plan.Registry)
}

// ClientEndpointDestinationChanged reports whether next would present a token
// to a different service than previous. A destination is the URL: for ssh://
// endpoints the node's SSH server forwards to its own REST listener, so no
// other field selects the service.
func ClientEndpointDestinationChanged(previous, next ClientEndpointConfig) bool {
	previousURL := strings.TrimRight(strings.TrimSpace(previous.URL), "/")
	nextURL := strings.TrimRight(strings.TrimSpace(next.URL), "/")
	return previousURL != nextURL
}

// SameClientEndpointTokenFile reports whether two token_file settings name
// one file once resolved against dataDir. Different spellings of a path, and
// symlinks to it, are the same credential.
func SameClientEndpointTokenFile(dataDir string, a, b ClientEndpointConfig) bool {
	return sameClientEndpointTokenFile(resolvedClientEndpointTokenPath(dataDir, a), resolvedClientEndpointTokenPath(dataDir, b))
}

// resolvedClientEndpointTokenPath returns the absolute, cleaned token path for
// a normalized endpoint profile.
func resolvedClientEndpointTokenPath(dataDir string, endpoint ClientEndpointConfig) string {
	path := ResolvePath(endpoint.TokenFile, dataDir)
	if path == "" {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return filepath.Clean(path)
}

func sameClientEndpointTokenFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	if errA == nil && errB == nil {
		return os.SameFile(infoA, infoB)
	}
	// One or both files are absent; fall back to their resolved locations.
	return evalClientEndpointTokenDir(a) == evalClientEndpointTokenDir(b)
}

// evalClientEndpointTokenDir resolves symlinks in the directory part of a
// token path, which exists even when the token file does not.
func evalClientEndpointTokenDir(path string) string {
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return path
	}
	return filepath.Join(dir, filepath.Base(path))
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

// DeleteStoredClientEndpoint removes an endpoint alias and retires its token.
func DeleteStoredClientEndpoint(dataDir, alias string) (ClientEndpointRegistry, error) {
	removal, err := RemoveStoredClientEndpoint(dataDir, alias)
	return removal.Registry, err
}

// RemoveStoredClientEndpoint removes an endpoint alias. Callers hold the
// client-data lock.
//
// A token's lifetime ends with its alias: the token file is retired before the
// route is removed, so a later profile of the same name cannot inherit it and
// an interruption leaves the route without a token rather than an orphaned
// token without a route. A token file that another alias also uses is left in
// place.
func RemoveStoredClientEndpoint(dataDir, alias string) (StoredClientEndpointRemoval, error) {
	if err := ValidateClientEndpointAlias(alias); err != nil {
		return StoredClientEndpointRemoval{}, err
	}
	registry, _, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		return StoredClientEndpointRemoval{}, err
	}
	if registry.Default == alias {
		return StoredClientEndpointRemoval{}, fmt.Errorf("endpoint alias %q is the default endpoint", alias)
	}
	endpoint, ok := registry.Endpoints[alias]
	if !ok {
		return StoredClientEndpointRemoval{}, fmt.Errorf("endpoint alias %q is not defined", alias)
	}
	var removal StoredClientEndpointRemoval
	tokenPath := resolvedClientEndpointTokenPath(dataDir, endpoint)
	if _, shared := clientEndpointTokenFileUser(dataDir, registry, alias, tokenPath); shared {
		removal.TokenShared = true
	} else {
		if _, statErr := os.Lstat(tokenPath); statErr == nil {
			removal.TokenRetired = true
		}
		if err := tokenfile.RetireToken(tokenPath); err != nil {
			return StoredClientEndpointRemoval{}, fmt.Errorf("retire token for endpoint %q before removing it: %w", alias, err)
		}
	}
	delete(registry.Endpoints, alias)
	if err := SaveStoredClientEndpointRegistry(dataDir, registry); err != nil {
		return StoredClientEndpointRemoval{}, err
	}
	removal.Registry = registry
	return removal, nil
}

// clientEndpointTokenFileUser returns another alias whose token file resolves
// to tokenPath, if any.
func clientEndpointTokenFileUser(dataDir string, registry ClientEndpointRegistry, alias, tokenPath string) (string, bool) {
	others := make([]string, 0, len(registry.Endpoints))
	for otherAlias, other := range registry.Endpoints {
		if otherAlias != alias && sameClientEndpointTokenFile(tokenPath, resolvedClientEndpointTokenPath(dataDir, other)) {
			others = append(others, otherAlias)
		}
	}
	if len(others) == 0 {
		return "", false
	}
	sort.Strings(others)
	return others[0], true
}

func normalizeStoredClientEndpointRegistry(registry *ClientEndpointRegistry) error {
	if registry.SchemaVersion == 0 {
		registry.SchemaVersion = ClientEndpointSchemaVersion
	}
	if registry.SchemaVersion != ClientEndpointSchemaVersion {
		return fmt.Errorf("%s schema_version = %d, want %d", ClientEndpointsFile, registry.SchemaVersion, ClientEndpointSchemaVersion)
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
	if endpoint.TokenFile == "" {
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
		a.IdentityFile != b.IdentityFile ||
		a.KnownHostsPath != b.KnownHostsPath ||
		a.TokenFile != b.TokenFile {
		return false
	}
	return true
}
