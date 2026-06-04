// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadStoredClientEndpointRegistry loads only endpoints.yaml, without
// overlaying the legacy config.yaml ssh primary endpoint.
func LoadStoredClientEndpointRegistry(dataDir string) (ClientEndpointRegistry, bool, error) {
	path := GetClientEndpointsPath(dataDir)
	if path == "" {
		return ClientEndpointRegistry{}, false, fmt.Errorf("data directory is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return emptyStoredClientEndpointRegistry(), false, nil
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
		if existingEndpoint.URL == normalized.URL {
			return StoredClientEndpointUpsertPlan{}, fmt.Errorf("endpoint URL %q already belongs to alias %q", normalized.URL, existingAlias)
		}
	}
	if _, hasStoredPrimary := registry.Endpoints[DefaultClientEndpointName]; !hasStoredPrimary && alias != DefaultClientEndpointName {
		if legacyPrimary, ok := storedLegacyPrimaryEndpoint(dataDir); ok && legacyPrimary.URL == normalized.URL {
			return StoredClientEndpointUpsertPlan{}, fmt.Errorf("endpoint URL %q already belongs to alias %q", normalized.URL, DefaultClientEndpointName)
		}
	}
	if exists && !storedClientEndpointsEqual(existing, normalized) && !replace {
		return StoredClientEndpointUpsertPlan{}, fmt.Errorf("endpoint alias %q already exists with different settings", alias)
	}
	oldDefault := registry.Default
	registry.Endpoints[alias] = normalized
	return StoredClientEndpointUpsertPlan{
		Registry:       registry,
		Alias:          alias,
		Endpoint:       normalized,
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
	if _, ok := registry.Endpoints[alias]; !ok {
		legacy, ok := storedLegacyPrimaryEndpoint(dataDir)
		if alias != DefaultClientEndpointName || !ok {
			return ClientEndpointRegistry{}, fmt.Errorf("endpoint alias %q is not defined", alias)
		}
		registry.Endpoints[alias] = legacy
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
		if alias == DefaultClientEndpointName {
			if _, hasLegacy := storedLegacyPrimaryEndpoint(dataDir); hasLegacy {
				return ClientEndpointRegistry{}, fmt.Errorf("endpoint alias %q is defined by config.yaml ssh settings; edit config.yaml to remove it", alias)
			}
		}
		return ClientEndpointRegistry{}, fmt.Errorf("endpoint alias %q is not defined", alias)
	}
	delete(registry.Endpoints, alias)
	if err := SaveStoredClientEndpointRegistry(dataDir, registry); err != nil {
		return ClientEndpointRegistry{}, err
	}
	return registry, nil
}

// ClientAttestorEndpointAliasPlan describes config.yaml attestor route mappings
// that would be written for one endpoint alias.
type ClientAttestorEndpointAliasPlan struct {
	Alias      string
	PublicKeys []string
}

// PlanClientAttestorEndpointAliases validates attestor public-key mappings for
// one endpoint alias without touching config.yaml.
func PlanClientAttestorEndpointAliases(dataDir, alias string, publicKeys []string) (ClientAttestorEndpointAliasPlan, error) {
	if err := ValidateClientEndpointAlias(alias); err != nil {
		return ClientAttestorEndpointAliasPlan{}, err
	}
	normalizedKeys, err := normalizeAttestorPublicKeys(publicKeys)
	if err != nil {
		return ClientAttestorEndpointAliasPlan{}, err
	}
	doc, err := loadClientYAMLDocument(GetConfigPath(dataDir))
	if err != nil {
		return ClientAttestorEndpointAliasPlan{}, err
	}
	root, err := clientYAMLDocumentMapping(doc)
	if err != nil {
		return ClientAttestorEndpointAliasPlan{}, err
	}
	routes := clientYAMLMappingValue(root, "attestor_endpoints")
	if routes != nil && routes.Kind != yaml.MappingNode {
		return ClientAttestorEndpointAliasPlan{}, fmt.Errorf("attestor_endpoints must be a mapping")
	}

	for _, publicKey := range normalizedKeys {
		if routes == nil {
			continue
		}
		existing := clientYAMLMappingValue(routes, publicKey)
		if existing == nil {
			continue
		}
		existingAlias, ok, err := attestorRouteAlias(existing)
		if err != nil {
			return ClientAttestorEndpointAliasPlan{}, err
		}
		if !ok {
			return ClientAttestorEndpointAliasPlan{}, fmt.Errorf("attestor endpoint %s already has an inline route; replace is required to move it to endpoint alias %q", publicKey, alias)
		}
		if existingAlias != alias {
			return ClientAttestorEndpointAliasPlan{}, fmt.Errorf("attestor endpoint %s already maps to endpoint alias %q", publicKey, existingAlias)
		}
	}

	return ClientAttestorEndpointAliasPlan{
		Alias:      alias,
		PublicKeys: normalizedKeys,
	}, nil
}

// ApplyClientAttestorEndpointAliases writes a previously planned set of
// attestor endpoint mappings.
func ApplyClientAttestorEndpointAliases(dataDir string, plan ClientAttestorEndpointAliasPlan) error {
	if err := ValidateClientEndpointAlias(plan.Alias); err != nil {
		return err
	}
	normalizedKeys, err := normalizeAttestorPublicKeys(plan.PublicKeys)
	if err != nil {
		return err
	}
	doc, err := loadClientYAMLDocument(GetConfigPath(dataDir))
	if err != nil {
		return err
	}
	root, err := clientYAMLDocumentMapping(doc)
	if err != nil {
		return err
	}
	routes, _, err := ensureClientYAMLMappingValue(root, "attestor_endpoints")
	if err != nil {
		return err
	}
	for _, publicKey := range normalizedKeys {
		setClientYAMLMappingValue(routes, publicKey, endpointAliasNode(plan.Alias))
	}
	return writeClientYAMLDocumentAtomic(GetConfigPath(dataDir), doc, 0o600)
}

func UpsertClientAttestorEndpointAliases(dataDir, alias string, publicKeys []string) error {
	plan, err := PlanClientAttestorEndpointAliases(dataDir, alias, publicKeys)
	if err != nil {
		return err
	}
	return ApplyClientAttestorEndpointAliases(dataDir, plan)
}

func ClientAttestorEndpointMappingsByAlias(dataDir string) (map[string][]string, error) {
	doc, err := loadClientYAMLDocument(GetConfigPath(dataDir))
	if err != nil {
		return nil, err
	}
	root, err := clientYAMLDocumentMapping(doc)
	if err != nil {
		return nil, err
	}
	routes := clientYAMLMappingValue(root, "attestor_endpoints")
	if routes == nil {
		return map[string][]string{}, nil
	}
	if routes.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("attestor_endpoints must be a mapping")
	}
	out := map[string][]string{}
	for i := 0; i+1 < len(routes.Content); i += 2 {
		publicKey, err := normalizeAttestorEndpointSelector(routes.Content[i].Value)
		if err != nil {
			return nil, err
		}
		alias, ok, err := attestorRouteAlias(routes.Content[i+1])
		if err != nil {
			return nil, err
		}
		if ok {
			out[alias] = append(out[alias], publicKey)
		}
	}
	for alias := range out {
		sort.Strings(out[alias])
	}
	return out, nil
}

func emptyStoredClientEndpointRegistry() ClientEndpointRegistry {
	return ClientEndpointRegistry{
		SchemaVersion: 1,
		Endpoints:     map[string]ClientEndpointConfig{},
	}
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
	if registry.Default != "" {
		if _, ok := registry.Endpoints[registry.Default]; !ok {
			return fmt.Errorf("%s default endpoint %q is not defined", ClientEndpointsFile, registry.Default)
		}
	}
	return nil
}

func normalizeStoredClientEndpoint(alias string, endpoint ClientEndpointConfig) (ClientEndpointConfig, error) {
	if err := ValidateClientEndpointAlias(alias); err != nil {
		return ClientEndpointConfig{}, err
	}
	endpoint.Role = ""
	endpoint.URL = strings.TrimRight(strings.TrimSpace(endpoint.URL), "/")
	if err := validateClientEndpointURL(alias, endpoint); err != nil {
		return ClientEndpointConfig{}, err
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
	return a == b
}

func storedLegacyPrimaryEndpoint(dataDir string) (ClientEndpointConfig, bool) {
	cfg, err := LoadConfigFromPath(GetConfigPath(dataDir))
	if err != nil || cfg.SSH == nil {
		return ClientEndpointConfig{}, false
	}
	endpoint, err := normalizeStoredClientEndpoint(DefaultClientEndpointName, ClientEndpointConfig{
		URL:            fmt.Sprintf("ssh://%s:%d", cfg.SSH.Host, cfg.SSH.Port),
		SignerPort:     cfg.SignerPort,
		IdentityFile:   cfg.SSH.IdentityFile,
		KnownHostsPath: cfg.SSH.KnownHostsPath,
		TokenFile:      "aplane.token",
	})
	if err != nil {
		return ClientEndpointConfig{}, false
	}
	return endpoint, true
}

func normalizeAttestorPublicKeys(publicKeys []string) ([]string, error) {
	out := make([]string, 0, len(publicKeys))
	seen := map[string]struct{}{}
	for _, publicKey := range publicKeys {
		normalized, err := normalizeAttestorEndpointSelector(publicKey)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out, nil
}

func attestorRouteAlias(node *yaml.Node) (string, bool, error) {
	if node.Kind != yaml.MappingNode {
		return "", false, fmt.Errorf("attestor endpoint route must be a mapping")
	}
	aliasNode := clientYAMLMappingValue(node, "endpoint")
	if aliasNode == nil {
		return "", false, nil
	}
	if aliasNode.Kind != yaml.ScalarNode {
		return "", false, fmt.Errorf("attestor endpoint alias must be a scalar")
	}
	alias := strings.TrimSpace(aliasNode.Value)
	if err := ValidateClientEndpointAlias(alias); err != nil {
		return "", false, err
	}
	return alias, true, nil
}

func endpointAliasNode(alias string) *yaml.Node {
	return &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
		Content: []*yaml.Node{
			clientYAMLStringNode("endpoint", 0),
			clientYAMLStringNode(alias, 0),
		},
	}
}

func loadClientYAMLDocument(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return emptyClientYAMLDocument(), nil
		}
		return nil, fmt.Errorf("read YAML file %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return emptyClientYAMLDocument(), nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse YAML file %s: %w", path, err)
	}
	return &doc, nil
}

func emptyClientYAMLDocument() *yaml.Node {
	return &yaml.Node{
		Kind: yaml.DocumentNode,
		Content: []*yaml.Node{{
			Kind: yaml.MappingNode,
			Tag:  "!!map",
		}},
	}
}

func clientYAMLDocumentMapping(doc *yaml.Node) (*yaml.Node, error) {
	if doc.Kind == 0 {
		*doc = *emptyClientYAMLDocument()
	}
	if doc.Kind != yaml.DocumentNode {
		return nil, fmt.Errorf("YAML root must be a document")
	}
	if len(doc.Content) == 0 {
		doc.Content = append(doc.Content, &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"})
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("YAML root must be a mapping")
	}
	return root, nil
}

func ensureClientYAMLMappingValue(parent *yaml.Node, key string) (*yaml.Node, bool, error) {
	value := clientYAMLMappingValue(parent, key)
	if value == nil {
		node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		parent.Content = append(parent.Content, clientYAMLStringNode(key, 0), node)
		return node, true, nil
	}
	if value.Kind != yaml.MappingNode {
		return nil, false, fmt.Errorf("%s must be a mapping", key)
	}
	return value, false, nil
}

func clientYAMLMappingValue(parent *yaml.Node, key string) *yaml.Node {
	if parent == nil || parent.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			return parent.Content[i+1]
		}
	}
	return nil
}

func setClientYAMLMappingValue(parent *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			parent.Content[i+1] = value
			return
		}
	}
	parent.Content = append(parent.Content, clientYAMLStringNode(key, 0), value)
}

func clientYAMLStringNode(value string, style yaml.Style) *yaml.Node {
	return &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: value,
		Style: style,
	}
}

func writeClientYAMLDocumentAtomic(path string, doc *yaml.Node, mode os.FileMode) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		_ = enc.Close()
		return fmt.Errorf("marshal YAML: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("marshal YAML: %w", err)
	}
	return writeConfigAtomic(path, buf.Bytes(), mode)
}
