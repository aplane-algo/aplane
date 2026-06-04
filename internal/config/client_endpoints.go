// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/aplane-algo/aplane/internal/tokenfile"
)

const (
	ClientEndpointsFile       = "endpoints.yaml"
	DefaultClientEndpointName = "primary"
)

// ClientEndpointRegistry stores client-local signer endpoint profiles loaded
// from endpoints.yaml.
type ClientEndpointRegistry struct {
	SchemaVersion int                             `yaml:"schema_version"`
	Default       string                          `yaml:"default,omitempty"`
	Endpoints     map[string]ClientEndpointConfig `yaml:"endpoints,omitempty"`
}

// ClientEndpointConfig describes one signer endpoint connection profile.
type ClientEndpointConfig struct {
	Role           string `yaml:"role,omitempty"`
	URL            string `yaml:"url" description:"Endpoint URL: self, https://..., loopback http://..., or ssh://host[:port]"`
	SignerPort     int    `yaml:"signer_port,omitempty" description:"Remote apsigner REST port for ssh:// endpoints"`
	LocalPort      int    `yaml:"local_port,omitempty" description:"Local tunnel port for ssh:// endpoints (0 = choose automatically)"`
	IdentityFile   string `yaml:"identity_file,omitempty" description:"SSH private key path for ssh:// endpoints"`
	KnownHostsPath string `yaml:"known_hosts_path,omitempty" description:"known_hosts path for ssh:// endpoints"`
	TokenFile      string `yaml:"token_file,omitempty" description:"Path to this endpoint's API token file"`
}

func GetClientEndpointsPath(dataDir string) string {
	if dataDir == "" {
		return ""
	}
	return filepath.Join(dataDir, ClientEndpointsFile)
}

// LoadClientEndpointRegistry loads endpoints.yaml and overlays the legacy
// config.yaml/aplane.token primary endpoint when possible.
func LoadClientEndpointRegistry(dataDir string, cfg Config) (ClientEndpointRegistry, error) {
	registry := legacyPrimaryEndpointRegistry(dataDir, cfg)
	path := GetClientEndpointsPath(dataDir)
	if path == "" {
		return registry, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return registry, nil
		}
		return ClientEndpointRegistry{}, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var stored ClientEndpointRegistry
	if err := unmarshalKnownFields(data, &stored); err != nil {
		return ClientEndpointRegistry{}, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	if stored.SchemaVersion == 0 {
		stored.SchemaVersion = 1
	}
	if stored.SchemaVersion != 1 {
		return ClientEndpointRegistry{}, fmt.Errorf("%s schema_version = %d, want 1", ClientEndpointsFile, stored.SchemaVersion)
	}
	if strings.TrimSpace(stored.Default) == "" {
		stored.Default = DefaultClientEndpointName
	}
	if err := ValidateClientEndpointAlias(stored.Default); err != nil {
		return ClientEndpointRegistry{}, fmt.Errorf("%s default: %w", ClientEndpointsFile, err)
	}
	if stored.Endpoints == nil {
		stored.Endpoints = map[string]ClientEndpointConfig{}
	}
	if registry.Endpoints != nil {
		if _, exists := stored.Endpoints[DefaultClientEndpointName]; !exists {
			if legacy, ok := registry.Endpoints[DefaultClientEndpointName]; ok {
				stored.Endpoints[DefaultClientEndpointName] = legacy
			}
		}
	}
	for alias, endpoint := range stored.Endpoints {
		if err := ValidateClientEndpointAlias(alias); err != nil {
			return ClientEndpointRegistry{}, fmt.Errorf("endpoint %q: %w", alias, err)
		}
		normalized, err := normalizeClientEndpointConfig(dataDir, cfg, alias, endpoint)
		if err != nil {
			return ClientEndpointRegistry{}, fmt.Errorf("endpoint %q: %w", alias, err)
		}
		stored.Endpoints[alias] = normalized
	}
	if _, ok := stored.Endpoints[stored.Default]; !ok {
		return ClientEndpointRegistry{}, fmt.Errorf("%s default endpoint %q is not defined", ClientEndpointsFile, stored.Default)
	}
	return stored, nil
}

func legacyPrimaryEndpointRegistry(dataDir string, cfg Config) ClientEndpointRegistry {
	if cfg.SSH == nil {
		return ClientEndpointRegistry{
			SchemaVersion: 1,
			Default:       DefaultClientEndpointName,
			Endpoints:     map[string]ClientEndpointConfig{},
		}
	}
	tokenFile, err := tokenfile.GetApshellTokenPathForDataDir(dataDir)
	if err != nil {
		tokenFile = filepath.Join(dataDir, tokenfile.APlaneTokenFile)
	}
	endpoint := ClientEndpointConfig{
		Role:           "signing",
		URL:            fmt.Sprintf("ssh://%s:%d", cfg.SSH.Host, cfg.SSH.Port),
		SignerPort:     cfg.SignerPort,
		IdentityFile:   cfg.SSH.IdentityFile,
		KnownHostsPath: cfg.SSH.KnownHostsPath,
		TokenFile:      tokenFile,
	}
	return ClientEndpointRegistry{
		SchemaVersion: 1,
		Default:       DefaultClientEndpointName,
		Endpoints: map[string]ClientEndpointConfig{
			DefaultClientEndpointName: endpoint,
		},
	}
}

func ValidateClientEndpointAlias(alias string) error {
	if alias == "" {
		return fmt.Errorf("alias is required")
	}
	for _, r := range alias {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-' {
			if r <= 127 {
				continue
			}
		}
		return fmt.Errorf("alias %q must contain only ASCII letters, digits, '.', '_', or '-'", alias)
	}
	return nil
}

func normalizeClientEndpointConfig(dataDir string, cfg Config, alias string, endpoint ClientEndpointConfig) (ClientEndpointConfig, error) {
	endpoint.Role = strings.ToLower(strings.TrimSpace(endpoint.Role))
	switch endpoint.Role {
	case "", "signing", "attestation", "dual":
	default:
		return endpoint, fmt.Errorf("role must be signing, attestation, or dual")
	}
	if endpoint.Role == "" {
		endpoint.Role = "dual"
	}
	endpoint.URL = strings.TrimRight(strings.TrimSpace(endpoint.URL), "/")
	if endpoint.URL == "" {
		return endpoint, fmt.Errorf("url is required")
	}
	if err := validateClientEndpointURL(alias, endpoint); err != nil {
		return endpoint, err
	}

	if endpoint.TokenFile == "" && endpoint.URL != "self" {
		if alias == DefaultClientEndpointName {
			endpoint.TokenFile = tokenfile.APlaneTokenFile
		} else {
			endpoint.TokenFile = filepath.Join("tokens", alias+".token")
		}
	}
	if endpoint.TokenFile != "" {
		endpoint.TokenFile = ResolvePath(endpoint.TokenFile, dataDir)
	}

	if strings.HasPrefix(endpoint.URL, "ssh://") {
		defaultSSH := DefaultSSHClientConfig()
		if cfg.SSH != nil {
			defaultSSH.IdentityFile = cfg.SSH.IdentityFile
			defaultSSH.KnownHostsPath = cfg.SSH.KnownHostsPath
		}
		if endpoint.SignerPort == 0 {
			if cfg.SignerPort != 0 {
				endpoint.SignerPort = cfg.SignerPort
			} else {
				endpoint.SignerPort = DefaultRESTPort
			}
		}
		if endpoint.IdentityFile == "" {
			endpoint.IdentityFile = defaultSSH.IdentityFile
		}
		if endpoint.KnownHostsPath == "" {
			endpoint.KnownHostsPath = defaultSSH.KnownHostsPath
		}
		endpoint.IdentityFile = ResolvePath(endpoint.IdentityFile, dataDir)
		endpoint.KnownHostsPath = ResolvePath(endpoint.KnownHostsPath, dataDir)
	}
	return endpoint, nil
}

func validateClientEndpointURL(alias string, endpoint ClientEndpointConfig) error {
	if endpoint.SignerPort < 0 || endpoint.SignerPort > 65535 {
		return fmt.Errorf("signer_port must be 1-65535 when set")
	}
	if endpoint.LocalPort < 0 || endpoint.LocalPort > 65535 {
		return fmt.Errorf("local_port must be 1-65535 when set")
	}
	if endpoint.URL == "self" {
		return nil
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	switch parsed.Scheme {
	case "ssh", "https", "http":
	default:
		return fmt.Errorf("unsupported url scheme %q", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("url host is required")
	}
	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("invalid url port %q", parsed.Port())
		}
	}
	if parsed.Scheme == "http" && !isLoopbackEndpointHost(parsed.Hostname()) {
		return fmt.Errorf("raw http endpoints must be loopback; use ssh:// or https:// for remote endpoint %q", alias)
	}
	return nil
}

func (r ClientEndpointRegistry) Clone() ClientEndpointRegistry {
	out := ClientEndpointRegistry{
		SchemaVersion: r.SchemaVersion,
		Default:       r.Default,
	}
	if len(r.Endpoints) > 0 {
		out.Endpoints = make(map[string]ClientEndpointConfig, len(r.Endpoints))
		for alias, endpoint := range r.Endpoints {
			out.Endpoints[alias] = endpoint
		}
	}
	return out
}

func (r ClientEndpointRegistry) DefaultEndpoint() (string, ClientEndpointConfig, bool) {
	alias := r.Default
	if alias == "" {
		alias = DefaultClientEndpointName
	}
	endpoint, ok := r.Endpoints[alias]
	return alias, endpoint, ok
}

func (r ClientEndpointRegistry) Endpoint(alias string) (ClientEndpointConfig, bool) {
	endpoint, ok := r.Endpoints[alias]
	return endpoint, ok
}

func (c Config) ClientEndpointsOrDefault(dataDir string) ClientEndpointRegistry {
	if len(c.Endpoints.Endpoints) > 0 || c.Endpoints.Default != "" {
		return c.Endpoints.Clone()
	}
	return legacyPrimaryEndpointRegistry(dataDir, c)
}

func (r ClientEndpointRegistry) ResolveAttestorEndpointConfigs(routes AttestorEndpointConfigs) (AttestorEndpointConfigs, error) {
	if len(routes) == 0 {
		return nil, nil
	}
	resolved := make(AttestorEndpointConfigs, len(routes))
	for publicKey, route := range routes {
		if route.Endpoint == "" {
			resolved[publicKey] = route
			continue
		}
		endpoint, ok := r.Endpoint(route.Endpoint)
		if !ok {
			return nil, fmt.Errorf("attestor endpoint %s references unknown endpoint alias %q", publicKey, route.Endpoint)
		}
		resolved[publicKey] = AttestorEndpointConfig{
			Endpoint:       route.Endpoint,
			URL:            endpoint.URL,
			TokenFile:      endpoint.TokenFile,
			SignerPort:     endpoint.SignerPort,
			LocalPort:      endpoint.LocalPort,
			IdentityFile:   endpoint.IdentityFile,
			KnownHostsPath: endpoint.KnownHostsPath,
		}
	}
	return resolved, nil
}
