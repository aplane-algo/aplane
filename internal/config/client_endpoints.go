// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"fmt"
	"net"
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

	ClientEndpointRoleSigner = "signer"
	ClientEndpointRoleSentry = "sentry"

	ClientEndpointSchemaVersion = 2
	MaxClientSentryEndpoints    = 12
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
	// Role declares how apshell may use this endpoint. A client has at most one
	// signer endpoint and any number of sentry endpoints.
	Role           string `yaml:"role"`
	URL            string `yaml:"url" description:"Endpoint URL: self, https://..., loopback http://..., or ssh://host[:port]"`
	SignerPort     int    `yaml:"signer_port,omitempty" description:"Remote apsigner REST port for ssh:// endpoints"`
	LocalPort      int    `yaml:"local_port,omitempty" description:"Local tunnel port for ssh:// endpoints (0 = choose automatically)"`
	IdentityFile   string `yaml:"identity_file,omitempty" description:"SSH private key path for ssh:// endpoints"`
	KnownHostsPath string `yaml:"known_hosts_path,omitempty" description:"known_hosts path for ssh:// endpoints"`
	TokenFile      string `yaml:"token_file,omitempty" description:"Path to this endpoint's API token file"`
}

// ClientEndpointSSH contains runtime SSH transport settings resolved from one
// endpoint profile.
type ClientEndpointSSH struct {
	Host           string
	Port           int
	SignerPort     int
	IdentityFile   string
	KnownHostsPath string
	TokenFile      string
}

func GetClientEndpointsPath(dataDir string) string {
	if dataDir == "" {
		return ""
	}
	return filepath.Join(dataDir, ClientEndpointsFile)
}

// LoadClientEndpointRegistry loads endpoints.yaml. Client signer routing lives
// only in endpoints.yaml; config.yaml ssh settings are not a fallback.
func LoadClientEndpointRegistry(dataDir string) (ClientEndpointRegistry, error) {
	path := GetClientEndpointsPath(dataDir)
	if path == "" {
		return emptyClientEndpointRegistry(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return emptyClientEndpointRegistry(), nil
		}
		return ClientEndpointRegistry{}, fmt.Errorf("failed to read %s: %w", path, err)
	}

	stored, err := decodeClientEndpointRegistry(data)
	if err != nil {
		return ClientEndpointRegistry{}, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	if stored.Endpoints == nil {
		stored.Endpoints = map[string]ClientEndpointConfig{}
	}
	for alias, endpoint := range stored.Endpoints {
		if err := ValidateClientEndpointAlias(alias); err != nil {
			return ClientEndpointRegistry{}, fmt.Errorf("endpoint %q: %w", alias, err)
		}
		normalized, err := normalizeClientEndpointConfig(dataDir, alias, endpoint)
		if err != nil {
			return ClientEndpointRegistry{}, fmt.Errorf("endpoint %q: %w", alias, err)
		}
		stored.Endpoints[alias] = normalized
	}
	if err := normalizeClientEndpointRegistryRoleState(&stored); err != nil {
		return ClientEndpointRegistry{}, err
	}
	return stored, nil
}

func emptyClientEndpointRegistry() ClientEndpointRegistry {
	return ClientEndpointRegistry{
		SchemaVersion: ClientEndpointSchemaVersion,
		Endpoints:     map[string]ClientEndpointConfig{},
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

func ValidateClientEndpointRole(role string) error {
	switch strings.TrimSpace(role) {
	case ClientEndpointRoleSigner, ClientEndpointRoleSentry:
		return nil
	case "":
		return fmt.Errorf("role is required (expected %q or %q)", ClientEndpointRoleSigner, ClientEndpointRoleSentry)
	default:
		return fmt.Errorf("unsupported role %q (expected %q or %q)", role, ClientEndpointRoleSigner, ClientEndpointRoleSentry)
	}
}

func normalizeClientEndpointConfig(dataDir, alias string, endpoint ClientEndpointConfig) (ClientEndpointConfig, error) {
	endpoint.Role = strings.TrimSpace(endpoint.Role)
	if err := ValidateClientEndpointRole(endpoint.Role); err != nil {
		return endpoint, err
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
		if endpoint.SignerPort == 0 {
			endpoint.SignerPort = DefaultRESTPort
		}
		if endpoint.IdentityFile == "" {
			endpoint.IdentityFile = ".ssh/id_ed25519"
		}
		if endpoint.KnownHostsPath == "" {
			endpoint.KnownHostsPath = ".ssh/known_hosts"
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

// ClientEndpointSSHHostPort returns the SSH host and port for an ssh://
// endpoint. It is shared by signer-facing clients so endpoint routing does not
// depend on legacy config.yaml ssh fields.
func ClientEndpointSSHHostPort(endpoint ClientEndpointConfig) (string, int, error) {
	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return "", 0, fmt.Errorf("invalid endpoint URL: %w", err)
	}
	if parsed.Scheme != "ssh" {
		return "", 0, fmt.Errorf("endpoint %q requires ssh://", endpoint.URL)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("endpoint %q has no SSH host", endpoint.URL)
	}
	sshPort := DefaultSSHPort
	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port <= 0 || port > 65535 {
			return "", 0, fmt.Errorf("invalid SSH port %q", parsed.Port())
		}
		sshPort = port
	}
	return host, sshPort, nil
}

// ResolveClientEndpointSSH resolves the complete SSH transport for an endpoint.
func ResolveClientEndpointSSH(endpoint ClientEndpointConfig) (ClientEndpointSSH, error) {
	host, port, err := ClientEndpointSSHHostPort(endpoint)
	if err != nil {
		return ClientEndpointSSH{}, err
	}
	signerPort := endpoint.SignerPort
	if signerPort == 0 {
		signerPort = DefaultRESTPort
	}
	return ClientEndpointSSH{
		Host:           host,
		Port:           port,
		SignerPort:     signerPort,
		IdentityFile:   endpoint.IdentityFile,
		KnownHostsPath: endpoint.KnownHostsPath,
		TokenFile:      endpoint.TokenFile,
	}, nil
}

func isLoopbackEndpointHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (r ClientEndpointRegistry) Clone() ClientEndpointRegistry {
	out := ClientEndpointRegistry{
		SchemaVersion: r.SchemaVersion,
		Default:       r.Default,
	}
	if len(r.Endpoints) > 0 {
		out.Endpoints = make(map[string]ClientEndpointConfig, len(r.Endpoints))
		for alias, endpoint := range r.Endpoints {
			out.Endpoints[alias] = cloneClientEndpointConfig(endpoint)
		}
	}
	return out
}

func (r ClientEndpointRegistry) DefaultEndpoint() (string, ClientEndpointConfig, bool) {
	alias := r.Default
	if alias == "" {
		return "", ClientEndpointConfig{}, false
	}
	endpoint, ok := r.Endpoints[alias]
	return alias, cloneClientEndpointConfig(endpoint), ok
}

func (r ClientEndpointRegistry) Endpoint(alias string) (ClientEndpointConfig, bool) {
	endpoint, ok := r.Endpoints[alias]
	return cloneClientEndpointConfig(endpoint), ok
}

func cloneClientEndpointConfig(endpoint ClientEndpointConfig) ClientEndpointConfig {
	return endpoint
}

func (c Config) ClientEndpointsOrDefault() ClientEndpointRegistry {
	if len(c.Endpoints.Endpoints) > 0 || c.Endpoints.Default != "" {
		return c.Endpoints.Clone()
	}
	return emptyClientEndpointRegistry()
}

func normalizeClientEndpointRegistryRoleState(registry *ClientEndpointRegistry) error {
	registry.Default = strings.TrimSpace(registry.Default)
	if registry.Default != "" {
		if err := ValidateClientEndpointAlias(registry.Default); err != nil {
			return fmt.Errorf("%s default: %w", ClientEndpointsFile, err)
		}
	}

	signerAlias := ""
	sentryCount := 0
	for alias, endpoint := range registry.Endpoints {
		if err := ValidateClientEndpointRole(endpoint.Role); err != nil {
			return fmt.Errorf("endpoint %q: %w", alias, err)
		}
		if endpoint.Role == ClientEndpointRoleSentry {
			sentryCount++
		}
		if endpoint.Role != ClientEndpointRoleSigner {
			continue
		}
		if signerAlias != "" {
			return fmt.Errorf("%s may contain at most one %q endpoint (found %q and %q)", ClientEndpointsFile, ClientEndpointRoleSigner, signerAlias, alias)
		}
		signerAlias = alias
	}
	if sentryCount > MaxClientSentryEndpoints {
		return fmt.Errorf("%s configures %d sentry endpoints; maximum is %d; remove or consolidate endpoint profiles", ClientEndpointsFile, sentryCount, MaxClientSentryEndpoints)
	}
	if signerAlias == "" {
		if registry.Default != "" {
			return fmt.Errorf("%s default endpoint %q is set but no %q endpoint is configured", ClientEndpointsFile, registry.Default, ClientEndpointRoleSigner)
		}
		return nil
	}
	if registry.Default != "" && registry.Default != signerAlias {
		return fmt.Errorf("%s default endpoint %q must be the %q endpoint %q", ClientEndpointsFile, registry.Default, ClientEndpointRoleSigner, signerAlias)
	}
	registry.Default = signerAlias
	return nil
}
