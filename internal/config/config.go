// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultSignerStatusPollInterval       = 10 * time.Second
	DefaultSignerStatusPollIntervalString = "10s"
	MinSignerStatusPollInterval           = 1 * time.Second
)

// SSHClientConfig holds SSH tunnel configuration for connecting to signer.
// Required for all client connections (localhost or remote).
type SSHClientConfig struct {
	Host           string `yaml:"host" description:"Signer host to SSH to (required)"`
	Port           int    `yaml:"port" description:"SSH port" default:"1127"`
	IdentityFile   string `yaml:"identity_file" description:"SSH private key path (relative to data dir)" default:".ssh/id_ed25519"`
	KnownHostsPath string `yaml:"known_hosts_path" description:"Known hosts file path (relative to data dir)" default:".ssh/known_hosts"`
}

// AttestorEndpointConfig maps an embedded attestor public key to the signer
// endpoint that can produce attestor-role component signatures for that key.
type AttestorEndpointConfig struct {
	URL            string `yaml:"url" description:"Attestor endpoint URL: self, https://..., loopback http://..., or ssh://host[:port]"`
	TokenFile      string `yaml:"token_file,omitempty" description:"Path to the attestor endpoint API token file"`
	SignerPort     int    `yaml:"signer_port,omitempty" description:"Remote apsigner REST port for ssh:// attestor endpoints"`
	LocalPort      int    `yaml:"local_port,omitempty" description:"Local tunnel port for ssh:// attestor endpoints (0 = choose automatically)"`
	IdentityFile   string `yaml:"identity_file,omitempty" description:"SSH private key path for ssh:// attestor endpoints"`
	KnownHostsPath string `yaml:"known_hosts_path,omitempty" description:"known_hosts path for ssh:// attestor endpoints"`
}

// AttestorEndpointConfigs is keyed by canonical lower-case Ed25519 attestor
// public-key hex.
type AttestorEndpointConfigs map[string]AttestorEndpointConfig

// Config holds apshell configuration settings
type Config struct {
	Network         string   `yaml:"network" description:"Default network context token" default:"testnet"`
	NetworksAllowed []string `yaml:"networks_allowed" description:"Restrict allowed networks (empty = all)" default:"[]"`
	SignerPort      int      `yaml:"signer_port" description:"Local REST port for apsigner" default:"11270"`
	Theme           string   `yaml:"theme" description:"Local client UI theme: auto, dark, or light (auto detects terminal)" default:"auto"`
	// SignerStatusPollInterval controls how often interactive apshell sessions
	// poll /status for keyset revision changes. "0" disables background polling.
	SignerStatusPollInterval string `yaml:"signer_status_poll_interval" description:"Background /status polling interval for signer keyset refresh (0=disabled)" default:"10s"`

	// SSH tunnel config (required for connecting to signer)
	SSH *SSHClientConfig `yaml:"ssh" description:"SSH tunnel settings (required for signer connection)"`

	// AttestorEndpoints maps attested-account embedded attestor public keys to
	// signer endpoints for attestor-role component signing.
	AttestorEndpoints AttestorEndpointConfigs `yaml:"attestor_endpoints,omitempty" description:"Attestor endpoint routing by embedded attestor public-key hex"`

	// Grouped network settings. This is the canonical on-disk network config.
	Networks ClientNetworkConfigs `yaml:"networks" description:"Grouped settings per network context token"`

	// Algod is a derived runtime index built from Networks.
	Algod AlgodConfig `yaml:"-"`
}

// DefaultConfig returns the default configuration for runtime use.
// Algod URLs are empty - user must explicitly configure them.
// SSH is nil by default (must be configured in config.yaml).
func DefaultConfig() Config {
	return Config{
		Network:                  "testnet",
		NetworksAllowed:          []string{}, // Empty = all networks allowed
		SignerPort:               DefaultRESTPort,
		Theme:                    "auto",
		SignerStatusPollInterval: DefaultSignerStatusPollIntervalString,
		SSH:                      nil, // Must be set in config.yaml
		// Algod URLs intentionally empty - must be explicitly configured
	}
}

// DefaultSSHClientConfig returns default SSH settings (used when ssh block exists but fields are missing)
func DefaultSSHClientConfig() SSHClientConfig {
	return SSHClientConfig{
		Port:           DefaultSSHPort,
		IdentityFile:   ".ssh/id_ed25519",  // Relative to data directory
		KnownHostsPath: ".ssh/known_hosts", // Relative to data directory
	}
}

// GetClientDataDir returns the data directory for aplane clients.
// Resolution order: -d flag > APCLIENT_DATA env var.
// Returns "" when neither is set; callers must treat empty as an error.
func GetClientDataDir(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("APCLIENT_DATA")
}

// GetConfigPath returns the path to the config file in the data directory.
// Returns empty string if dataDir is empty.
func GetConfigPath(dataDir string) string {
	if dataDir == "" {
		return ""
	}
	return filepath.Join(dataDir, "config.yaml")
}

// LoadConfig loads configuration from config.yaml in the data directory.
// The dataDir parameter is required - use GetClientDataDir() to resolve it.
// If dataDir is empty or file doesn't exist, returns default config.
// Relative SSH paths are resolved relative to the data directory.
// Returns an error if the config is invalid (e.g., network not in networks_allowed)
func LoadConfig(dataDir string) (Config, error) {
	config, err := LoadConfigFromPath(GetConfigPath(dataDir))
	if err != nil {
		return config, err
	}

	// Resolve relative SSH paths to absolute paths based on dataDir
	if config.SSH != nil {
		config.SSH.IdentityFile = ResolvePath(config.SSH.IdentityFile, dataDir)
		config.SSH.KnownHostsPath = ResolvePath(config.SSH.KnownHostsPath, dataDir)
	}
	config.resolveAttestorEndpointPaths(dataDir)

	return config, nil
}

// LoadConfigFromPath loads configuration from the specified path.
// If path is empty, returns default config.
// If the file doesn't exist, returns default config.
func LoadConfigFromPath(path string) (Config, error) {
	if path == "" {
		return DefaultConfig(), nil
	}

	// If config file doesn't exist, return defaults
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		// Other errors - log but return defaults
		_, _ = fmt.Fprintf(os.Stderr, "Warning: Failed to read config file: %v\n", err)
		return DefaultConfig(), nil
	}

	// Start with defaults, then overlay config file values
	config := DefaultConfig()
	if err := unmarshalKnownFields(data, &config); err != nil {
		return Config{}, fmt.Errorf("failed to parse config file: %w", err)
	}
	if config.Algod, err = mergeClientNetworkAlgodConfig(nil, config.Networks); err != nil {
		return Config{}, fmt.Errorf("invalid network in networks config: %w", err)
	}

	// Validate network is a filesystem-safe context token.
	if err := ValidateNetworkID(config.Network); err != nil {
		return Config{}, fmt.Errorf("invalid network in config: %w", err)
	}

	// Validate networks_allowed entries are valid context tokens.
	for _, n := range config.NetworksAllowed {
		if err := ValidateNetworkID(n); err != nil {
			return Config{}, fmt.Errorf("invalid network in networks_allowed: %w", err)
		}
	}

	// Validate network is in networks_allowed (if networks_allowed is set)
	if len(config.NetworksAllowed) > 0 && !config.IsNetworkAllowed(config.Network) {
		return Config{}, fmt.Errorf("network '%s' is not in networks_allowed %v", config.Network, config.NetworksAllowed)
	}
	if _, err := ParseSignerStatusPollInterval(config.SignerStatusPollInterval); err != nil {
		return Config{}, fmt.Errorf("invalid signer_status_poll_interval in config: %w", err)
	}

	// Validate algod map keys are valid context tokens.
	for network := range config.Algod {
		if err := ValidateNetworkID(network); err != nil {
			return Config{}, fmt.Errorf("invalid network in algod config: %w", err)
		}
	}

	// Fill in defaults for missing values
	defaults := DefaultConfig()
	if config.SignerPort == 0 {
		config.SignerPort = defaults.SignerPort
	}
	if config.Theme == "" {
		config.Theme = defaults.Theme
	}
	if config.SignerStatusPollInterval == "" {
		config.SignerStatusPollInterval = defaults.SignerStatusPollInterval
	}

	// Fill in SSH defaults if SSH block is present
	if config.SSH != nil {
		sshDefaults := DefaultSSHClientConfig()
		if config.SSH.Host == "" {
			return Config{}, fmt.Errorf("ssh.host is required when ssh block is present")
		}
		if config.SSH.Port == 0 {
			config.SSH.Port = sshDefaults.Port
		}
		if config.SSH.IdentityFile == "" {
			config.SSH.IdentityFile = sshDefaults.IdentityFile
		}
		if config.SSH.KnownHostsPath == "" {
			config.SSH.KnownHostsPath = sshDefaults.KnownHostsPath
		}
	}
	if err := config.validateAndCanonicalizeAttestorEndpoints(); err != nil {
		return Config{}, fmt.Errorf("invalid attestor_endpoints in config: %w", err)
	}

	return config, nil
}

// Clone returns a shallow copy of endpoint configs.
func (c AttestorEndpointConfigs) Clone() AttestorEndpointConfigs {
	if len(c) == 0 {
		return nil
	}
	clone := make(AttestorEndpointConfigs, len(c))
	for k, v := range c {
		clone[k] = v
	}
	return clone
}

func (c *Config) validateAndCanonicalizeAttestorEndpoints() error {
	if len(c.AttestorEndpoints) == 0 {
		return nil
	}
	canonical := make(AttestorEndpointConfigs, len(c.AttestorEndpoints))
	for selector, endpoint := range c.AttestorEndpoints {
		normalized, err := normalizeAttestorEndpointSelector(selector)
		if err != nil {
			return fmt.Errorf("%q: %w", selector, err)
		}
		if _, exists := canonical[normalized]; exists {
			return fmt.Errorf("duplicate endpoint for attestor public key %s", normalized)
		}
		if err := validateAttestorEndpointConfig(normalized, endpoint); err != nil {
			return err
		}
		if strings.HasPrefix(endpoint.URL, "ssh://") && endpoint.SignerPort == 0 {
			endpoint.SignerPort = c.SignerPort
		}
		canonical[normalized] = endpoint
	}
	c.AttestorEndpoints = canonical
	return nil
}

func normalizeAttestorEndpointSelector(selector string) (string, error) {
	raw := strings.TrimSpace(selector)
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X")
	if raw == "" {
		return "", fmt.Errorf("attestor public key is required")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("attestor public key must be hex: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return "", fmt.Errorf("attestor public key length %d invalid (expected %d bytes)", len(decoded), ed25519.PublicKeySize)
	}
	return hex.EncodeToString(decoded), nil
}

func validateAttestorEndpointConfig(selector string, endpoint AttestorEndpointConfig) error {
	if strings.TrimSpace(endpoint.URL) == "" {
		return fmt.Errorf("attestor endpoint %s: url is required", selector)
	}
	if endpoint.SignerPort < 0 || endpoint.SignerPort > 65535 {
		return fmt.Errorf("attestor endpoint %s: signer_port must be 1-65535 when set", selector)
	}
	if endpoint.LocalPort < 0 || endpoint.LocalPort > 65535 {
		return fmt.Errorf("attestor endpoint %s: local_port must be 1-65535 when set", selector)
	}
	if endpoint.URL == "self" {
		return nil
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return fmt.Errorf("attestor endpoint %s: invalid url: %w", selector, err)
	}
	switch parsed.Scheme {
	case "ssh", "https", "http":
	default:
		return fmt.Errorf("attestor endpoint %s: unsupported url scheme %q", selector, parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("attestor endpoint %s: url host is required", selector)
	}
	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("attestor endpoint %s: invalid url port %q", selector, parsed.Port())
		}
	}
	if parsed.Scheme == "http" && !isLoopbackEndpointHost(parsed.Hostname()) {
		return fmt.Errorf("attestor endpoint %s: raw http endpoints must be loopback; use ssh:// or https:// for remote attestors", selector)
	}
	if strings.TrimSpace(endpoint.TokenFile) == "" {
		return fmt.Errorf("attestor endpoint %s: token_file is required for non-self endpoints", selector)
	}
	return nil
}

func isLoopbackEndpointHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Config) resolveAttestorEndpointPaths(dataDir string) {
	if len(c.AttestorEndpoints) == 0 {
		return
	}
	defaultSSH := DefaultSSHClientConfig()
	globalIdentityFile := defaultSSH.IdentityFile
	globalKnownHostsPath := defaultSSH.KnownHostsPath
	if c.SSH != nil {
		globalIdentityFile = c.SSH.IdentityFile
		globalKnownHostsPath = c.SSH.KnownHostsPath
	}
	for selector, endpoint := range c.AttestorEndpoints {
		if endpoint.TokenFile != "" {
			endpoint.TokenFile = ResolvePath(endpoint.TokenFile, dataDir)
		}
		if strings.HasPrefix(endpoint.URL, "ssh://") {
			if endpoint.IdentityFile == "" {
				endpoint.IdentityFile = globalIdentityFile
			}
			if endpoint.KnownHostsPath == "" {
				endpoint.KnownHostsPath = globalKnownHostsPath
			}
			endpoint.IdentityFile = ResolvePath(endpoint.IdentityFile, dataDir)
			endpoint.KnownHostsPath = ResolvePath(endpoint.KnownHostsPath, dataDir)
		}
		c.AttestorEndpoints[selector] = endpoint
	}
}

// ParseSignerStatusPollInterval parses the apshell background /status polling interval.
// It accepts Go duration strings such as "10s" or "1m"; "0" disables polling.
func ParseSignerStatusPollInterval(intervalStr string) (time.Duration, error) {
	if intervalStr == "" {
		return DefaultSignerStatusPollInterval, nil
	}
	if intervalStr == "0" {
		return 0, nil
	}
	duration, err := time.ParseDuration(intervalStr)
	if err != nil {
		return 0, fmt.Errorf("invalid duration format: %w", err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("duration must be positive or \"0\" to disable polling")
	}
	if duration < MinSignerStatusPollInterval {
		return 0, fmt.Errorf("duration %q below minimum %s", intervalStr, MinSignerStatusPollInterval)
	}
	return duration, nil
}

// SignerStatusPollIntervalDuration returns the parsed background /status poll interval.
func (c Config) SignerStatusPollIntervalDuration() time.Duration {
	duration, err := ParseSignerStatusPollInterval(c.SignerStatusPollInterval)
	if err != nil {
		return DefaultSignerStatusPollInterval
	}
	return duration
}

// IsNetworkAllowed checks if switching to the given network is allowed
func (c *Config) IsNetworkAllowed(network string) bool {
	// If networks_allowed is empty, all networks are allowed
	if len(c.NetworksAllowed) == 0 {
		return true
	}
	for _, n := range c.NetworksAllowed {
		if n == network {
			return true
		}
	}
	return false
}

// GetAlgodConfig returns the algod settings for the specified network.
// Returns the configured values without fallback defaults - caller should
// check if Server is empty and handle accordingly.
func (c *Config) GetAlgodConfig(network string) (*AlgodNetworkConfig, error) {
	return c.Algod.GetNetwork(network)
}

// GetParsedConnection returns a ParsedConnection from the config.
// Returns nil if no SSH is configured.
func (c *Config) GetParsedConnection() *ParsedConnection {
	if c.SSH == nil {
		return nil // SSH not configured
	}
	return &ParsedConnection{
		Host:       c.SSH.Host,
		SSHPort:    c.SSH.Port,
		SignerPort: c.SignerPort,
	}
}

// UseSSH returns true if SSH tunnel is configured
func (c *Config) UseSSH() bool {
	return c.SSH != nil
}

// ParsedConnection represents a parsed connection string
type ParsedConnection struct {
	Host       string // The remote host
	SSHPort    int    // SSH port (default 1127)
	SignerPort int    // Remote signer REST port (default 11270)
}

// ParseConnectionString parses a connection string in the format:
//
//	<host> [--ssh-port <port>] [--signer-port <port>]
//
// For localhost connections (SSH tunnel to localhost):
//
//	localhost [--signer-port <port>]
//
// Defaults are taken from config.yaml if available, otherwise: ssh-port=1127, signer-port=11270
// Returns the parsed connection or an error if invalid
func ParseConnectionString(connStr string) (*ParsedConnection, error) {
	if connStr == "" {
		return nil, fmt.Errorf("empty connection string")
	}

	parts := strings.Fields(connStr) // Split on whitespace
	if len(parts) < 1 {
		return nil, fmt.Errorf("invalid connection format: expected '<host> [--ssh-port <port>] [--signer-port <port>]'")
	}

	// Use hardcoded defaults - the caller should have loaded config separately
	result := &ParsedConnection{
		Host:       parts[0],
		SSHPort:    DefaultSSHPort,
		SignerPort: DefaultRESTPort,
	}

	// Parse optional flags
	for i := 1; i < len(parts); i++ {
		switch parts[i] {
		case "--ssh-port":
			if i+1 >= len(parts) {
				return nil, fmt.Errorf("--ssh-port requires a value")
			}
			port, err := strconv.Atoi(parts[i+1])
			if err != nil || port <= 0 || port > 65535 {
				return nil, fmt.Errorf("invalid SSH port: %s", parts[i+1])
			}
			result.SSHPort = port
			i++ // Skip the value
		case "--signer-port":
			if i+1 >= len(parts) {
				return nil, fmt.Errorf("--signer-port requires a value")
			}
			port, err := strconv.Atoi(parts[i+1])
			if err != nil || port <= 0 || port > 65535 {
				return nil, fmt.Errorf("invalid signer port: %s", parts[i+1])
			}
			result.SignerPort = port
			i++ // Skip the value
		default:
			return nil, fmt.Errorf("unknown option: %s", parts[i])
		}
	}

	return result, nil
}

// DisplayConfig prints the current configuration
func DisplayConfig(dataDir string) {
	config, err := LoadConfig(dataDir)
	configPath := GetConfigPath(dataDir)

	fmt.Println("Current Configuration:")
	fmt.Println("=====================")
	fmt.Printf("Data dir:    %s\n", dataDir)
	fmt.Printf("Config file: %s\n", configPath)
	if err != nil {
		fmt.Printf("Error:       %v\n", err)
		fmt.Println()
		return
	}
	fmt.Printf("Network:     %s\n", config.Network)
	if len(config.NetworksAllowed) > 0 {
		fmt.Printf("Allowed:     %v\n", config.NetworksAllowed)
	} else {
		fmt.Printf("Allowed:     all networks\n")
	}
	fmt.Printf("Signer port: %d\n", config.SignerPort)
	if config.SSH != nil {
		fmt.Printf("SSH host:    %s\n", config.SSH.Host)
		fmt.Printf("SSH port:    %d\n", config.SSH.Port)
		fmt.Printf("SSH key:     %s\n", config.SSH.IdentityFile)
		fmt.Printf("known_hosts: %s\n", config.SSH.KnownHostsPath)
	} else {
		fmt.Printf("SSH:         not configured (required — add ssh block to config.yaml)\n")
	}
	for network, cfg := range config.Algod {
		if cfg != nil && cfg.Server != "" {
			fmt.Printf("algod.%s:  %s\n", network, cfg.Server)
		}
	}
	fmt.Println()
}
