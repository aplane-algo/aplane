// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"fmt"
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

// SSHClientConfig is compatibility-only client SSH configuration retained for
// old command forms. Current signer and sentry endpoint routing lives in
// ClientEndpointConfig records loaded from endpoints.yaml.
type SSHClientConfig struct {
	Host           string `yaml:"host" description:"Signer host to SSH to (required)"`
	Port           int    `yaml:"port" description:"SSH port" default:"1127"`
	IdentityFile   string `yaml:"identity_file" description:"SSH private key path (relative to data dir)" default:".ssh/id_ed25519"`
	KnownHostsPath string `yaml:"known_hosts_path" description:"Known hosts file path (relative to data dir)" default:".ssh/known_hosts"`
}

// AttestorEndpointConfig maps an embedded sentry public key to the signer
// endpoint that can produce sentry-role component signatures for that key.
type AttestorEndpointConfig struct {
	Endpoint       string `yaml:"endpoint,omitempty" description:"Endpoint alias from endpoints.yaml"`
	URL            string `yaml:"url" description:"Sentry endpoint URL: self, https://..., loopback http://..., or ssh://host[:port]"`
	TokenFile      string `yaml:"token_file,omitempty" description:"Path to the sentry endpoint API token file"`
	SignerPort     int    `yaml:"signer_port,omitempty" description:"Remote apsigner REST port for ssh:// sentry endpoints"`
	LocalPort      int    `yaml:"local_port,omitempty" description:"Local tunnel port for ssh:// sentry endpoints (0 = choose automatically)"`
	IdentityFile   string `yaml:"identity_file,omitempty" description:"SSH private key path for ssh:// sentry endpoints"`
	KnownHostsPath string `yaml:"known_hosts_path,omitempty" description:"known_hosts path for ssh:// sentry endpoints"`
}

// AttestorEndpointConfigs is keyed by canonical lower-case embedded sentry
// public-key hex.
type AttestorEndpointConfigs map[string]AttestorEndpointConfig

// Config holds apshell configuration settings
type Config struct {
	Network          string   `yaml:"network" description:"Default network context token" default:"testnet"`
	NetworksAllowed  []string `yaml:"networks_allowed" description:"Restrict allowed networks (empty = all)" default:"[]"`
	LegacySignerPort int      `yaml:"signer_port" configdoc:"skip" description:"Compatibility fallback for legacy client routing; current endpoint signer_port lives in endpoints.yaml" default:"11270"`
	Theme            string   `yaml:"theme" description:"Local client UI theme: auto, dark, or light (auto detects terminal)" default:"auto"`
	// SignerStatusPollInterval controls how often interactive apshell sessions
	// poll /status for keyset revision changes. "0" disables background polling.
	SignerStatusPollInterval string `yaml:"signer_status_poll_interval" description:"Background /status polling interval for signer keyset refresh (0=disabled)" default:"10s"`

	// LegacySSH is compatibility-only client routing state. New installs and
	// normal connections use endpoint records from endpoints.yaml.
	LegacySSH *SSHClientConfig `yaml:"ssh" configdoc:"skip" description:"Compatibility SSH tunnel settings; current endpoint SSH fields live in endpoints.yaml"`

	// AttestorEndpoints maps attested-account embedded sentry public keys to
	// signer endpoints for sentry-role component signing. It is derived
	// runtime state from endpoints.yaml published_sentries and is not part of
	// config.yaml.
	AttestorEndpoints AttestorEndpointConfigs `yaml:"-"`

	// Endpoints is loaded from endpoints.yaml and is not part of config.yaml.
	Endpoints ClientEndpointRegistry `yaml:"-"`

	// Grouped network settings. This is the canonical on-disk network config.
	Networks ClientNetworkConfigs `yaml:"networks" description:"Grouped settings per network context token"`

	// Algod is a derived runtime index built from Networks.
	Algod AlgodConfig `yaml:"-"`
}

// DefaultConfig returns the default configuration for runtime use.
// Algod URLs are empty - user must explicitly configure them.
// SSH is nil by default; normal routing is loaded from endpoints.yaml.
func DefaultConfig() Config {
	return Config{
		Network:                  "testnet",
		NetworksAllowed:          []string{}, // Empty = all networks allowed
		LegacySignerPort:         DefaultRESTPort,
		Theme:                    "auto",
		SignerStatusPollInterval: DefaultSignerStatusPollIntervalString,
		LegacySSH:                nil,
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
	if config.LegacySSH != nil {
		config.LegacySSH.IdentityFile = ResolvePath(config.LegacySSH.IdentityFile, dataDir)
		config.LegacySSH.KnownHostsPath = ResolvePath(config.LegacySSH.KnownHostsPath, dataDir)
	}
	endpoints, err := LoadClientEndpointRegistry(dataDir, config)
	if err != nil {
		return Config{}, err
	}
	config.Endpoints = endpoints
	config.AttestorEndpoints, err = endpoints.PublishedSentryEndpointConfigs()
	if err != nil {
		return Config{}, err
	}

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
	if config.LegacySignerPort == 0 {
		config.LegacySignerPort = defaults.LegacySignerPort
	}
	if config.Theme == "" {
		config.Theme = defaults.Theme
	}
	if config.SignerStatusPollInterval == "" {
		config.SignerStatusPollInterval = defaults.SignerStatusPollInterval
	}

	// Fill in SSH defaults if SSH block is present
	if config.LegacySSH != nil {
		sshDefaults := DefaultSSHClientConfig()
		if config.LegacySSH.Host == "" {
			return Config{}, fmt.Errorf("ssh.host is required when ssh block is present")
		}
		if config.LegacySSH.Port == 0 {
			config.LegacySSH.Port = sshDefaults.Port
		}
		if config.LegacySSH.IdentityFile == "" {
			config.LegacySSH.IdentityFile = sshDefaults.IdentityFile
		}
		if config.LegacySSH.KnownHostsPath == "" {
			config.LegacySSH.KnownHostsPath = sshDefaults.KnownHostsPath
		}
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
	if c.LegacySSH == nil {
		return nil // SSH not configured
	}
	return &ParsedConnection{
		Host:       c.LegacySSH.Host,
		SSHPort:    c.LegacySSH.Port,
		SignerPort: c.LegacySignerPort,
	}
}

// UseSSH returns true if SSH tunnel is configured
func (c *Config) UseSSH() bool {
	return c.LegacySSH != nil
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
	fmt.Printf("Signer port: %d (compatibility fallback; current routing is endpoints.yaml)\n", config.LegacySignerPort)
	if config.LegacySSH != nil {
		fmt.Printf("SSH host:    %s\n", config.LegacySSH.Host)
		fmt.Printf("SSH port:    %d\n", config.LegacySSH.Port)
		fmt.Printf("SSH key:     %s\n", config.LegacySSH.IdentityFile)
		fmt.Printf("known_hosts: %s\n", config.LegacySSH.KnownHostsPath)
	} else {
		fmt.Printf("SSH:         not configured in config.yaml (current signer routing is endpoints.yaml)\n")
	}
	for network, cfg := range config.Algod {
		if cfg != nil && cfg.Server != "" {
			fmt.Printf("algod.%s:  %s\n", network, cfg.Server)
		}
	}
	fmt.Println()
}
