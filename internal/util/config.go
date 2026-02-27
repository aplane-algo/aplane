// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// SSHClientConfig holds SSH tunnel configuration for connecting to remote signer.
// If nil, direct connection to localhost is used.
type SSHClientConfig struct {
	Host           string `yaml:"host" description:"Remote host to SSH to (required)"`
	Port           int    `yaml:"port" description:"SSH port" default:"1127"`
	IdentityFile   string `yaml:"identity_file" description:"SSH private key path (relative to data dir)" default:".ssh/id_ed25519"`
	KnownHostsPath string `yaml:"known_hosts_path" description:"Known hosts file path (relative to data dir)" default:".ssh/known_hosts"`
}

// Config holds apshell configuration settings
type Config struct {
	Network         string   `yaml:"network" description:"Default network (mainnet, testnet, betanet)" default:"testnet"`
	NetworksAllowed []string `yaml:"networks_allowed" description:"Restrict allowed networks (empty = all)" default:"[]"`
	SignerPort      int      `yaml:"signer_port" description:"Local REST port for apsignerd" default:"11270"`
	AIModel         string   `yaml:"ai_model" description:"AI model override (provider default if empty)"`

	// SSH tunnel config (nil = direct connection to localhost)
	SSH *SSHClientConfig `yaml:"ssh" description:"SSH tunnel settings (omit for direct localhost connection)"`

	// Mainnet algod settings
	MainnetAlgodServer string `yaml:"mainnet_algod_server" description:"Mainnet algod server URL"`
	MainnetAlgodPort   int    `yaml:"mainnet_algod_port" description:"Mainnet algod port (if separate from URL)"`
	MainnetAlgodToken  string `yaml:"mainnet_algod_token" description:"Mainnet algod API token"`

	// Testnet algod settings
	TestnetAlgodServer string `yaml:"testnet_algod_server" description:"Testnet algod server URL"`
	TestnetAlgodPort   int    `yaml:"testnet_algod_port" description:"Testnet algod port (if separate from URL)"`
	TestnetAlgodToken  string `yaml:"testnet_algod_token" description:"Testnet algod API token"`

	// Betanet algod settings
	BetanetAlgodServer string `yaml:"betanet_algod_server" description:"Betanet algod server URL"`
	BetanetAlgodPort   int    `yaml:"betanet_algod_port" description:"Betanet algod port (if separate from URL)"`
	BetanetAlgodToken  string `yaml:"betanet_algod_token" description:"Betanet algod API token"`
}

// DefaultConfig returns the default configuration for runtime use.
// Algod URLs are empty - user must explicitly configure them.
// SSH is nil by default (direct connection to localhost).
func DefaultConfig() Config {
	return Config{
		Network:         "testnet",
		NetworksAllowed: []string{}, // Empty = all networks allowed
		SignerPort:      DefaultRESTPort,
		SSH:             nil, // nil = direct connection to localhost
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

// DefaultClientDataDir is the default data directory for aplane clients (apshell, Python SDK)
const DefaultClientDataDir = "~/.apclient"

// GetClientDataDir returns the data directory for aplane clients.
// Resolution order: -d flag > APCLIENT_DATA env var > ~/.apclient
func GetClientDataDir(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if envDir := os.Getenv("APCLIENT_DATA"); envDir != "" {
		return envDir
	}
	// Expand ~ to home directory
	home, err := os.UserHomeDir()
	if err != nil {
		return "" // Can't determine default
	}
	return filepath.Join(home, ".apclient")
}

// RequireClientDataDir resolves the client data directory from the flag value,
// APCLIENT_DATA environment variable, or ~/.apclient default. Exits if unresolvable.
func RequireClientDataDir(flagValue string) string {
	dir := GetClientDataDir(flagValue)
	if dir == "" {
		fmt.Fprintln(os.Stderr, "Error: Could not determine data directory")
		fmt.Fprintln(os.Stderr, "Use -d <path> or set APCLIENT_DATA environment variable")
		os.Exit(1)
	}
	return dir
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
	if err := yaml.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate network is a valid Algorand network
	validNetworks := map[string]bool{
		"mainnet": true,
		"testnet": true,
		"betanet": true,
	}
	if !validNetworks[config.Network] {
		return Config{}, fmt.Errorf("invalid network '%s' in config (must be mainnet, testnet, or betanet)", config.Network)
	}

	// Validate networks_allowed entries are valid networks
	for _, n := range config.NetworksAllowed {
		if !validNetworks[n] {
			return Config{}, fmt.Errorf("invalid network '%s' in networks_allowed (must be mainnet, testnet, or betanet)", n)
		}
	}

	// Validate network is in networks_allowed (if networks_allowed is set)
	if len(config.NetworksAllowed) > 0 && !config.IsNetworkAllowed(config.Network) {
		return Config{}, fmt.Errorf("network '%s' is not in networks_allowed %v", config.Network, config.NetworksAllowed)
	}

	// Fill in defaults for missing values
	defaults := DefaultConfig()
	if config.SignerPort == 0 {
		config.SignerPort = defaults.SignerPort
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

	return config, nil
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

// AlgodConfig holds algod connection settings for a network
type AlgodConfig struct {
	Server string
	Port   int
	Token  string
}

// Address returns the full algod address, including port if specified
func (a *AlgodConfig) Address() string {
	if a.Port > 0 {
		return fmt.Sprintf("%s:%d", a.Server, a.Port)
	}
	return a.Server
}

// GetAlgodConfig returns the algod settings for the specified network.
// Returns the configured values without fallback defaults - caller should
// check if Server is empty and handle accordingly.
func (c *Config) GetAlgodConfig(network string) (*AlgodConfig, error) {
	switch network {
	case "mainnet":
		return &AlgodConfig{
			Server: c.MainnetAlgodServer,
			Port:   c.MainnetAlgodPort,
			Token:  c.MainnetAlgodToken,
		}, nil
	case "testnet":
		return &AlgodConfig{
			Server: c.TestnetAlgodServer,
			Port:   c.TestnetAlgodPort,
			Token:  c.TestnetAlgodToken,
		}, nil
	case "betanet":
		return &AlgodConfig{
			Server: c.BetanetAlgodServer,
			Port:   c.BetanetAlgodPort,
			Token:  c.BetanetAlgodToken,
		}, nil
	default:
		return nil, fmt.Errorf("invalid network: %s", network)
	}
}

// GetParsedConnection returns a ParsedConnection from the config.
// Returns nil if no SSH is configured (direct localhost connection).
func (c *Config) GetParsedConnection() *ParsedConnection {
	if c.SSH == nil {
		return nil // Direct connection to localhost
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
// For localhost connections (direct, no tunnel):
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
		fmt.Printf("SSH:         disabled (direct connection to localhost)\n")
	}
	if config.AIModel != "" {
		fmt.Printf("AI model:    %s\n", config.AIModel)
	} else {
		fmt.Printf("AI model:    (provider default)\n")
	}
	fmt.Println()
}
