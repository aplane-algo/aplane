// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// SSHServerConfig holds SSH server configuration for apsignerd.
// If nil, SSH is disabled and REST API binds to all interfaces.
type SSHServerConfig struct {
	Port               int    `yaml:"port" description:"SSH port to listen on" default:"1127"`
	HostKeyPath        string `yaml:"host_key_path" description:"Server's private host key path" default:".ssh/ssh_host_key"`
	AuthorizedKeysPath string `yaml:"authorized_keys_path" description:"Allowed client public keys file" default:".ssh/authorized_keys"`
	AutoRegister       *bool  `yaml:"auto_register" description:"Auto-register new SSH keys (TOFU)" default:"false"`
}

// ServerConfig represents the Signer configuration file
type ServerConfig struct {
	SignerPort            int               `yaml:"signer_port" description:"REST API port" default:"11270"`
	SSH                   *SSHServerConfig  `yaml:"ssh" description:"SSH tunnel settings (omit to disable SSH)"`
	PassphraseTimeout     string            `yaml:"passphrase_timeout" description:"Inactivity timeout before auto-lock (0=never)" default:"15m"`
	StoreDir              string            `yaml:"store" description:"Store directory (required)"`
	IPCPath               string            `yaml:"ipc_path" description:"Unix socket path for admin IPC" default:"/tmp/aplane.sock"`
	LockOnDisconnect      *bool             `yaml:"lock_on_disconnect" description:"Lock signer when admin disconnects" default:"true"`
	PassphraseCommandArgv []string          `yaml:"passphrase_command_argv" description:"Command to run to obtain/store the passphrase (all paths resolved relative to data directory; verb 'read' or 'write' is injected as argv[1])"`
	PassphraseCommandEnv  map[string]string `yaml:"passphrase_command_env" description:"Environment variables to pass to the passphrase command (process env is never inherited)"`
	// TEAL compilation settings (for LogicSig generation)
	TEALCompilerAlgodURL   string `yaml:"teal_compiler_algod_url" description:"Algod URL for TEAL compilation"`
	TEALCompilerAlgodToken string `yaml:"teal_compiler_algod_token" description:"Algod token for TEAL compilation"`
	// Security settings
	RequireMemoryProtection bool `yaml:"require_memory_protection" description:"Fail startup if memory protection unavailable" default:"false"`
	// Approval policy settings (previously in separate policy.yaml)
	TxnAutoApprove         bool `yaml:"txn_auto_approve" description:"Auto-approve ALL single transaction signing requests (use with caution)" default:"false"`
	GroupAutoApprove       bool `yaml:"group_auto_approve" description:"Auto-approve ALL transaction group requests (use with caution)" default:"false"`
	AllowGroupModification bool `yaml:"allow_group_modification" description:"Allow /sign to modify pre-grouped transactions (adds dummies, changes group ID)" default:"false"`
}

// ResolvePath resolves a path relative to baseDir if not absolute.
// Returns path unchanged if empty or already absolute.
func ResolvePath(path, baseDir string) string {
	if path == "" || baseDir == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

// DefaultSSHServerConfig returns default SSH server settings
// (used when ssh block exists but fields are missing)
func DefaultSSHServerConfig() SSHServerConfig {
	return SSHServerConfig{
		Port:               DefaultSSHPort,
		HostKeyPath:        ".ssh/ssh_host_key",    // Relative to data directory
		AuthorizedKeysPath: ".ssh/authorized_keys", // Relative to data directory
		// AutoRegister defaults to true (handled by ShouldAutoRegisterSSHKeys)
	}
}

// DefaultServerConfig returns the default server configuration
// Relative paths in config are resolved relative to the data directory ($APSIGNER_DATA)
// SSH is nil by default (disabled) - REST API binds to all interfaces
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		SignerPort:        DefaultRESTPort,
		SSH:               nil,   // nil = SSH disabled
		PassphraseTimeout: "15m", // 15 minute session timeout (use "0" for never expire)
		StoreDir:          "",    // no default - must be explicitly configured
		IPCPath:           GetDefaultIPCPath(),
	}
}

// GetSignerDataDir returns the data directory for apsignerd.
// It checks -d flag value first (passed as parameter), then APSIGNER_DATA env var.
// Returns empty string if neither is set.
func GetSignerDataDir(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("APSIGNER_DATA")
}

// RequireSignerDataDir resolves the signer data directory from the flag value
// or APSIGNER_DATA environment variable. Exits if neither is set.
func RequireSignerDataDir(flagValue string) string {
	dir := GetSignerDataDir(flagValue)
	if dir == "" {
		fmt.Fprintln(os.Stderr, "Error: Data directory not specified")
		fmt.Fprintln(os.Stderr, "Use -d <path> or set APSIGNER_DATA environment variable")
		os.Exit(1)
	}
	return dir
}

// LoadServerConfig loads configuration from a YAML file in the data directory.
// The dataDir parameter is required - use GetSignerDataDir() to resolve it.
// Config file is expected at <dataDir>/config.yaml.
// Returns default config if file doesn't exist or can't be read.
func LoadServerConfig(dataDir string) ServerConfig {
	defaults := DefaultServerConfig()

	if dataDir == "" {
		return defaults
	}

	path := filepath.Join(dataDir, "config.yaml")

	// Try to read config file
	data, err := os.ReadFile(path)
	if err != nil {
		// File doesn't exist or can't be read - use defaults
		return defaults
	}

	// Parse YAML
	var config ServerConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Warning: Failed to parse config file %s: %v\n", path, err)
		return defaults
	}

	// Fill in missing fields with defaults
	if config.SignerPort == 0 {
		config.SignerPort = defaults.SignerPort
	}
	if config.PassphraseTimeout == "" {
		config.PassphraseTimeout = defaults.PassphraseTimeout
	}
	if config.IPCPath == "" {
		config.IPCPath = defaults.IPCPath
	}
	// StoreDir intentionally has no default - must be explicitly configured

	// Fill in SSH defaults if SSH block is present
	if config.SSH != nil {
		sshDefaults := DefaultSSHServerConfig()
		if config.SSH.Port == 0 {
			config.SSH.Port = sshDefaults.Port
		}
		if config.SSH.HostKeyPath == "" {
			config.SSH.HostKeyPath = sshDefaults.HostKeyPath
		}
		if config.SSH.AuthorizedKeysPath == "" {
			config.SSH.AuthorizedKeysPath = sshDefaults.AuthorizedKeysPath
		}
		// Resolve relative SSH paths to absolute paths
		config.SSH.HostKeyPath = ResolvePath(config.SSH.HostKeyPath, dataDir)
		config.SSH.AuthorizedKeysPath = ResolvePath(config.SSH.AuthorizedKeysPath, dataDir)
	}

	// Resolve relative paths to absolute paths based on dataDir
	config.StoreDir = ResolvePath(config.StoreDir, dataDir)

	// Resolve relative paths in passphrase_command_argv against the data directory.
	// All elements (binary and arguments) use the same resolution logic.
	for i := range config.PassphraseCommandArgv {
		config.PassphraseCommandArgv[i] = ResolvePath(config.PassphraseCommandArgv[i], dataDir)
	}

	return config
}

// ShouldAutoRegisterSSHKeys returns whether new SSH keys should be auto-registered.
// Defaults to false if not explicitly set. Returns false if SSH is disabled.
func (c *ServerConfig) ShouldAutoRegisterSSHKeys() bool {
	if c.SSH == nil {
		return false // SSH disabled
	}
	if c.SSH.AutoRegister == nil {
		return false // Default: reject unknown keys
	}
	return *c.SSH.AutoRegister
}

// SSHEnabled returns true if SSH is configured
func (c *ServerConfig) SSHEnabled() bool {
	return c.SSH != nil
}

// ShouldLockOnDisconnect returns whether the signer should lock when apadmin disconnects.
// Defaults to true if not explicitly set.
// Note: In headless mode (passphrase_command_argv set), this is always false.
func (c *ServerConfig) ShouldLockOnDisconnect() bool {
	// Headless mode never locks on disconnect
	if len(c.PassphraseCommandArgv) > 0 {
		return false
	}
	if c.LockOnDisconnect == nil {
		return true // Default: lock on disconnect for security
	}
	return *c.LockOnDisconnect
}

// EffectiveTxnAutoApprove returns true if single transaction auto-approve is enabled.
func (c *ServerConfig) EffectiveTxnAutoApprove() bool {
	return c.TxnAutoApprove
}

// ValidateHeadlessPolicy checks policy settings for headless operation.
// Returns warnings (not errors) because automated passphrase retrieval does not preclude
// human approval — an operator may connect via apadmin for manual approval.
func ValidateHeadlessPolicy(config *ServerConfig) []string {
	var warnings []string

	if !config.EffectiveTxnAutoApprove() {
		warnings = append(warnings, "headless mode without txn_auto_approve: transactions will require manual approval via apadmin")
	}

	if !config.GroupAutoApprove {
		warnings = append(warnings, "headless mode without group_auto_approve: group transactions will require manual approval via apadmin")
	}

	return warnings
}

// PassphraseCommandCfg builds a PassphraseCommandConfig from the ServerConfig fields.
func (c *ServerConfig) PassphraseCommandCfg() *PassphraseCommandConfig {
	return &PassphraseCommandConfig{
		Argv: c.PassphraseCommandArgv,
		Env:  c.PassphraseCommandEnv,
	}
}

// ParsePassphraseTimeout parses a passphrase timeout string into a time.Duration.
// Accepts formats like: "0" (never expire), "15m" (15 minutes), "1h" (1 hour).
// Negative durations are rejected.
func ParsePassphraseTimeout(timeoutStr string) (time.Duration, error) {
	if timeoutStr == "" || timeoutStr == "0" {
		return 0, nil // Never expire
	}

	// Try to parse as duration
	duration, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return 0, fmt.Errorf("invalid duration format: %w", err)
	}

	if duration < 0 {
		return 0, fmt.Errorf("negative duration %q not supported (use \"0\" for no timeout)", timeoutStr)
	}

	return duration, nil
}
