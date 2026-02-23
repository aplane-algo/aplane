// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"bytes"
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
	AutoRegister       *bool  `yaml:"auto_register" description:"Auto-register new SSH keys (TOFU)" default:"true"`
}

// ServerConfig represents the Signer configuration file
type ServerConfig struct {
	SignerPort        int              `yaml:"signer_port" description:"REST API port" default:"11270"`
	SSH               *SSHServerConfig `yaml:"ssh" description:"SSH tunnel settings (omit to disable SSH)"`
	PassphraseTimeout string           `yaml:"passphrase_timeout" description:"Inactivity timeout before auto-lock (0=never)" default:"15m"`
	StoreDir          string           `yaml:"store" description:"Store directory (required)"`
	IPCPath           string           `yaml:"ipc_path" description:"Unix socket path for admin IPC" default:"/tmp/aplane.sock"`
	LockOnDisconnect  *bool            `yaml:"lock_on_disconnect" description:"Lock signer when admin disconnects" default:"true"`
	PassphraseFile    string           `yaml:"passphrase_file" description:"Passphrase file for headless startup"`
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
	config.PassphraseFile = ResolvePath(config.PassphraseFile, dataDir)

	return config
}

// ShouldAutoRegisterSSHKeys returns whether new SSH keys should be auto-registered.
// Defaults to true if not explicitly set. Returns false if SSH is disabled.
func (c *ServerConfig) ShouldAutoRegisterSSHKeys() bool {
	if c.SSH == nil {
		return false // SSH disabled
	}
	if c.SSH.AutoRegister == nil {
		return true // Default: auto-register for TOFU
	}
	return *c.SSH.AutoRegister
}

// SSHEnabled returns true if SSH is configured
func (c *ServerConfig) SSHEnabled() bool {
	return c.SSH != nil
}

// ShouldLockOnDisconnect returns whether the signer should lock when apadmin disconnects.
// Defaults to true if not explicitly set.
// Note: In headless mode (passphrase_file set), this is always false.
func (c *ServerConfig) ShouldLockOnDisconnect() bool {
	// Headless mode never locks on disconnect
	if c.PassphraseFile != "" {
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

// ValidateHeadlessPolicy checks that policy settings are properly configured for headless operation.
func ValidateHeadlessPolicy(config *ServerConfig) error {
	// Check that there's a way to auto-approve transactions
	// Note: validation transactions (0 ALGO self-send) are always auto-approved
	if !config.EffectiveTxnAutoApprove() {
		return fmt.Errorf("headless mode requires txn_auto_approve:true in config (no one available to manually approve)")
	}

	// Group signing also requires auto-approve in headless mode (no apadmin to approve)
	if !config.GroupAutoApprove {
		return fmt.Errorf("headless mode requires group_auto_approve:true in config (no one available to manually approve groups)")
	}

	return nil
}

// ValidatePassphraseFile checks that a passphrase file exists and has secure permissions.
func ValidatePassphraseFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("passphrase_file: %w", err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("passphrase_file must be a regular file, not %s", info.Mode().Type())
	}

	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		return fmt.Errorf("passphrase_file has insecure permissions %04o (group/other access not allowed)", perm)
	}

	return nil
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

// ReadPassphraseFileBytes reads a passphrase from a file with security checks.
// Returns the passphrase as []byte for secure handling (can be zeroed after use).
// Returns nil and error if:
// - File doesn't exist or can't be read
// - File has group or other permissions set (must be 0600 or more restrictive)
func ReadPassphraseFileBytes(path string) ([]byte, error) {
	// Check file exists and get info
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot access passphrase file: %w", err)
	}

	// Check it's a regular file
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("passphrase_file must be a regular file, not %s", info.Mode().Type())
	}

	// Check permissions - no group/other access allowed
	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		return nil, fmt.Errorf("passphrase_file has insecure permissions %04o (group/other access not allowed)", perm)
	}

	// Read the file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read passphrase file: %w", err)
	}

	// Trim whitespace (allow trailing newline in file)
	passphrase := bytes.TrimSpace(data)
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase_file is empty")
	}

	return passphrase, nil
}
