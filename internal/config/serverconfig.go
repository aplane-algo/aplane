// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// SSHServerConfig holds SSH server configuration for apsigner.
type SSHServerConfig struct {
	Port               int    `yaml:"port" description:"SSH port to listen on" default:"1127"`
	HostKeyPath        string `yaml:"host_key_path" description:"Server's private host key path" default:".ssh/ssh_host_key"`
	AuthorizedKeysPath string `yaml:"authorized_keys_path" description:"Legacy/global authorized client public keys file" default:".ssh/authorized_keys"`
}

const (
	DefaultApprovalWaitString = "60s"
	DefaultApprovalWait       = 60 * time.Second
	MinApprovalWait           = 30 * time.Second
	MaxApprovalWait           = 30 * time.Minute
)

// ServerConfig represents the Signer configuration file
type ServerConfig struct {
	SignerPort            int               `yaml:"signer_port" description:"REST API port" default:"11270"`
	SSH                   SSHServerConfig   `yaml:"ssh" description:"SSH tunnel settings for apsigner" default:"default SSH settings"`
	PassphraseTimeout     string            `yaml:"passphrase_timeout" description:"Admin idle disconnect timeout (0=never)" default:"15m"`
	ApprovalWait          string            `yaml:"approval_wait" description:"Maximum time to wait for operator approval of a signing request" default:"60s"`
	IPCPath               string            `yaml:"ipc_path" description:"Unix socket path for admin IPC" default:"$APSIGNER_DATA/aplane.sock"`
	LockOnDisconnect      *bool             `yaml:"lock_on_disconnect" description:"Lock signer when admin disconnects" default:"true"`
	PassphraseCommandArgv []string          `yaml:"passphrase_command_argv" description:"Command to run to obtain/store the passphrase (all paths resolved relative to data directory; verb 'read' or 'write' is injected as argv[1])" default:"[]"`
	PassphraseCommandEnv  map[string]string `yaml:"passphrase_command_env" description:"Environment variables to pass to the passphrase command; the process env is not inherited except for the systemd CREDENTIALS_DIRECTORY passthrough" default:"{}"`
	// Network settings per context token (used for TEAL compilation, policy enforcement, etc.).
	// This is the canonical on-disk network config.
	Networks           ServerNetworkConfigs `yaml:"networks" description:"Grouped settings per network context token"`
	TEALCompileNetwork string               `yaml:"teal_compile_network" description:"Network context token whose algod is used for TEAL compilation" default:"testnet"`
	// Algod and GenesisHashNetworks are derived runtime indexes built from Networks.
	Algod               AlgodConfig       `yaml:"-"`
	GenesisHashNetworks map[string]string `yaml:"-"`
	// Security settings
	RequireMemoryProtection bool `yaml:"require_memory_protection" description:"Fail startup if memory protection unavailable" default:"false"`
	// Operator-default approval setting. Policy rules live in identity policy.yaml.
	UserAutoApprove bool `yaml:"user_auto_approve" description:"User default to sign non-rejected requests without operator approval unless policy forces review" default:"false"`
	// Display settings
	Theme string `yaml:"theme" description:"Signer-admin UI theme: auto, dark, or light (auto detects terminal)" default:"auto"`
}

type serverConfigFile struct {
	ServerConfig   `yaml:",inline"`
	ManualApproval *bool `yaml:"manual_approval,omitempty"`
}

// Clone returns an independent copy of the server config.
func (c ServerConfig) Clone() ServerConfig {
	out := c
	if c.LockOnDisconnect != nil {
		v := *c.LockOnDisconnect
		out.LockOnDisconnect = &v
	}
	if c.PassphraseCommandArgv != nil {
		out.PassphraseCommandArgv = append([]string(nil), c.PassphraseCommandArgv...)
	}
	if c.PassphraseCommandEnv != nil {
		out.PassphraseCommandEnv = make(map[string]string, len(c.PassphraseCommandEnv))
		for k, v := range c.PassphraseCommandEnv {
			out.PassphraseCommandEnv[k] = v
		}
	}
	if c.Algod != nil {
		out.Algod = make(AlgodConfig, len(c.Algod))
		for network, cfg := range c.Algod {
			if cfg == nil {
				continue
			}
			cp := *cfg
			out.Algod[network] = &cp
		}
	}
	if c.GenesisHashNetworks != nil {
		out.GenesisHashNetworks = cloneStringMap(c.GenesisHashNetworks)
	}
	if c.Networks != nil {
		out.Networks = make(ServerNetworkConfigs, len(c.Networks))
		for network, cfg := range c.Networks {
			if cfg == nil {
				continue
			}
			cp := *cfg
			if cfg.Algod != nil {
				algodCP := *cfg.Algod
				cp.Algod = &algodCP
			}
			out.Networks[network] = &cp
		}
	}
	return out
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
	}
}

// DefaultServerConfig returns the default server configuration.
// Relative paths in config are resolved relative to the data directory ($APSIGNER_DATA).
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		SignerPort:         DefaultRESTPort,
		SSH:                DefaultSSHServerConfig(),
		PassphraseTimeout:  "15m", // 15 minute admin idle timeout (use "0" to disable)
		ApprovalWait:       DefaultApprovalWaitString,
		IPCPath:            "",
		TEALCompileNetwork: "testnet",
		UserAutoApprove:    false,
	}
}

// GetSignerDataDir returns the data directory for apsigner.
// It checks -d flag value first (passed as parameter), then APSIGNER_DATA env var.
// Returns empty string if neither is set.
func GetSignerDataDir(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("APSIGNER_DATA")
}

// LoadServerConfig loads configuration from a YAML file in the data directory.
// The dataDir parameter is required - use GetSignerDataDir() to resolve it.
// Config file is expected at <dataDir>/config.yaml.
// Returns default config if file doesn't exist or can't be read.
func LoadServerConfig(dataDir string) (ServerConfig, error) {
	defaults := DefaultServerConfig()

	if dataDir == "" {
		return defaults, nil
	}

	path := filepath.Join(dataDir, "config.yaml")

	// Try to read config file
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			_, _ = fmt.Fprintf(os.Stderr, "Warning: Config file not found: %s\n", path)
		} else if os.IsPermission(err) {
			_, _ = fmt.Fprintf(os.Stderr, "Warning: Permission denied reading config file: %s\n", path)
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "Warning: Could not read config file %s: %v\n", path, err)
		}
		return defaults, nil
	}

	// Parse YAML
	configFile := serverConfigFile{ServerConfig: defaults}
	if err := unmarshalKnownFields(data, &configFile); err != nil {
		return ServerConfig{}, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}
	config := configFile.ServerConfig
	if err := applyLegacyManualApproval(data, configFile.ManualApproval, &config); err != nil {
		return ServerConfig{}, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}
	if config.Algod, err = mergeServerNetworkAlgodConfig(nil, config.Networks); err != nil {
		return ServerConfig{}, fmt.Errorf("invalid network in networks config: %w", err)
	}
	if config.GenesisHashNetworks, err = mergeServerNetworkGenesisHashConfig(nil, config.Networks); err != nil {
		return ServerConfig{}, fmt.Errorf("invalid genesis_hash in networks config: %w", err)
	}

	// Fill in missing fields with defaults
	if config.SignerPort == 0 {
		config.SignerPort = defaults.SignerPort
	}
	if config.PassphraseTimeout == "" {
		config.PassphraseTimeout = defaults.PassphraseTimeout
	}
	if config.ApprovalWait == "" {
		config.ApprovalWait = defaults.ApprovalWait
	}
	if _, err := ParseApprovalWait(config.ApprovalWait); err != nil {
		return ServerConfig{}, fmt.Errorf("invalid approval_wait in config: %w", err)
	}
	if config.IPCPath == "" && dataDir != "" {
		config.IPCPath = filepath.Join(dataDir, "aplane.sock")
	}
	if config.TEALCompileNetwork == "" {
		config.TEALCompileNetwork = defaults.TEALCompileNetwork
	}

	// Validate teal_compile_network is a filesystem-safe context token.
	if err := ValidateNetworkID(config.TEALCompileNetwork); err != nil {
		return ServerConfig{}, fmt.Errorf("invalid teal_compile_network in config: %w", err)
	}

	// Validate algod map keys are valid context tokens.
	for network := range config.Algod {
		if err := ValidateNetworkID(network); err != nil {
			return ServerConfig{}, fmt.Errorf("invalid network in algod config: %w", err)
		}
	}
	if _, err := NewGenesisHashNetworkResolver(config.GenesisHashNetworks); err != nil {
		return ServerConfig{}, fmt.Errorf("invalid network genesis_hash: %w", err)
	}

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
	// Resolve relative SSH paths to absolute paths.
	config.SSH.HostKeyPath = ResolvePath(config.SSH.HostKeyPath, dataDir)
	config.SSH.AuthorizedKeysPath = ResolvePath(config.SSH.AuthorizedKeysPath, dataDir)

	// Resolve relative paths in passphrase_command_argv against the data directory.
	// All elements (binary and arguments) use the same resolution logic.
	for i := range config.PassphraseCommandArgv {
		config.PassphraseCommandArgv[i] = ResolvePath(config.PassphraseCommandArgv[i], dataDir)
	}

	return config, nil
}

func applyLegacyManualApproval(data []byte, manualApproval *bool, config *ServerConfig) error {
	if manualApproval == nil {
		return nil
	}
	legacyUserAutoApprove := !*manualApproval
	if yamlHasTopLevelKey(data, "user_auto_approve") {
		if config.UserAutoApprove != legacyUserAutoApprove {
			return fmt.Errorf("manual_approval is deprecated and conflicts with user_auto_approve")
		}
		return nil
	}
	config.UserAutoApprove = legacyUserAutoApprove
	return nil
}

func yamlHasTopLevelKey(data []byte, key string) bool {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return false
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return false
	}
	mapping := root.Content[0]
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return true
		}
	}
	return false
}

// GetAlgodConfig returns the algod settings for the specified network.
func (c *ServerConfig) GetAlgodConfig(network string) (*AlgodNetworkConfig, error) {
	return c.Algod.GetNetwork(network)
}

// GetTEALCompileAlgod returns the algod config used for TEAL compilation.
func (c *ServerConfig) GetTEALCompileAlgod() (*AlgodNetworkConfig, error) {
	return c.Algod.GetNetwork(c.TEALCompileNetwork)
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

// ValidateHeadlessPolicy checks policy settings for headless operation.
// Returns warnings (not errors) because automated passphrase retrieval does not preclude
// human approval — an operator may connect via apadmin for manual approval.
func ValidateHeadlessPolicy(config *ServerConfig) []string {
	var warnings []string

	warnings = append(warnings, "headless mode keeps the signer unlocked in memory until process exit or manual lock")

	if !config.UserAutoApprove {
		warnings = append(warnings, "headless mode with user_auto_approve:false: transactions will require manual approval via apadmin")
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

// SaveSetting writes a single setting to config.yaml, preserving all other
// fields in the file. Only the specified key is updated.
func SaveSetting(dataDir, key string, value interface{}) error {
	if dataDir == "" {
		return fmt.Errorf("data directory not set")
	}

	path := filepath.Join(dataDir, "config.yaml")

	existing := make(map[string]interface{})
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	existing[key] = value

	out, err := yaml.Marshal(existing)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := writeConfigAtomic(path, out, 0o640); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// ConfigFileChanged checks whether the on-disk config.yaml has been modified
// externally (e.g., by appass) since apsigner loaded it. Compares the mutable
// fields that could conflict if stale.
func ConfigFileChanged(dataDir string, startup ServerConfig) (bool, error) {
	disk, err := LoadServerConfig(dataDir)
	if err != nil {
		return false, err
	}

	if disk.PassphraseTimeout != startup.PassphraseTimeout {
		return true, nil
	}
	if disk.ApprovalWait != startup.ApprovalWait {
		return true, nil
	}
	if disk.UserAutoApprove != startup.UserAutoApprove {
		return true, nil
	}
	if disk.Theme != startup.Theme {
		return true, nil
	}
	if disk.SignerPort != startup.SignerPort {
		return true, nil
	}
	if disk.SSH.Port != startup.SSH.Port {
		return true, nil
	}
	if disk.ShouldLockOnDisconnect() != startup.ShouldLockOnDisconnect() {
		return true, nil
	}
	if !reflect.DeepEqual(disk.PassphraseCommandEnv, startup.PassphraseCommandEnv) {
		return true, nil
	}
	if !reflect.DeepEqual(disk.Networks, startup.Networks) {
		return true, nil
	}
	// Compare passphrase_command_argv
	if len(disk.PassphraseCommandArgv) != len(startup.PassphraseCommandArgv) {
		return true, nil
	}
	for i := range disk.PassphraseCommandArgv {
		if disk.PassphraseCommandArgv[i] != startup.PassphraseCommandArgv[i] {
			return true, nil
		}
	}

	return false, nil
}

func writeConfigAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "config.yaml.tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}

	targetMode := mode
	var targetUID, targetGID int
	hasOwnership := false

	info, statErr := os.Stat(path)
	switch {
	case statErr == nil:
		targetMode = info.Mode().Perm()
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			targetUID = int(stat.Uid)
			targetGID = int(stat.Gid)
			hasOwnership = true
		}
	case os.IsNotExist(statErr):
		// New file: keep default mode and current ownership.
	default:
		return statErr
	}

	if err := tmp.Chmod(targetMode); err != nil {
		return err
	}
	if hasOwnership && (os.Getuid() != targetUID || os.Getgid() != targetGID) {
		if err := tmp.Chown(targetUID, targetGID); err != nil {
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// ParsePassphraseTimeout parses an admin idle timeout string into a time.Duration.
// Accepts formats like: "0" (disabled), "15m" (15 minutes), "1h" (1 hour).
// Negative durations are rejected.
func ParsePassphraseTimeout(timeoutStr string) (time.Duration, error) {
	if timeoutStr == "" || timeoutStr == "0" {
		return 0, nil // Disabled
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

// ParseApprovalWait parses and validates the manual signing approval wait.
func ParseApprovalWait(waitStr string) (time.Duration, error) {
	if waitStr == "" {
		return DefaultApprovalWait, nil
	}

	duration, err := time.ParseDuration(waitStr)
	if err != nil {
		return 0, fmt.Errorf("invalid duration format: %w", err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	if duration < MinApprovalWait {
		return 0, fmt.Errorf("duration %q below minimum %s", waitStr, MinApprovalWait)
	}
	if duration > MaxApprovalWait {
		return 0, fmt.Errorf("duration %q above maximum %s", waitStr, MaxApprovalWait)
	}
	return duration, nil
}
