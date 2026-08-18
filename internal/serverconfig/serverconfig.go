// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package serverconfig

import (
	"fmt"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/endpointrefs"

	"gopkg.in/yaml.v3"
)

// SSHServerConfig holds SSH server configuration for apsigner.
type SSHServerConfig struct {
	ListenAddress      string `yaml:"listen_address" description:"SSH listen address to bind" default:"127.0.0.1"`
	Port               int    `yaml:"port" description:"SSH port to listen on" default:"1127"`
	HostKeyPath        string `yaml:"host_key_path" description:"Server's private host key path" default:".ssh/ssh_host_key"`
	AuthorizedKeysPath string `yaml:"authorized_keys_path" description:"Process-global authorized client public keys file" default:".ssh/authorized_keys"`
}

// ServerEndpointConfig holds the signer endpoint surface exposed to clients.
type ServerEndpointConfig struct {
	AdvertiseURL string          `yaml:"advertise_url,omitempty" description:"Client-reachable public endpoint URL used by apadmin endpoint export when --host/--url are omitted"`
	SignerPort   int             `yaml:"signer_port" description:"Loopback REST API port behind the endpoint" default:"11270"`
	SSH          SSHServerConfig `yaml:"ssh" description:"SSH tunnel settings for apsigner endpoint access" default:"default SSH settings"`
}

const (
	DefaultApprovalWaitString = "60s"
	DefaultApprovalWait       = 60 * time.Second
	MinApprovalWait           = 30 * time.Second
	MaxApprovalWait           = 30 * time.Minute
)

// ServerConfig represents the Signer configuration file
type ServerConfig struct {
	SchemaVersion         int                  `yaml:"schema_version,omitempty" description:"Signer config schema version" default:"1"`
	Endpoint              ServerEndpointConfig `yaml:"endpoint" description:"Signer endpoint exposure settings" default:"default endpoint settings"`
	PassphraseTimeout     string               `yaml:"passphrase_timeout" description:"Admin idle disconnect timeout (0=never)" default:"15m"`
	ApprovalWait          string               `yaml:"approval_wait" description:"Maximum time to wait for operator approval of a signing request" default:"60s"`
	IPCPath               string               `yaml:"ipc_path" description:"Unix socket path for admin IPC; systemd custom paths must be outside signer data in a service-owned protected runtime directory" default:"systemd: /run/apsigner/aplane.sock; same-UID: $APSIGNER_DATA/aplane.sock"`
	LockOnDisconnect      *bool                `yaml:"lock_on_disconnect" description:"Lock signer when admin disconnects" default:"true"`
	PassphraseCommandArgv []string             `yaml:"passphrase_command_argv" description:"Command to run to obtain/store the passphrase (all paths resolved relative to data directory; verb 'read' or 'write' is injected as argv[1])" default:"[]"`
	PassphraseCommandEnv  map[string]string    `yaml:"passphrase_command_env" description:"Environment variables to pass to the passphrase command; the process env is not inherited except for the systemd CREDENTIALS_DIRECTORY passthrough" default:"{}"`
	// Network settings per context token (used for TEAL compilation, policy enforcement, etc.).
	// This is the canonical on-disk network config.
	Networks           ServerNetworkConfigs `yaml:"networks" description:"Grouped settings per network context token"`
	TEALCompileNetwork string               `yaml:"teal_compile_network" description:"Network context token whose algod is used for TEAL compilation" default:"testnet"`
	// Algod and GenesisHashNetworks are derived runtime indexes built from Networks.
	Algod               apconfig.AlgodConfig `yaml:"-"`
	GenesisHashNetworks map[string]string    `yaml:"-"`
	// Security settings
	RequireMemoryProtection bool `yaml:"require_memory_protection" description:"Fail startup if memory protection unavailable" default:"false"`
	// Operator-default approval setting. Policy rules live in identity policy.yaml.
	UserAutoApprove bool `yaml:"user_auto_approve" description:"User default to sign non-rejected requests without operator approval unless policy forces review" default:"false"`
	// Display settings
	Theme string `yaml:"theme" description:"Signer-admin UI theme: auto, dark, or light (auto detects terminal)" default:"auto"`
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
		out.Algod = make(apconfig.AlgodConfig, len(c.Algod))
		for network, cfg := range c.Algod {
			if cfg == nil {
				continue
			}
			cp := *cfg
			out.Algod[network] = &cp
		}
	}
	if c.GenesisHashNetworks != nil {
		out.GenesisHashNetworks = cloneServerStringMap(c.GenesisHashNetworks)
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

// DefaultSSHServerConfig returns default SSH server settings
// (used when ssh block exists but fields are missing)
func DefaultSSHServerConfig() SSHServerConfig {
	return SSHServerConfig{
		ListenAddress:      apconfig.DefaultSSHListenAddress,
		Port:               apconfig.DefaultSSHPort,
		HostKeyPath:        ".ssh/ssh_host_key",    // Relative to data directory
		AuthorizedKeysPath: ".ssh/authorized_keys", // Relative to data directory
	}
}

// DefaultServerEndpointConfig returns default signer endpoint settings.
func DefaultServerEndpointConfig() ServerEndpointConfig {
	return ServerEndpointConfig{
		SignerPort: apconfig.DefaultRESTPort,
		SSH:        DefaultSSHServerConfig(),
	}
}

// ValidateSSHListenAddress validates the host/address part used for the SSH
// listener. It accepts IP literals and DNS-style hostnames; ports and URLs are
// configured separately.
func ValidateSSHListenAddress(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("listen_address is required")
	}
	if strings.Contains(value, "://") {
		return fmt.Errorf("must be a host or IP address, not a URL")
	}
	if strings.ContainsAny(value, "/\\\x00") {
		return fmt.Errorf("must not contain path separators")
	}
	if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
		return fmt.Errorf("omit IPv6 brackets; configure the address without a port")
	}
	if strings.Contains(value, ":") {
		if strings.Count(value, ":") == 1 {
			return fmt.Errorf("must not include a port")
		}
		if _, err := netip.ParseAddr(value); err != nil {
			return fmt.Errorf("invalid IPv6 address: %w", err)
		}
		return nil
	}

	if len(value) > 253 {
		return fmt.Errorf("host name is too long")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" {
			return fmt.Errorf("host name contains an empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("host label %q is too long", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("host label %q must not start or end with '-'", label)
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return fmt.Errorf("host label %q contains invalid character %q", label, ch)
		}
	}
	return nil
}

// DefaultServerConfig returns the default server configuration.
// Relative paths in config are resolved relative to the data directory ($APSIGNER_DATA).
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		SchemaVersion:      apconfig.ConfigSchemaVersion,
		Endpoint:           DefaultServerEndpointConfig(),
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

	return parseServerConfig(dataDir, path, data, defaults)
}

// LoadServerConfigStrict loads an existing config and propagates every read
// failure. Discovery and security-sensitive callers use it after establishing
// that config.yaml exists so an unreadable custom path cannot silently become
// a default socket or configuration.
func LoadServerConfigStrict(dataDir string) (ServerConfig, error) {
	defaults := DefaultServerConfig()
	if dataDir == "" {
		return defaults, nil
	}
	path := filepath.Join(dataDir, "config.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return ServerConfig{}, fmt.Errorf("failed to read config file %s: %w", path, err)
	}
	return parseServerConfig(dataDir, path, data, defaults)
}

func parseServerConfig(dataDir, path string, data []byte, defaults ServerConfig) (ServerConfig, error) {
	config := defaults
	if err := apconfig.UnmarshalKnownConfigFields(data, &config); err != nil {
		return ServerConfig{}, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}
	config.SchemaVersion = apconfig.NormalizeConfigSchemaVersion(config.SchemaVersion)
	if err := apconfig.ValidateConfigSchemaVersion("server config", config.SchemaVersion); err != nil {
		return ServerConfig{}, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}
	var err error
	if config.Algod, err = mergeServerNetworkAlgodConfig(nil, config.Networks); err != nil {
		return ServerConfig{}, fmt.Errorf("invalid network in networks config: %w", err)
	}
	if config.GenesisHashNetworks, err = mergeServerNetworkGenesisHashConfig(nil, config.Networks); err != nil {
		return ServerConfig{}, fmt.Errorf("invalid genesis_hash in networks config: %w", err)
	}

	// Fill in missing fields with defaults
	if config.Endpoint.SignerPort == 0 {
		config.Endpoint.SignerPort = defaults.Endpoint.SignerPort
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
	if err := apconfig.ValidateNetworkID(config.TEALCompileNetwork); err != nil {
		return ServerConfig{}, fmt.Errorf("invalid teal_compile_network in config: %w", err)
	}

	// Validate algod map keys are valid context tokens.
	for network := range config.Algod {
		if err := apconfig.ValidateNetworkID(network); err != nil {
			return ServerConfig{}, fmt.Errorf("invalid network in algod config: %w", err)
		}
	}
	if _, err := apconfig.NewGenesisHashNetworkResolver(config.GenesisHashNetworks); err != nil {
		return ServerConfig{}, fmt.Errorf("invalid network genesis_hash: %w", err)
	}

	sshDefaults := defaults.Endpoint.SSH
	config.Endpoint.SSH.ListenAddress = strings.TrimSpace(config.Endpoint.SSH.ListenAddress)
	if config.Endpoint.SSH.ListenAddress == "" {
		config.Endpoint.SSH.ListenAddress = sshDefaults.ListenAddress
	}
	if err := ValidateSSHListenAddress(config.Endpoint.SSH.ListenAddress); err != nil {
		return ServerConfig{}, fmt.Errorf("invalid endpoint.ssh.listen_address in config: %w", err)
	}
	if config.Endpoint.SSH.Port == 0 {
		config.Endpoint.SSH.Port = sshDefaults.Port
	}
	if config.Endpoint.SSH.HostKeyPath == "" {
		config.Endpoint.SSH.HostKeyPath = sshDefaults.HostKeyPath
	}
	if config.Endpoint.SSH.AuthorizedKeysPath == "" {
		config.Endpoint.SSH.AuthorizedKeysPath = sshDefaults.AuthorizedKeysPath
	}
	config.Endpoint.AdvertiseURL = strings.TrimRight(strings.TrimSpace(config.Endpoint.AdvertiseURL), "/")
	if config.Endpoint.AdvertiseURL != "" {
		if err := endpointrefs.ValidatePortableURL(config.Endpoint.AdvertiseURL); err != nil {
			return ServerConfig{}, fmt.Errorf("invalid endpoint.advertise_url in config: %w", err)
		}
	}
	// Resolve relative SSH paths to absolute paths.
	config.Endpoint.SSH.HostKeyPath = apconfig.ResolvePath(config.Endpoint.SSH.HostKeyPath, dataDir)
	config.Endpoint.SSH.AuthorizedKeysPath = apconfig.ResolvePath(config.Endpoint.SSH.AuthorizedKeysPath, dataDir)

	// Resolve relative paths in passphrase_command_argv against the data directory.
	// All elements (binary and arguments) use the same resolution logic.
	for i := range config.PassphraseCommandArgv {
		config.PassphraseCommandArgv[i] = apconfig.ResolvePath(config.PassphraseCommandArgv[i], dataDir)
	}

	return config, nil
}

// GetAlgodConfig returns the algod settings for the specified network.
func (c *ServerConfig) GetAlgodConfig(network string) (*apconfig.AlgodNetworkConfig, error) {
	return c.Algod.GetNetwork(network)
}

// GetTEALCompileAlgod returns the algod config used for TEAL compilation.
func (c *ServerConfig) GetTEALCompileAlgod() (*apconfig.AlgodNetworkConfig, error) {
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

	if err := apconfig.WriteConfigAtomic(path, out); err != nil {
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
	if disk.Endpoint.SignerPort != startup.Endpoint.SignerPort {
		return true, nil
	}
	if disk.Endpoint.SSH.Port != startup.Endpoint.SSH.Port {
		return true, nil
	}
	if disk.Endpoint.SSH.ListenAddress != startup.Endpoint.SSH.ListenAddress {
		return true, nil
	}
	if disk.Endpoint.AdvertiseURL != startup.Endpoint.AdvertiseURL {
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

func cloneServerStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
