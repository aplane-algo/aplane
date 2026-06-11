// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package identity

import (
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// IdentityConfig holds identity-scoped configuration that may vary
// per identity. Process-global settings (ports, SSH config, theme)
// remain on ServerConfig.
type IdentityConfig struct {
	mu               sync.RWMutex
	userAutoApprove  bool
	lockOnDisconnect bool
	sessionTimeout   time.Duration
	approvalWait     time.Duration
}

// ConfigDefaults contains process-level defaults that an identity overlay can
// inherit at startup.
type ConfigDefaults struct {
	UserAutoApprove  bool
	LockOnDisconnect bool
	SessionTimeout   time.Duration
	ApprovalWait     time.Duration
}

// EffectiveConfig contains the concrete runtime settings for one identity.
type EffectiveConfig struct {
	UserAutoApprove  bool
	LockOnDisconnect bool
	SessionTimeout   time.Duration
	ApprovalWait     time.Duration
}

// StoredConfig is the persisted per-identity configuration overlay.
// Zero values mean "inherit from process-global defaults" except for
// PassphraseTimeout, where an empty string means "inherit".
type StoredConfig struct {
	UserAutoApprove   *bool  `yaml:"user_auto_approve,omitempty"`
	LockOnDisconnect  *bool  `yaml:"lock_on_disconnect,omitempty"`
	PassphraseTimeout string `yaml:"passphrase_timeout,omitempty"`
	ApprovalWait      string `yaml:"approval_wait,omitempty"`
	Mode              string `yaml:"mode,omitempty"`
	Decommissioned    *bool  `yaml:"decommissioned,omitempty"`
}

// NewIdentityConfig creates an identity config with values from the process config.
func NewIdentityConfig(userAutoApprove, lockOnDisconnect bool, sessionTimeout, approvalWait time.Duration) *IdentityConfig {
	if approvalWait <= 0 {
		approvalWait = serverconfig.DefaultApprovalWait
	}
	return &IdentityConfig{
		userAutoApprove:  userAutoApprove,
		lockOnDisconnect: lockOnDisconnect,
		sessionTimeout:   sessionTimeout,
		approvalWait:     approvalWait,
	}
}

// UserAutoApprove returns whether unmatched signing requests skip operator approval.
func (c *IdentityConfig) UserAutoApprove() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.userAutoApprove
}

// SetUserAutoApprove updates whether unmatched signing requests skip operator approval.
func (c *IdentityConfig) SetUserAutoApprove(v bool) {
	c.mu.Lock()
	c.userAutoApprove = v
	c.mu.Unlock()
}

// LockOnDisconnect returns whether the identity should lock when its admin session disconnects.
func (c *IdentityConfig) LockOnDisconnect() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lockOnDisconnect
}

// SetLockOnDisconnect updates the lock-on-disconnect setting.
func (c *IdentityConfig) SetLockOnDisconnect(v bool) {
	c.mu.Lock()
	c.lockOnDisconnect = v
	c.mu.Unlock()
}

// SessionTimeout returns the admin idle disconnect timeout for this identity.
func (c *IdentityConfig) SessionTimeout() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionTimeout
}

// SetSessionTimeout updates the admin idle disconnect timeout.
func (c *IdentityConfig) SetSessionTimeout(d time.Duration) {
	c.mu.Lock()
	c.sessionTimeout = d
	c.mu.Unlock()
}

// ApprovalWait returns the maximum manual signing approval wait for this identity.
func (c *IdentityConfig) ApprovalWait() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.approvalWait
}

// SetApprovalWait updates the manual signing approval wait.
func (c *IdentityConfig) SetApprovalWait(d time.Duration) {
	c.mu.Lock()
	c.approvalWait = d
	c.mu.Unlock()
}

// ConfigPath returns the path to an identity's persisted settings file.
func ConfigPath(dataRoot, identityID string) string {
	return filepath.Join(dataRoot, "identities", identityID, "config.yaml")
}

// LoadStoredConfig reads the per-identity settings overlay.
// Returns an empty config if the file does not exist.
func LoadStoredConfig(dataRoot, identityID string) (*StoredConfig, error) {
	path := ConfigPath(dataRoot, identityID)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &StoredConfig{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read identity config: %w", err)
	}

	var cfg StoredConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse identity config: %w", err)
	}
	return &cfg, nil
}

// SaveStoredSetting writes a single per-identity setting atomically.
func SaveStoredSetting(dataRoot, identityID, key string, value interface{}) error {
	path := ConfigPath(dataRoot, identityID)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create identity config directory: %w", err)
	}

	existing := make(map[string]interface{})
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read identity config: %w", err)
	}
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("failed to parse identity config: %w", err)
		}
	}

	existing[key] = value

	out, err := yaml.Marshal(existing)
	if err != nil {
		return fmt.Errorf("failed to marshal identity config: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return fmt.Errorf("failed to write identity config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("failed to rename identity config: %w", err)
	}
	return nil
}

// Apply returns the effective runtime values after overlaying the stored
// identity settings on top of process-global defaults.
func (c *StoredConfig) Apply(defaults ConfigDefaults) (EffectiveConfig, error) {
	effective := EffectiveConfig(defaults)

	if c.UserAutoApprove != nil {
		effective.UserAutoApprove = *c.UserAutoApprove
	}

	if c.LockOnDisconnect != nil {
		effective.LockOnDisconnect = *c.LockOnDisconnect
	}

	if c.PassphraseTimeout != "" {
		parsed, err := serverconfig.ParsePassphraseTimeout(c.PassphraseTimeout)
		if err != nil {
			return EffectiveConfig{}, fmt.Errorf("invalid identity passphrase_timeout: %w", err)
		}
		effective.SessionTimeout = parsed
	}

	if c.ApprovalWait != "" {
		parsed, err := serverconfig.ParseApprovalWait(c.ApprovalWait)
		if err != nil {
			return EffectiveConfig{}, fmt.Errorf("invalid identity approval_wait: %w", err)
		}
		effective.ApprovalWait = parsed
	}

	if c.Mode != "" {
		return EffectiveConfig{}, fmt.Errorf("identity config mode is unsupported in this release; use root node.yaml role")
	}

	return effective, nil
}

// IsDecommissioned reports whether the stored config marks the identity as disabled.
func (c *StoredConfig) IsDecommissioned() bool {
	return c != nil && c.Decommissioned != nil && *c.Decommissioned
}
