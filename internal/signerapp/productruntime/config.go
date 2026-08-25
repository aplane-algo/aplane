// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"gopkg.in/yaml.v3"
)

// RuntimeConfig holds mutable settings for the product runtime. Process-global
// settings (ports, SSH config, theme) remain on ServerConfig.
type RuntimeConfig struct {
	mu               sync.RWMutex
	userAutoApprove  bool
	lockOnDisconnect bool
	sessionTimeout   time.Duration
	approvalWait     time.Duration
}

// ConfigDefaults contains process-level defaults that the product overlay can
// inherit at startup.
type ConfigDefaults struct {
	UserAutoApprove  bool
	LockOnDisconnect bool
	SessionTimeout   time.Duration
	ApprovalWait     time.Duration
}

// EffectiveConfig contains the concrete product runtime settings.
type EffectiveConfig struct {
	UserAutoApprove  bool
	LockOnDisconnect bool
	SessionTimeout   time.Duration
	ApprovalWait     time.Duration
}

// StoredConfig is the persisted product runtime configuration overlay.
// Zero values mean "inherit from process-global defaults" except for
// PassphraseTimeout, where an empty string means "inherit".
type StoredConfig struct {
	UserAutoApprove   *bool  `yaml:"user_auto_approve,omitempty"`
	LockOnDisconnect  *bool  `yaml:"lock_on_disconnect,omitempty"`
	PassphraseTimeout string `yaml:"passphrase_timeout,omitempty"`
	ApprovalWait      string `yaml:"approval_wait,omitempty"`
	Mode              string `yaml:"mode,omitempty"`
}

// NewRuntimeConfig creates runtime settings from the process config.
func NewRuntimeConfig(userAutoApprove, lockOnDisconnect bool, sessionTimeout, approvalWait time.Duration) *RuntimeConfig {
	if approvalWait <= 0 {
		approvalWait = serverconfig.DefaultApprovalWait
	}
	return &RuntimeConfig{
		userAutoApprove:  userAutoApprove,
		lockOnDisconnect: lockOnDisconnect,
		sessionTimeout:   sessionTimeout,
		approvalWait:     approvalWait,
	}
}

// UserAutoApprove returns whether unmatched signing requests skip operator approval.
func (c *RuntimeConfig) UserAutoApprove() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.userAutoApprove
}

// SetUserAutoApprove updates whether unmatched signing requests skip operator approval.
func (c *RuntimeConfig) SetUserAutoApprove(v bool) {
	c.mu.Lock()
	c.userAutoApprove = v
	c.mu.Unlock()
}

// LockOnDisconnect returns whether the product runtime should lock when its admin session disconnects.
func (c *RuntimeConfig) LockOnDisconnect() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lockOnDisconnect
}

// SetLockOnDisconnect updates the lock-on-disconnect setting.
func (c *RuntimeConfig) SetLockOnDisconnect(v bool) {
	c.mu.Lock()
	c.lockOnDisconnect = v
	c.mu.Unlock()
}

// SessionTimeout returns the product admin idle disconnect timeout.
func (c *RuntimeConfig) SessionTimeout() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionTimeout
}

// SetSessionTimeout updates the admin idle disconnect timeout.
func (c *RuntimeConfig) SetSessionTimeout(d time.Duration) {
	c.mu.Lock()
	c.sessionTimeout = d
	c.mu.Unlock()
}

// ApprovalWait returns the product's maximum manual signing approval wait.
func (c *RuntimeConfig) ApprovalWait() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.approvalWait
}

// SetApprovalWait updates the manual signing approval wait.
func (c *RuntimeConfig) SetApprovalWait(d time.Duration) {
	c.mu.Lock()
	c.approvalWait = d
	c.mu.Unlock()
}

// ConfigPath returns the path to the product runtime's persisted settings file.
func ConfigPath(dataRoot string) string {
	return filepath.Join(storepaths.NewPaths(dataRoot).ProductDir(), "config.yaml")
}

// LoadStoredConfig reads the product runtime settings overlay.
// Returns an empty config if the file does not exist.
func LoadStoredConfig(dataRoot string) (*StoredConfig, error) {
	path := ConfigPath(dataRoot)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &StoredConfig{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read runtime config: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return &StoredConfig{}, nil
	}

	var cfg StoredConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to parse runtime config: %w", err)
	}
	return &cfg, nil
}

// SaveStoredSetting writes a single product runtime setting atomically.
func SaveStoredSetting(dataRoot, key string, value interface{}) error {
	path := ConfigPath(dataRoot)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create runtime config directory: %w", err)
	}

	existing := make(map[string]interface{})
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read runtime config: %w", err)
	}
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("failed to parse runtime config: %w", err)
		}
	}

	existing[key] = value

	out, err := yaml.Marshal(existing)
	if err != nil {
		return fmt.Errorf("failed to marshal runtime config: %w", err)
	}

	if err := fsutil.WriteFileDurableWithProfile(path, out, fsutil.PrivateStoreFileProfile); err != nil {
		return fmt.Errorf("failed to write runtime config: %w", err)
	}
	return nil
}

// Apply returns the effective runtime values after overlaying the stored
// product settings on top of process-global defaults.
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
			return EffectiveConfig{}, fmt.Errorf("invalid runtime passphrase_timeout: %w", err)
		}
		effective.SessionTimeout = parsed
	}

	if c.ApprovalWait != "" {
		parsed, err := serverconfig.ParseApprovalWait(c.ApprovalWait)
		if err != nil {
			return EffectiveConfig{}, fmt.Errorf("invalid runtime approval_wait: %w", err)
		}
		effective.ApprovalWait = parsed
	}

	if c.Mode != "" {
		return EffectiveConfig{}, fmt.Errorf("runtime config mode is unsupported in this release; use root node.yaml role")
	}

	return effective, nil
}
