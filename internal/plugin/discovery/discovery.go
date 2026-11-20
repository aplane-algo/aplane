// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package discovery handles finding and loading external plugins
package discovery

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/plugin/integrity"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
	"gopkg.in/yaml.v3"
)

const (
	// AvailableDirName is the client-data plugin catalog directory. Plugins in
	// this directory are loadable only when named in ActivationConfigName.
	AvailableDirName = "plugins.available"

	// ActivationConfigName records which catalog plugins are enabled.
	ActivationConfigName = "plugins.yaml"
)

// Plugin represents a discovered external plugin
type Plugin struct {
	Dir      string             // Full path to plugin directory
	Manifest *manifest.Manifest // Parsed manifest
}

// Discoverer finds and validates external plugins
type Discoverer struct {
	dataDir string
}

type activationConfig struct {
	EnabledPlugins []string `yaml:"enabled_plugins"`
}

// NewWithDataDir creates a plugin discoverer for a specific apshell data dir.
func NewWithDataDir(dataDir string) *Discoverer {
	return &Discoverer{dataDir: dataDir}
}

func loadEnabledPluginNames(dataDir string) ([]string, error) {
	configPath := filepath.Join(dataDir, ActivationConfigName)
	data, err := os.ReadFile(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load plugin activation config %s: %w", configPath, err)
	}

	var cfg activationConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse plugin activation config %s: %w", configPath, err)
	}

	seen := make(map[string]bool, len(cfg.EnabledPlugins))
	enabled := make([]string, 0, len(cfg.EnabledPlugins))
	for _, name := range cfg.EnabledPlugins {
		if err := validateEnabledPluginName(name); err != nil {
			return nil, fmt.Errorf("invalid enabled plugin name %q in %s: %w", name, configPath, err)
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		enabled = append(enabled, name)
	}

	return enabled, nil
}

func validateEnabledPluginName(name string) error {
	if name == "" {
		return fmt.Errorf("name is empty")
	}
	if name == "." || name == ".." || filepath.Clean(name) != name {
		return fmt.Errorf("name must be a single directory name")
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("name must not contain path separators")
	}
	return nil
}

// Discover loads the plugins plugins.yaml enables from the plugins.available
// catalog. An enabled plugin that fails to load is skipped with a warning; when
// two share a manifest name, the first enabled wins.
func (d *Discoverer) Discover() ([]*Plugin, error) {
	if d.dataDir == "" {
		return nil, nil
	}
	enabled, err := loadEnabledPluginNames(d.dataDir)
	if err != nil {
		return nil, err
	}

	catalog := filepath.Join(d.dataDir, AvailableDirName)
	var plugins []*Plugin
	seen := make(map[string]bool, len(enabled))
	for _, name := range enabled {
		plugin, err := d.loadPluginDir(filepath.Join(catalog, name))
		if err != nil {
			logger().Warn("enabled plugin skipped", "name", name, "error", err)
			continue
		}
		if seen[plugin.Manifest.Name] {
			continue
		}
		seen[plugin.Manifest.Name] = true
		plugins = append(plugins, plugin)
	}
	return plugins, nil
}

// logger returns the discovery logger. It is made at each call, because a logger
// kept from package initialization would miss the handler the host installs. The
// component "plugin" is reserved for what plugins themselves print.
func logger() *slog.Logger {
	return slog.With("component", "plugins")
}

func (d *Discoverer) loadPluginDir(pluginDir string) (*Plugin, error) {
	// Reject symlinks; plugin discovery should only traverse real directories
	// in the configured search paths.
	info, err := os.Lstat(pluginDir)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("plugin directory must not be a symlink")
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("plugin path is not a directory")
	}

	verifier := integrity.NewVerifier()
	if err := verifier.VerifyManifest(pluginDir); err != nil {
		return nil, fmt.Errorf("integrity check failed: %w", err)
	}

	// Try to load the manifest
	manifest, err := manifest.LoadFromDir(pluginDir)
	if err != nil {
		return nil, err
	}

	// Verify plugin integrity (mandatory)
	// Determine which file to verify as the "executable"
	execToVerify := manifest.Executable
	localExecPath := filepath.Join(pluginDir, manifest.Executable)
	if _, err := os.Stat(localExecPath); os.IsNotExist(err) {
		// Executable is a system command (node, python, etc.) - verify first arg instead
		if len(manifest.Args) > 0 {
			execToVerify = manifest.Args[0]
		}
	}
	if err := verifier.VerifyPlugin(pluginDir, execToVerify); err != nil {
		return nil, fmt.Errorf("integrity check failed: %w", err)
	}

	// Verify executable exists (either in plugin dir or in PATH)
	execPath := manifest.GetExecutablePath(pluginDir)
	if _, err := os.Stat(execPath); os.IsNotExist(err) {
		// If not found in plugin dir, check if it's a system command in PATH
		if _, lookErr := exec.LookPath(manifest.Executable); lookErr != nil {
			return nil, fmt.Errorf("executable not found: %s", manifest.Executable)
		}
	}

	return &Plugin{
		Dir:      pluginDir,
		Manifest: manifest,
	}, nil
}
