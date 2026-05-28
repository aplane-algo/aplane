// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package discovery handles finding and loading external plugins
package discovery

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/config"
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
	searchPaths   []string
	enabledByPath map[string][]string
	dataDir       string
}

type activationConfig struct {
	EnabledPlugins []string `yaml:"enabled_plugins"`
}

// New creates a new plugin discoverer
func New() *Discoverer {
	return NewWithDataDir(config.GetClientDataDir(""))
}

// NewWithDataDir creates a plugin discoverer for a specific apshell data dir.
func NewWithDataDir(dataDir string) *Discoverer {
	if dataDir == "" {
		return &Discoverer{}
	}

	availablePath := filepath.Join(dataDir, AvailableDirName)
	return &Discoverer{
		searchPaths: []string{availablePath},
		dataDir:     dataDir,
	}
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

// Discover finds all valid plugins in the search paths
func (d *Discoverer) Discover() ([]*Plugin, error) {
	enabledByPath := d.enabledByPath
	if d.dataDir != "" {
		enabled, err := loadEnabledPluginNames(d.dataDir)
		if err != nil {
			return nil, err
		}
		enabledByPath = map[string][]string{
			filepath.Join(d.dataDir, AvailableDirName): enabled,
		}
	}

	var plugins []*Plugin
	seen := make(map[string]bool) // Track seen plugins by name to avoid duplicates

	for _, searchPath := range d.searchPaths {
		enabled, configuredPath := enabledByPath[searchPath]

		// Skip missing legacy scan paths. Configured catalog paths are still
		// checked per enabled plugin so missing enabled entries produce warnings.
		if _, err := os.Stat(searchPath); os.IsNotExist(err) && !configuredPath {
			continue
		}

		// Find plugins in this search path.
		var found []*Plugin
		var err error
		if configuredPath {
			found, err = d.discoverEnabledInPath(searchPath, enabled)
		} else {
			found, err = d.discoverInPath(searchPath)
		}
		if err != nil {
			// Log error but continue with other paths
			fmt.Fprintf(os.Stderr, "Warning: error searching %s: %v\n", searchPath, err)
			continue
		}

		// Add plugins, avoiding duplicates (first found wins)
		for _, plugin := range found {
			if !seen[plugin.Manifest.Name] {
				plugins = append(plugins, plugin)
				seen[plugin.Manifest.Name] = true
			}
		}
	}

	return plugins, nil
}

func (d *Discoverer) discoverEnabledInPath(searchPath string, enabled []string) ([]*Plugin, error) {
	var plugins []*Plugin

	for _, name := range enabled {
		pluginDir := filepath.Join(searchPath, name)
		plugin, err := d.loadPluginDir(pluginDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: enabled plugin %s skipped: %v\n", name, err)
			continue
		}
		plugins = append(plugins, plugin)
	}

	return plugins, nil
}

// discoverInPath finds plugins in a specific directory
func (d *Discoverer) discoverInPath(searchPath string) ([]*Plugin, error) {
	var plugins []*Plugin

	entries, err := os.ReadDir(searchPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		pluginDir := filepath.Join(searchPath, entry.Name())

		plugin, err := d.loadPluginDir(pluginDir)
		if err != nil {
			// Not a valid plugin, skip silently
			continue
		}
		plugins = append(plugins, plugin)
	}

	return plugins, nil
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

// FindByName finds a specific plugin by name
func (d *Discoverer) FindByName(name string) (*Plugin, error) {
	plugins, err := d.Discover()
	if err != nil {
		return nil, err
	}

	for _, plugin := range plugins {
		if plugin.Manifest.Name == name {
			return plugin, nil
		}
	}

	return nil, fmt.Errorf("plugin not found: %s", name)
}

// FindByCommand finds plugins that provide a specific command
func (d *Discoverer) FindByCommand(command string) ([]*Plugin, error) {
	plugins, err := d.Discover()
	if err != nil {
		return nil, err
	}

	var matches []*Plugin
	for _, plugin := range plugins {
		if plugin.Manifest.FindCommand(command) != nil {
			matches = append(matches, plugin)
		}
	}

	return matches, nil
}

// ListCommands returns all available commands from all plugins
func (d *Discoverer) ListCommands() (map[string][]*Plugin, error) {
	plugins, err := d.Discover()
	if err != nil {
		return nil, err
	}

	commands := make(map[string][]*Plugin)

	for _, plugin := range plugins {
		for _, cmd := range plugin.Manifest.Commands {
			commands[cmd.Name] = append(commands[cmd.Name], plugin)
		}
	}

	return commands, nil
}

// GetPluginInfo returns a formatted string with plugin information
func (p *Plugin) GetPluginInfo() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Plugin: %s v%s\n", p.Manifest.Name, p.Manifest.Version))
	sb.WriteString(fmt.Sprintf("Description: %s\n", p.Manifest.Description))

	if p.Manifest.Author != "" {
		sb.WriteString(fmt.Sprintf("Author: %s\n", p.Manifest.Author))
	}

	if len(p.Manifest.Networks) > 0 {
		sb.WriteString(fmt.Sprintf("Networks: %s\n", strings.Join(p.Manifest.Networks, ", ")))
	}

	sb.WriteString("Commands:\n")
	for _, cmd := range p.Manifest.Commands {
		sb.WriteString(fmt.Sprintf("  - %s: %s\n", cmd.Name, cmd.Description))
		if cmd.Usage != "" {
			sb.WriteString(fmt.Sprintf("    Usage: %s\n", cmd.Usage))
		}
	}

	return sb.String()
}
