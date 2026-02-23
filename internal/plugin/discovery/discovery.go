// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package discovery handles finding and loading external plugins
package discovery

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/plugin/integrity"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
	"github.com/aplane-algo/aplane/internal/util"
)

// Plugin represents a discovered external plugin
type Plugin struct {
	Dir      string             // Full path to plugin directory
	Manifest *manifest.Manifest // Parsed manifest
}

// Discoverer finds and validates external plugins
type Discoverer struct {
	searchPaths []string
}

// New creates a new plugin discoverer
func New() *Discoverer {
	return &Discoverer{
		searchPaths: getDefaultSearchPaths(),
	}
}

// getDefaultSearchPaths returns the default paths to search for plugins
// Search order: data_dir/plugins -> ./plugins -> /usr/local/lib/aplane/plugins
func getDefaultSearchPaths() []string {
	paths := []string{}

	// Client data dir plugins (APCLIENT_DATA or ~/.aplane)
	if dataDir := util.GetClientDataDir(""); dataDir != "" {
		paths = append(paths, filepath.Join(dataDir, "plugins"))
	}

	// Current directory plugins
	paths = append(paths, "plugins")

	// System-wide plugins
	paths = append(paths, "/usr/local/lib/aplane/plugins")

	return paths
}

// Discover finds all valid plugins in the search paths
func (d *Discoverer) Discover() ([]*Plugin, error) {
	var plugins []*Plugin
	seen := make(map[string]bool) // Track seen plugins by name to avoid duplicates

	for _, searchPath := range d.searchPaths {
		// Skip if path doesn't exist
		if _, err := os.Stat(searchPath); os.IsNotExist(err) {
			continue
		}

		// Find plugins in this search path
		found, err := d.discoverInPath(searchPath)
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

// discoverInPath finds plugins in a specific directory
func (d *Discoverer) discoverInPath(searchPath string) ([]*Plugin, error) {
	var plugins []*Plugin

	entries, err := os.ReadDir(searchPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		pluginDir := filepath.Join(searchPath, entry.Name())

		// Check if entry is a directory (follow symlinks)
		info, err := os.Stat(pluginDir)
		if err != nil || !info.IsDir() {
			continue
		}

		// Try to load the manifest
		manifest, err := manifest.LoadFromDir(pluginDir)
		if err != nil {
			// Not a valid plugin, skip silently
			continue
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
		verifier := integrity.NewVerifier()
		if err := verifier.VerifyPlugin(pluginDir, execToVerify); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: plugin %s failed integrity check: %v\n",
				manifest.Name, err)
			continue
		}

		// Verify executable exists (either in plugin dir or in PATH)
		execPath := manifest.GetExecutablePath(pluginDir)
		if _, err := os.Stat(execPath); os.IsNotExist(err) {
			// If not found in plugin dir, check if it's a system command in PATH
			if _, lookErr := exec.LookPath(manifest.Executable); lookErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: plugin %s executable not found: %s\n",
					manifest.Name, manifest.Executable)
				continue
			}
		}

		plugins = append(plugins, &Plugin{
			Dir:      pluginDir,
			Manifest: manifest,
		})
	}

	return plugins, nil
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
