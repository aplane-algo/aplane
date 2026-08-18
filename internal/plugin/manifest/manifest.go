// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package manifest handles external plugin manifest files
package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/cmdspec"
)

const CurrentManifestFormat = "2.0"

// Manifest represents an external plugin's manifest.json
type Manifest struct {
	// Basic metadata
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Author      string `json:"author,omitempty"`
	Homepage    string `json:"homepage,omitempty"`

	// Executable information
	Executable string   `json:"executable"`
	Args       []string `json:"args,omitempty"`

	// Capabilities and permissions
	Commands []Command `json:"commands"`           // Executable command interface
	Networks []string  `json:"networks,omitempty"` // Network context tokens

	// Resource limits
	Timeout int `json:"timeout,omitempty"` // seconds, default 30

	// Manifest schema format.
	ManifestFormat string `json:"manifest_format,omitempty"`
}

// Command represents a command exposed by the plugin (legacy interface)
type Command struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Usage       string            `json:"usage,omitempty"`
	Examples    []string          `json:"examples,omitempty"`
	Returns     string            `json:"returns,omitempty"`  // Documents return data structure for AI
	Category    string            `json:"category,omitempty"` // "defi", "utility", etc.
	ArgSpecs    []cmdspec.ArgSpec `json:"arg_specs,omitempty"`
}

// load reads and parses a manifest.json file
func load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}
	if err := rejectRetiredManifestFields(data); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	return &m, nil
}

// LoadFromDir loads manifest.json from a plugin directory
func LoadFromDir(dir string) (*Manifest, error) {
	manifestPath := filepath.Join(dir, "manifest.json")
	return load(manifestPath)
}

// Validate checks if the manifest has all required fields and valid values
func (m *Manifest) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("name is required")
	}

	if m.Version == "" {
		return fmt.Errorf("version is required")
	}

	if m.Description == "" {
		return fmt.Errorf("description is required")
	}

	if m.Executable == "" {
		return fmt.Errorf("executable is required")
	}

	if err := m.normalizeManifestFormat(); err != nil {
		return err
	}

	if len(m.Commands) == 0 {
		return fmt.Errorf("at least one command is required")
	}

	for i, cmd := range m.Commands {
		if cmd.Name == "" {
			return fmt.Errorf("command[%d]: name is required", i)
		}
		if cmd.Description == "" {
			return fmt.Errorf("command[%d]: description is required", i)
		}
	}

	// Set defaults
	if m.Timeout < 0 {
		return fmt.Errorf("timeout must be non-negative")
	}
	if m.Timeout == 0 {
		m.Timeout = 30
	}

	return nil
}

func (m *Manifest) normalizeManifestFormat() error {
	if m.ManifestFormat == "" {
		m.ManifestFormat = CurrentManifestFormat
	}
	if m.ManifestFormat != CurrentManifestFormat {
		return fmt.Errorf("unsupported manifest_format %q", m.ManifestFormat)
	}
	return nil
}

func rejectRetiredManifestFields(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, ok := fields["protocol_version"]; ok {
		return fmt.Errorf("protocol_version is no longer supported; use manifest_format")
	}
	if _, ok := fields["functions"]; ok {
		return fmt.Errorf("functions is no longer supported in manifest_format 2.0; expose executable commands only")
	}
	return nil
}

// GetExecutablePath returns the full path to the plugin executable
func (m *Manifest) GetExecutablePath(pluginDir string) string {
	if filepath.IsAbs(m.Executable) {
		return m.Executable
	}

	// First check if executable exists in plugin directory
	localPath := filepath.Join(pluginDir, m.Executable)
	if _, err := os.Stat(localPath); err == nil {
		return localPath
	}

	// If not found locally, check if it's a system command in PATH
	if path, err := exec.LookPath(m.Executable); err == nil {
		return path
	}

	// Fallback to local path (will fail later with appropriate error)
	return localPath
}

// SupportsNetwork checks if the plugin supports a given network
func (m *Manifest) SupportsNetwork(network string) bool {
	if len(m.Networks) == 0 {
		// No restriction, supports all networks
		return true
	}

	for _, n := range m.Networks {
		if n == network {
			return true
		}
	}

	return false
}

// FindCommand searches for a command by name
func (m *Manifest) FindCommand(name string) *Command {
	for _, cmd := range m.Commands {
		if cmd.Name == name {
			return &cmd
		}
	}
	return nil
}
