// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package manifest handles external plugin manifest files
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Command is one command a plugin exposes.
type Command struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Usage       string            `json:"usage,omitempty"`
	Examples    []string          `json:"examples,omitempty"`
	ArgSpecs    []cmdspec.ArgSpec `json:"arg_specs,omitempty"`
}

// load reads and parses a manifest.json file
func load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("failed to parse manifest: unexpected content after the manifest object")
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
		// The shell reads arg_specs with cmdspec.ArgSpecAt, for argument
		// normalization and for completion; this refuses specs it cannot read.
		if err := cmdspec.ValidateArgSpecs(cmd.ArgSpecs, "arg_specs"); err != nil {
			return fmt.Errorf("command[%d] %q: %w", i, cmd.Name, err)
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
