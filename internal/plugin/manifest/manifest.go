// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

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
	Commands  []Command  `json:"commands"`            // Legacy command interface
	Functions []Function `json:"functions,omitempty"` // Typed JS function interface
	Networks  []string   `json:"networks,omitempty"`  // testnet, mainnet, betanet

	// Resource limits
	Timeout int `json:"timeout,omitempty"` // seconds, default 30

	// Protocol version
	ProtocolVersion string `json:"protocol_version"` // "1.0"
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

// FunctionParam describes a parameter for a typed plugin function
type FunctionParam struct {
	Name        string `json:"name"`                  // Parameter name (e.g., "addr")
	Type        string `json:"type"`                  // Type: "string", "number", "address", "asset"
	Description string `json:"description,omitempty"` // Human-readable description
}

// Function represents a typed JavaScript function exposed by the plugin.
// These get auto-generated as first-class JS functions with proper typing.
type Function struct {
	Name        string          `json:"name"`        // JS function name
	Description string          `json:"description"` // What the function does
	Params      []FunctionParam `json:"params"`      // Function parameters
	Returns     string          `json:"returns"`     // Return type description for AI
	Command     []string        `json:"command"`     // Plugin command args (use $paramName for substitution)
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

	// Note: Function-only plugins are not yet supported because typed function
	// wrappers are not registered in the JS runtime. Once registerTypedPluginFunction
	// is implemented (see ARCH_AI_SCRIPTING.md), change this to allow functions OR commands.
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

	if m.ProtocolVersion == "" {
		m.ProtocolVersion = "1.0"
	}

	// Set defaults
	if m.Timeout == 0 {
		m.Timeout = 30
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
