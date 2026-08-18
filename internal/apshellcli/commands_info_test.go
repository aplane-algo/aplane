// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/plugin/integrity"
)

func TestCmdHelpIncludesDiscoveredPluginCommands(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("APCLIENT_DATA", dataDir)
	createHelpPlugin(t, dataDir, `{
  "name": "reti-plugin",
  "version": "1.0.0",
  "description": "Reti integration",
  "executable": "reti-plugin.sh",
  "commands": [{
    "name": "reti",
    "description": "Interact with Reti staking pools",
    "usage": "reti validator <validator_id>",
    "examples": ["reti validator 1"]
  }],
  "networks": ["testnet", "mainnet"],
  "manifest_format": "2.0"
}`)

	state := newHelpTestState(t, dataDir)
	var out bytes.Buffer
	state.SetOutput(&out)

	if err := state.runHelp(nil, nil); err != nil {
		t.Fatalf("cmdHelp() error = %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "Plugins:") {
		t.Fatalf("help output missing plugin section:\n%s", got)
	}
	if !strings.Contains(got, "reti-plugin") {
		t.Fatalf("help output missing plugin name:\n%s", got)
	}
	if !strings.Contains(got, "help <plugin>") {
		t.Fatalf("help output missing plugin help hint:\n%s", got)
	}
}

func TestCmdHelpShowsDetailedPluginCommandHelp(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("APCLIENT_DATA", dataDir)
	createHelpPlugin(t, dataDir, `{
  "name": "reti-plugin",
  "version": "1.0.0",
  "description": "Reti integration",
  "executable": "reti-plugin.sh",
  "commands": [{
    "name": "reti",
    "description": "Interact with Reti staking pools",
    "usage": "reti validator <validator_id>",
    "examples": ["reti validator 1", "reti validator 25"]
  }],
  "networks": ["testnet", "mainnet"],
  "manifest_format": "2.0"
}`)

	state := newHelpTestState(t, dataDir)
	var out bytes.Buffer
	state.SetOutput(&out)

	if err := state.runHelp([]string{"reti"}, nil); err != nil {
		t.Fatalf("cmdHelp(reti) error = %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "Command: reti") {
		t.Fatalf("detailed help missing command header:\n%s", got)
	}
	if !strings.Contains(got, "Type: External Plugin") {
		t.Fatalf("detailed help missing plugin type:\n%s", got)
	}
	if !strings.Contains(got, "Examples:") || !strings.Contains(got, "reti validator 1") {
		t.Fatalf("detailed help missing plugin examples:\n%s", got)
	}
	if !strings.Contains(got, "Networks:") || !strings.Contains(got, "testnet, mainnet") {
		t.Fatalf("detailed help missing plugin networks:\n%s", got)
	}
}

func newHelpTestState(t *testing.T, dataDir string) *REPLState {
	t.Helper()

	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	state := &REPLState{
		App:             apshellapp.New(eng, config.DefaultConfig(), dataDir),
		DataDir:         dataDir,
		Config:          config.DefaultConfig(),
		CommandRegistry: nil,
	}
	state.CommandRegistry = state.initCommandRegistry()
	if err := initPluginRuntime(state); err != nil {
		t.Fatalf("initPluginRuntime() error = %v", err)
	}
	return state
}

func createHelpPlugin(t *testing.T, dataDir, manifestJSON string) {
	t.Helper()

	pluginDir := filepath.Join(dataDir, "plugins.available", "reti-plugin")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", pluginDir, err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "plugins.yaml"), []byte("enabled_plugins:\n  - reti-plugin\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(plugins.yaml) error = %v", err)
	}

	execName := "reti-plugin.sh"
	execPath := filepath.Join(pluginDir, execName)
	if err := os.WriteFile(execPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", execPath, err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifestJSON), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest.json) error = %v", err)
	}

	checksums, err := integrity.GenerateChecksums(pluginDir, []string{"manifest.json", execName})
	if err != nil {
		t.Fatalf("GenerateChecksums(%s) error = %v", pluginDir, err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "checksums.sha256"), []byte(checksums), 0o644); err != nil {
		t.Fatalf("WriteFile(checksums.sha256) error = %v", err)
	}
}
