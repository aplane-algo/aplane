// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package discovery

import (
	"bytes"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/plugin/integrity"
)

func TestDiscoverInPathSkipsSymlinkEntries(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}
	link := filepath.Join(root, "linked-plugin")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	d := New()
	plugins, err := d.discoverInPath(root)
	if err != nil {
		t.Fatalf("discoverInPath() error = %v", err)
	}
	if len(plugins) != 0 {
		t.Fatalf("discoverInPath() = %#v, want symlink skipped", plugins)
	}
}

func TestDiscoverUsesActivationConfigAndAvailableCatalog(t *testing.T) {
	dataDir := t.TempDir()
	availableDir := filepath.Join(dataDir, AvailableDirName)
	if err := os.MkdirAll(availableDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", availableDir, err)
	}

	createDiscoveryPlugin(t, availableDir, "alpha", "swap", "alpha")
	createDiscoveryPlugin(t, availableDir, "beta", "lend", "beta")
	if err := os.WriteFile(filepath.Join(dataDir, ActivationConfigName), []byte("enabled_plugins:\n  - beta\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", ActivationConfigName, err)
	}

	plugins, err := NewWithDataDir(dataDir).Discover()
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	got := discoveredPluginSummaries(plugins)
	want := []string{"beta:lend"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Discover() = %#v, want %#v", got, want)
	}
}

func TestDiscoverWithoutActivationConfigDoesNotLoadCatalogPlugins(t *testing.T) {
	dataDir := t.TempDir()
	availableDir := filepath.Join(dataDir, AvailableDirName)
	if err := os.MkdirAll(availableDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", availableDir, err)
	}
	createDiscoveryPlugin(t, availableDir, "alpha", "swap", "alpha")

	plugins, err := NewWithDataDir(dataDir).Discover()
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(plugins) != 0 {
		t.Fatalf("Discover() = %#v, want no plugins without %s", plugins, ActivationConfigName)
	}
}

func TestDiscoverRejectsInvalidActivationPluginName(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, ActivationConfigName), []byte("enabled_plugins:\n  - ../reti\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", ActivationConfigName, err)
	}

	_, err := NewWithDataDir(dataDir).Discover()
	if err == nil {
		t.Fatalf("Discover() error = nil, want invalid enabled plugin name error")
	}
}

func TestDiscoverMixedPathsDeterministicallyFiltersInvalidAndDuplicatePlugins(t *testing.T) {
	root := t.TempDir()
	pathA := filepath.Join(root, "path-a")
	pathB := filepath.Join(root, "path-b")
	for _, dir := range []string{pathA, pathB} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll(%s) error = %v", dir, err)
		}
	}

	createDiscoveryPlugin(t, pathA, "alpha", "swap", "alpha-a")
	createMalformedDiscoveryPlugin(t, pathA, "broken-json")
	createChecksumMismatchDiscoveryPlugin(t, pathA, "bad-checksum", "broken")

	createDiscoveryPlugin(t, pathB, "alpha", "ignored-duplicate", "alpha-b")
	createDiscoveryPlugin(t, pathB, "beta", "lend", "beta")

	d := &Discoverer{searchPaths: []string{pathA, pathB}}

	first, err := d.Discover()
	if err != nil {
		t.Fatalf("Discover() first error = %v", err)
	}
	second, err := d.Discover()
	if err != nil {
		t.Fatalf("Discover() second error = %v", err)
	}

	gotFirst := discoveredPluginSummaries(first)
	gotSecond := discoveredPluginSummaries(second)
	want := []string{
		"alpha:swap",
		"beta:lend",
	}

	if !reflect.DeepEqual(gotFirst, want) {
		t.Fatalf("first Discover() = %#v, want %#v", gotFirst, want)
	}
	if !reflect.DeepEqual(gotSecond, want) {
		t.Fatalf("second Discover() = %#v, want %#v", gotSecond, want)
	}
}

func createDiscoveryPlugin(t *testing.T, searchPath, name, commandName, executableBody string) {
	t.Helper()

	pluginDir := filepath.Join(searchPath, name)
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", pluginDir, err)
	}

	execName := name + ".sh"
	execPath := filepath.Join(pluginDir, execName)
	if err := os.WriteFile(execPath, []byte("#!/bin/sh\n# "+executableBody+"\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", execPath, err)
	}

	manifestJSON := `{
  "name": "` + name + `",
  "version": "1.0.0",
  "description": "test plugin",
  "executable": "` + execName + `",
  "commands": [{"name": "` + commandName + `", "description": "cmd"}],
  "manifest_format": "2.0"
}`
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifestJSON), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}

	checksums, err := integrity.GenerateChecksums(pluginDir, []string{"manifest.json", execName})
	if err != nil {
		t.Fatalf("GenerateChecksums(%s) error = %v", pluginDir, err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "checksums.sha256"), []byte(checksums), 0o644); err != nil {
		t.Fatalf("WriteFile(checksums) error = %v", err)
	}
}

func createMalformedDiscoveryPlugin(t *testing.T, searchPath, name string) {
	t.Helper()

	pluginDir := filepath.Join(searchPath, name)
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", pluginDir, err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte("{invalid json"), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
}

func createChecksumMismatchDiscoveryPlugin(t *testing.T, searchPath, name, commandName string) {
	t.Helper()

	pluginDir := filepath.Join(searchPath, name)
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", pluginDir, err)
	}

	execName := name + ".sh"
	if err := os.WriteFile(filepath.Join(pluginDir, execName), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(executable) error = %v", err)
	}

	manifestJSON := `{
  "name": "` + name + `",
  "version": "1.0.0",
  "description": "bad checksum plugin",
  "executable": "` + execName + `",
  "commands": [{"name": "` + commandName + `", "description": "cmd"}],
  "manifest_format": "2.0"
}`
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifestJSON), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}

	badChecksums := "0000000000000000000000000000000000000000000000000000000000000000  " + execName + "\n"
	if err := os.WriteFile(filepath.Join(pluginDir, "checksums.sha256"), []byte(badChecksums), 0o644); err != nil {
		t.Fatalf("WriteFile(checksums) error = %v", err)
	}
}

func discoveredPluginSummaries(plugins []*Plugin) []string {
	summaries := make([]string, 0, len(plugins))
	for _, plugin := range plugins {
		command := ""
		if len(plugin.Manifest.Commands) > 0 {
			command = plugin.Manifest.Commands[0].Name
		}
		summaries = append(summaries, plugin.Manifest.Name+":"+command)
	}
	return summaries
}

func TestSkippedPluginIsLoggedAsAWarning(t *testing.T) {
	previous := slog.Default()
	flags := log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	})
	var out bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, nil)))

	d := New()
	if _, err := d.discoverEnabledInPath(t.TempDir(), []string{"missing-plugin"}); err != nil {
		t.Fatalf("discoverEnabledInPath() error = %v", err)
	}

	got := out.String()
	for _, want := range []string{"level=WARN", "component=plugins", "name=missing-plugin"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log = %q, want %q", got, want)
		}
	}
}

// TestPluginWithUnreadableArgSpecsIsNotLoaded installs an enabled plugin
// whose arg_specs branch names a negative argument index, next to a good
// one. Discovery leaves it out and warns with the reason, as for any other
// manifest error, so neither argument normalization nor completion ever sees
// those specs.
func TestPluginWithUnreadableArgSpecsIsNotLoaded(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	var out bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, nil)))

	dataDir := t.TempDir()
	availableDir := filepath.Join(dataDir, AvailableDirName)
	createDiscoveryPlugin(t, availableDir, "good", "swap", "good")
	pluginDir := filepath.Join(availableDir, "bad")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", pluginDir, err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "bad.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(executable) error = %v", err)
	}
	manifestJSON := `{
  "name": "bad",
  "version": "1.0.0",
  "description": "plugin with a negative branch index",
  "executable": "bad.sh",
  "commands": [{"name": "lend", "description": "cmd", "arg_specs": [
    {"branches": [{"when": {"arg": -1, "matches": "^x$"}, "specs": [{"type": "address"}]}]}
  ]}],
  "manifest_format": "2.0"
}`
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifestJSON), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	checksums, err := integrity.GenerateChecksums(pluginDir, []string{"manifest.json", "bad.sh"})
	if err != nil {
		t.Fatalf("GenerateChecksums() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "checksums.sha256"), []byte(checksums), 0o644); err != nil {
		t.Fatalf("WriteFile(checksums) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, ActivationConfigName), []byte("enabled_plugins:\n  - bad\n  - good\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", ActivationConfigName, err)
	}

	plugins, err := NewWithDataDir(dataDir).Discover()
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got, want := discoveredPluginSummaries(plugins), []string{"good:swap"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Discover() = %#v, want %#v", got, want)
	}
	logged := out.String()
	for _, want := range []string{"level=WARN", "name=bad", "when.arg is -1"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("log = %q, want %q", logged, want)
		}
	}
}
