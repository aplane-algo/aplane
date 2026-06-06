// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
)

func TestRunDryRunDoesNotWriteEndpointRegistry(t *testing.T) {
	dataDir := writeLegacyClientConfig(t)
	var stdout, stderr bytes.Buffer

	code := run([]string{"-d", dataDir, "--dry-run"}, &stdout, &stderr, "")
	if code != 0 {
		t.Fatalf("run exit = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Would write") {
		t.Fatalf("stdout = %q, want dry-run write summary", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, config.ClientEndpointsFile)); !os.IsNotExist(err) {
		t.Fatalf("endpoints.yaml stat err = %v, want not exist", err)
	}
}

func TestRunWritesEndpointRegistryFromLegacyConfig(t *testing.T) {
	dataDir := writeLegacyClientConfig(t)
	var stdout, stderr bytes.Buffer

	code := run([]string{"-d", dataDir}, &stdout, &stderr, "")
	if code != 0 {
		t.Fatalf("run exit = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Wrote") {
		t.Fatalf("stdout = %q, want write summary", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Left config.yaml unchanged") {
		t.Fatalf("stdout = %q, want unchanged config note", stdout.String())
	}

	registry, found, err := config.LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatalf("LoadStoredClientEndpointRegistry() error = %v", err)
	}
	if !found {
		t.Fatal("endpoints.yaml not found after migration")
	}
	alias, endpoint, ok := registry.DefaultEndpoint()
	if !ok || alias != config.DefaultClientEndpointName {
		t.Fatalf("DefaultEndpoint() = %q/%v, want primary/true", alias, ok)
	}
	if endpoint.URL != "ssh://signer.example.com:2222" {
		t.Fatalf("endpoint URL = %q", endpoint.URL)
	}
	if endpoint.SignerPort != 12345 {
		t.Fatalf("endpoint SignerPort = %d, want 12345", endpoint.SignerPort)
	}
	if endpoint.TokenFile != "aplane.token" {
		t.Fatalf("endpoint TokenFile = %q, want aplane.token", endpoint.TokenFile)
	}
}

func TestRunNoOpWhenEndpointRegistryAlreadyPresent(t *testing.T) {
	dataDir := writeLegacyClientConfig(t)
	if _, _, err := config.MaterializeStoredClientPrimaryEndpoint(dataDir); err != nil {
		t.Fatalf("MaterializeStoredClientPrimaryEndpoint() error = %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run([]string{"-d", dataDir}, &stdout, &stderr, "")
	if code != 0 {
		t.Fatalf("run exit = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "No legacy client endpoint migration needed") {
		t.Fatalf("stdout = %q, want no-op summary", stdout.String())
	}
}

func TestRunRequiresDataDir(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(nil, &stdout, &stderr, "")
	if code != 2 {
		t.Fatalf("run exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "apclient data directory is required") {
		t.Fatalf("stderr = %q, want data-dir error", stderr.String())
	}
}

func writeLegacyClientConfig(t *testing.T) string {
	t.Helper()
	dataDir := t.TempDir()
	data := []byte(`
network: testnet
signer_port: 12345
ssh:
  host: signer.example.com
  port: 2222
  identity_file: .ssh/id_ed25519
  known_hosts_path: .ssh/known_hosts
`)
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), data, 0o600); err != nil {
		t.Fatalf("WriteFile(config.yaml) error = %v", err)
	}
	return dataDir
}
