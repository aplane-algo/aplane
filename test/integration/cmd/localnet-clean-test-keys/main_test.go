// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/serverconfig"

	"github.com/aplane-algo/aplane/internal/config"
)

func TestRequirePathInside(t *testing.T) {
	if err := requirePathInside("/tmp/aplane-test-env/apsigner", "/tmp/aplane-test-env"); err != nil {
		t.Fatalf("requirePathInside valid fixture path: %v", err)
	}
	if err := requirePathInside("/tmp/other-env/apsigner", "/tmp/aplane-test-env"); err == nil {
		t.Fatal("requirePathInside accepted path outside fixture root")
	}
}

func TestResolveFixtureRoot(t *testing.T) {
	if root, err := resolveFixtureRoot(defaultTestEnv); err != nil || root != defaultTestEnv {
		t.Fatalf("resolveFixtureRoot default = %q, %v", root, err)
	}

	unmarked := t.TempDir()
	if _, err := resolveFixtureRoot(unmarked); err == nil {
		t.Fatal("resolveFixtureRoot accepted a root that setup did not generate")
	}

	generated := t.TempDir()
	if err := os.WriteFile(filepath.Join(generated, testEnvOwnerFile), []byte("/checkout\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if root, err := resolveFixtureRoot(generated); err != nil || root != generated {
		t.Fatalf("resolveFixtureRoot generated = %q, %v", root, err)
	}
}

func TestServerConfigLooksLocalnet(t *testing.T) {
	if !serverConfigLooksLocalnet(serverconfig.ServerConfig{TEALCompileNetwork: localnetNetwork}) {
		t.Fatal("serverConfigLooksLocalnet rejected localnet teal compile network")
	}
	if !serverConfigLooksLocalnet(serverconfig.ServerConfig{
		Algod: config.AlgodConfig{
			localnetNetwork: &config.AlgodNetworkConfig{Server: "http://localhost:4001"},
		},
	}) {
		t.Fatal("serverConfigLooksLocalnet rejected localnet algod config")
	}
	if serverConfigLooksLocalnet(serverconfig.ServerConfig{TEALCompileNetwork: "testnet"}) {
		t.Fatal("serverConfigLooksLocalnet accepted testnet-only config")
	}
}
