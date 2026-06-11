// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"testing"

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
