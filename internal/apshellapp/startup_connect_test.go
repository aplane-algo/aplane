// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

func TestStartupConnectDecisionNoTokenNoSSH(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	app := New(eng, config.DefaultConfig(), t.TempDir())

	decision := app.StartupConnectDecision()
	if decision.HasToken {
		t.Fatal("HasToken = true, want false")
	}
	if decision.HasSSHConfig {
		t.Fatal("HasSSHConfig = true, want false")
	}
	if decision.ShouldConnect {
		t.Fatal("ShouldConnect = true, want false")
	}
}

func TestStartupConnectDecisionWithSSHConfig(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.SSH = &config.SSHClientConfig{
		Host:         "signer.example",
		Port:         1127,
		IdentityFile: "/tmp/id_ed25519",
	}
	cfg.SignerPort = 11270
	app := New(eng, cfg, t.TempDir())

	decision := app.StartupConnectDecision()
	if !decision.HasSSHConfig {
		t.Fatal("HasSSHConfig = false, want true")
	}
	if decision.Host != "signer.example" || decision.SSHPort != 1127 || decision.SignerPort != 11270 {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestStartupConnectDecisionUsesDefaultEndpointToken(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	dataDir := t.TempDir()
	tokenPath := filepath.Join(dataDir, "tokens", "primary-alt.token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := tokenfile.WriteToken(tokenPath, "token"); err != nil {
		t.Fatalf("WriteToken() error = %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Endpoints = config.ClientEndpointRegistry{
		SchemaVersion: 1,
		Default:       "primary-alt",
		Endpoints: map[string]config.ClientEndpointConfig{
			"primary-alt": {
				URL:            "ssh://signer.example:2222",
				SignerPort:     12270,
				IdentityFile:   "/tmp/id_ed25519",
				KnownHostsPath: "/tmp/known_hosts",
				TokenFile:      tokenPath,
			},
		},
	}
	app := New(eng, cfg, dataDir)

	decision := app.StartupConnectDecision()
	if !decision.HasToken || !decision.ShouldConnect {
		t.Fatalf("decision = %#v, want token and connect", decision)
	}
	if decision.TokenPath != tokenPath || decision.EndpointName != "primary-alt" {
		t.Fatalf("decision = %#v, want endpoint token path", decision)
	}
	if decision.Host != "signer.example" || decision.SSHPort != 2222 || decision.SignerPort != 12270 {
		t.Fatalf("decision = %#v, want endpoint connection info", decision)
	}
}
