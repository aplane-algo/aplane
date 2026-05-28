// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
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
