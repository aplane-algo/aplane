// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

func TestStartupConnectDecisionNoDefaultEndpoint(t *testing.T) {
	eng := engine.NewEngine("testnet")
	app := New(eng, config.DefaultConfig(), t.TempDir())

	decision := app.StartupConnectDecision()
	if decision.ShouldConnect {
		t.Fatal("ShouldConnect = true, want false")
	}
}

func TestStartupConnectDecisionWithDefaultSignerEndpoint(t *testing.T) {
	eng := engine.NewEngine("testnet")

	cfg := config.DefaultConfig()
	cfg.Endpoints = config.ClientEndpointRegistry{
		SchemaVersion: 1,
		Default:       "primary",
		Endpoints: map[string]config.ClientEndpointConfig{
			"primary": {
				Role: config.ClientEndpointRoleSigner,
				URL:  "ssh://signer.example:1127",
			},
		},
	}
	app := New(eng, cfg, t.TempDir())

	decision := app.StartupConnectDecision()
	if !decision.ShouldConnect {
		t.Fatalf("decision = %#v, want connect", decision)
	}
	if decision.Host != "signer.example" || decision.SSHPort != 1127 {
		t.Fatalf("decision = %#v", decision)
	}
}
