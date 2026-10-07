// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

// Connect fails closed on an identity file that does not exist, before any
// network activity.
func TestConnectRequiresIdentityFile(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	dataDir := t.TempDir()
	app := New(eng, config.DefaultConfig(), dataDir)
	_, err = app.Connect(context.Background(), ConnectRequest{
		Host:           "localhost",
		SSHPort:        1,
		IdentityFile:   dataDir + "/missing_id",
		KnownHostsPath: dataDir + "/known_hosts",
	})
	if err == nil {
		t.Fatal("Connect() error = nil, want a failure")
	}
}

func TestDisconnectNoOpWhenNotConnected(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	res, err := app.Disconnect(context.Background())
	if err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}
	if res.WasConnected {
		t.Fatalf("Disconnect() result = %#v, want not connected", res)
	}
}

func TestConnectConfiguredRequiresDefaultSignerEndpoint(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	_, err = app.ConnectConfigured(context.Background(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no default signer endpoint") {
		t.Fatalf("ConnectConfigured() error = %v, want missing default endpoint error", err)
	}
}

func TestDecorateConnectResult(t *testing.T) {
	result := &ConnectResult{
		Port:     1234,
		KeyCount: 2,
		Summary:  Summary{Message: "Signer verified via tunnel at http://localhost:1234"},
	}

	decorateConnectResult(result)

	if len(result.RenderLines) < 3 {
		t.Fatalf("RenderLines = %#v, want connection lines", result.RenderLines)
	}
	if result.RenderLines[0] != "✓ SSH tunnel established via public key" {
		t.Fatalf("first render line = %q", result.RenderLines[0])
	}
	if result.RenderLines[2] != "✓ Loaded 2 signing key(s)" {
		t.Fatalf("third render line = %q", result.RenderLines[2])
	}
}

func TestDecorateConnectResultOmitsLockedTranscriptLine(t *testing.T) {
	result := &ConnectResult{
		Port:    1234,
		Locked:  true,
		Summary: Summary{Message: "Signer verified via tunnel at http://localhost:1234"},
	}

	decorateConnectResult(result)

	for _, line := range result.RenderLines {
		if strings.Contains(line, "Signer is locked") {
			t.Fatalf("RenderLines contains stale locked transcript line: %#v", result.RenderLines)
		}
	}
	if len(result.RenderLines) != 2 {
		t.Fatalf("RenderLines = %#v, want only tunnel and verification lines", result.RenderLines)
	}
}

func TestResolveEnrollmentTarget(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Endpoints = config.ClientEndpointRegistry{
		Default: "primary",
		Endpoints: map[string]config.ClientEndpointConfig{
			"primary":  {Role: config.ClientEndpointRoleSigner},
			"cosigner": {Role: config.ClientEndpointRoleCosigner},
		},
	}
	app := New(nil, cfg, t.TempDir())

	for _, tc := range []struct {
		alias, wantAlias string
		wantAutoConnect  bool
	}{
		{alias: "", wantAlias: "primary", wantAutoConnect: true},
		{alias: "primary", wantAlias: "primary", wantAutoConnect: true},
		{alias: "cosigner", wantAlias: "cosigner", wantAutoConnect: false},
	} {
		target, err := app.ResolveEnrollmentTarget(tc.alias)
		if err != nil || target.Alias != tc.wantAlias || target.AutoConnect != tc.wantAutoConnect {
			t.Fatalf("ResolveEnrollmentTarget(%q) = %+v, %v; want alias %q, auto-connect %v",
				tc.alias, target, err, tc.wantAlias, tc.wantAutoConnect)
		}
	}
	if _, err := app.ResolveEnrollmentTarget("missing"); err == nil || !strings.Contains(err.Error(), `unknown endpoint alias "missing"`) {
		t.Fatalf("ResolveEnrollmentTarget(missing) error = %v", err)
	}

	app.Config.Endpoints = config.ClientEndpointRegistry{}
	if _, err := app.ResolveEnrollmentTarget(""); err == nil || !strings.Contains(err.Error(), "no default signer endpoint") {
		t.Fatalf("ResolveEnrollmentTarget(no default) error = %v", err)
	}
}
