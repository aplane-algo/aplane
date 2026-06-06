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

func TestConnectRequiresToken(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	_, err = app.Connect(context.Background(), ConnectRequest{
		Host:           "localhost",
		SSHPort:        1127,
		SignerPort:     11270,
		IdentityFile:   "/tmp/id",
		KnownHostsPath: "/tmp/known_hosts",
	})
	if err == nil || !strings.Contains(err.Error(), "no token configured") {
		t.Fatalf("Connect() error = %v, want missing token error", err)
	}
}

func TestConnectRequiresEndpointToken(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	dataDir := t.TempDir()
	tokenPath := dataDir + "/tokens/attestor-local.token"
	app := New(eng, config.DefaultConfig(), dataDir)
	_, err = app.Connect(context.Background(), ConnectRequest{
		Host:           "localhost",
		SSHPort:        1127,
		SignerPort:     11270,
		IdentityFile:   "/tmp/id",
		KnownHostsPath: "/tmp/known_hosts",
		TokenFile:      tokenPath,
	})
	if err == nil || !strings.Contains(err.Error(), tokenPath) {
		t.Fatalf("Connect() error = %v, want missing endpoint token path", err)
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

func TestRequestTokenConfiguredRequiresDefaultSignerEndpoint(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	_, err = app.RequestTokenConfigured(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "usage: request-token") {
		t.Fatalf("RequestTokenConfigured() error = %v, want usage error", err)
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
