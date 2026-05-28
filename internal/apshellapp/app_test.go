// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

func TestNew(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	cfg := config.DefaultConfig()
	app := New(eng, cfg, "/tmp/apclient")

	if app == nil {
		t.Fatal("New() returned nil")
		return
	}
	if app.eng == nil {
		t.Fatal("New() did not initialize engine dependency")
	}
	if app.eng != eng {
		t.Fatal("New() did not retain provided engine")
	}
	if app.DataDir != "/tmp/apclient" {
		t.Fatalf("DataDir = %q, want %q", app.DataDir, "/tmp/apclient")
	}
	if app.Config.Network != cfg.Network {
		t.Fatalf("Config.Network = %q, want %q", app.Config.Network, cfg.Network)
	}
}
