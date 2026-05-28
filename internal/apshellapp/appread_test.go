// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

func TestAppReadRequiresSubcommand(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	app := New(eng, config.DefaultConfig(), t.TempDir())

	_, err = app.AppRead(context.Background(), AppReadRequest{})
	if err == nil || err.Error() != "usage: app read <info|global|local|box|boxes>" {
		t.Fatalf("AppRead() error = %v", err)
	}
}

func TestAppReadRejectsInvalidSubcommand(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	app := New(eng, config.DefaultConfig(), t.TempDir())

	_, err = app.AppRead(context.Background(), AppReadRequest{Args: []string{"wat"}})
	if err == nil || err.Error() != "unknown app read command: wat" {
		t.Fatalf("AppRead() error = %v", err)
	}
}

func TestAppReadInfoDelegatesToEngine(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	app := New(eng, config.DefaultConfig(), t.TempDir())

	_, err = app.AppRead(context.Background(), AppReadRequest{Args: []string{"info", "123"}})
	if err == nil || err.Error() != "algod client not configured" {
		t.Fatalf("AppRead() error = %v", err)
	}
}

func TestAppReadLocalResolvesAccount(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AliasCache.Aliases = map[string]string{
		"alice": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	}
	app := New(eng, config.DefaultConfig(), t.TempDir())

	_, err = app.AppRead(context.Background(), AppReadRequest{Args: []string{"local", "123", "alice"}})
	if err == nil || err.Error() != "algod client not configured" {
		t.Fatalf("AppRead() error = %v", err)
	}
}
