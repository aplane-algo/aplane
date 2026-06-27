// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

func TestSignFileRejectsInvalidFile(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	if _, err := app.SignFile(context.Background(), SignFileRequest{
		FilePath: filepath.Join(t.TempDir(), "missing.txn"),
		Wait:     true,
	}); err == nil {
		t.Fatal("SignFile() error = nil, want failure")
	}
}

func TestSignFileLoadsTransactionsBeforeSubmission(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), dir)
	_, err = app.SignFile(context.Background(), SignFileRequest{
		FilePath: path,
		Wait:     true,
	})
	if err == nil {
		t.Fatal("SignFile() error = nil, want failure")
	}
}

func TestSubmitPluginTransactionsRequiresConnection(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	_, err = app.SubmitPluginTransactions(context.Background(), "plugin", &jsonrpc.ExecuteResult{}, nil)
	if err == nil || err.Error() != "not connected to signer" {
		t.Fatalf("SubmitPluginTransactions() error = %v, want not connected", err)
	}
}
