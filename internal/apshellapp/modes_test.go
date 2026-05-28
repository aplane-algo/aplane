// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

func TestSetWriteModeEnablesDirectoryAndState(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	app := New(eng, config.DefaultConfig(), t.TempDir())

	if _, err := app.SetWriteMode(true); err != nil {
		t.Fatalf("SetWriteMode(true) error = %v", err)
	}
	if !eng.GetWriteMode() {
		t.Fatal("write mode not enabled")
	}
	if _, err := os.Stat(filepath.Join(tempDir, "txnjson")); err != nil {
		t.Fatalf("txnjson directory stat error = %v", err)
	}
}

func TestSetVerboseAndSimulateMode(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	app.SetVerboseMode(true)
	app.SetSimulateMode(true)

	if !eng.GetVerbose() {
		t.Fatal("verbose mode not enabled")
	}
	if !eng.GetSimulate() {
		t.Fatal("simulate mode not enabled")
	}
}
