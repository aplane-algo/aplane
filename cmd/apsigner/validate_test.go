// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
)

func TestValidateStartupAcceptsSSHDefaults(t *testing.T) {
	t.Parallel()

	cfg := apconfig.DefaultServerConfig()
	runtime := &signerstartup.RuntimeState{}

	if _, err := signerstartup.Validate(&cfg, runtime, utilkeys.NewPaths(t.TempDir()), "default"); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateStartupRejectsInvalidSSHConfig(t *testing.T) {
	t.Parallel()

	cfg := apconfig.DefaultServerConfig()
	cfg.Endpoint.SSH.AuthorizedKeysPath = ""
	runtime := &signerstartup.RuntimeState{}

	if _, err := signerstartup.Validate(&cfg, runtime, utilkeys.NewPaths(t.TempDir()), "default"); err == nil {
		t.Fatal("Validate() error = nil, want invalid ssh configuration error")
	}
}
