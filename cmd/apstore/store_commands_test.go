// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/storeinit"
	utilpaths "github.com/aplane-algo/aplane/internal/storepaths"
)

func TestHasPartialKeystoreState(t *testing.T) {
	paths := utilpaths.NewPaths(t.TempDir())
	identityID := "default"

	if storeinit.HasPartialState(paths, identityID) {
		t.Fatal("empty identity dir should not be partial")
	}

	identityDir := paths.ProductDir()
	if err := os.MkdirAll(identityDir, 0o770); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(identityDir, "orphan.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if !storeinit.HasPartialState(paths, identityID) {
		t.Fatal("expected orphaned identity dir state to be detected")
	}

	if err := os.WriteFile(filepath.Join(identityDir, ".keystore"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile(.keystore) error = %v", err)
	}
	if storeinit.HasPartialState(paths, identityID) {
		t.Fatal("presence of .keystore should not be considered partial initialization")
	}
}

func TestCmdInitializeInitializes(t *testing.T) {
	oldDataDirectory := dataDirectory
	oldConfig := config
	oldReader := stdinReader
	oldInitializeStoreForCommand := initializeStoreForCommand
	defer func() {
		dataDirectory = oldDataDirectory
		config = oldConfig
		stdinReader = oldReader
		initializeStoreForCommand = oldInitializeStoreForCommand
	}()

	dataDirectory = t.TempDir()
	config = serverconfig.ServerConfig{}
	stdinReader = nil
	var gotPassphrase string
	var gotRole noderole.Role
	initializeStoreForCommand = func(passphrase []byte, role noderole.Role) (protocol.InitializeStoreResultMessage, error) {
		gotPassphrase = string(passphrase)
		gotRole = role
		return protocol.InitializeStoreResultMessage{
			Success:     true,
			MetadataDir: keystorePaths().KeystoreMetadataDir(),
		}, nil
	}

	err := withTestStdin("init-passphrase\ninit-passphrase\n", func() error {
		return cmdInitialize(nil)
	})
	if err != nil {
		t.Fatalf("cmdInitialize() error = %v", err)
	}
	if gotPassphrase != "init-passphrase" {
		t.Fatalf("initialize passphrase = %q, want init-passphrase", gotPassphrase)
	}
	if gotRole != noderole.RoleSigner {
		t.Fatalf("initialize role = %q, want %q", gotRole, noderole.RoleSigner)
	}
}

func TestParseInitializeRole(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    noderole.Role
		wantErr string
	}{
		{name: "default signer", want: noderole.RoleSigner},
		{name: "explicit signer", args: []string{"--role", "signer"}, want: noderole.RoleSigner},
		{name: "explicit sentry", args: []string{"--role", "sentry"}, want: noderole.RoleSentry},
		{name: "dual rejected", args: []string{"--role", "dual"}, wantErr: "invalid initialize role"},
		{name: "extra arg rejected", args: []string{"extra"}, wantErr: "usage: apstore initialize"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseInitializeRole(tt.args)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseInitializeRole() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseInitializeRole() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseInitializeRole() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCmdInitializeReturnsInitializeFailure(t *testing.T) {
	oldReader := stdinReader
	oldInitializeStoreForCommand := initializeStoreForCommand
	defer func() {
		stdinReader = oldReader
		initializeStoreForCommand = oldInitializeStoreForCommand
	}()

	stdinReader = nil
	initializeStoreForCommand = func(passphrase []byte, role noderole.Role) (protocol.InitializeStoreResultMessage, error) {
		return protocol.InitializeStoreResultMessage{
			Success: false,
			Code:    "initialize_store_failed",
			Error:   "keystore already initialized",
		}, nil
	}

	err := withTestStdin("new-passphrase\nnew-passphrase\n", func() error {
		return cmdInitialize(nil)
	})
	if err == nil || !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("cmdInitialize() error = %v, want initialize failure", err)
	}
}
