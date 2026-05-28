// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
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

	identityDir := paths.IdentityDir(identityID)
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
	config = apconfig.ServerConfig{}
	stdinReader = nil
	var gotPassphrase string
	initializeStoreForCommand = func(passphrase []byte) (protocol.InitializeStoreResultMessage, error) {
		gotPassphrase = string(passphrase)
		return protocol.InitializeStoreResultMessage{
			Success:     true,
			MetadataDir: keystorePaths().KeystoreMetadataDir(productIdentityID()),
		}, nil
	}

	err := withTestStdin("init-passphrase\ninit-passphrase\n", cmdInitialize)
	if err != nil {
		t.Fatalf("cmdInitialize() error = %v", err)
	}
	if gotPassphrase != "init-passphrase" {
		t.Fatalf("initialize passphrase = %q, want init-passphrase", gotPassphrase)
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
	initializeStoreForCommand = func(passphrase []byte) (protocol.InitializeStoreResultMessage, error) {
		return protocol.InitializeStoreResultMessage{
			Success: false,
			Code:    "initialize_store_failed",
			Error:   "keystore already initialized",
		}, nil
	}

	err := withTestStdin("new-passphrase\nnew-passphrase\n", cmdInitialize)
	if err == nil || !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("cmdInitialize() error = %v, want initialize failure", err)
	}
}

func TestCmdChangepassUsesAdminIPC(t *testing.T) {
	oldReader := stdinReader
	defer func() {
		stdinReader = oldReader
	}()

	fake := &fakeApstoreAdminRequester{
		changePassphraseResult: protocol.ChangeStorePassphraseResultMessage{
			Success:           true,
			KeysMigrated:      2,
			TemplatesMigrated: 1,
		},
	}
	withFakeApstoreAdminClient(t, fake)

	err := withTestStdin("current-passphrase\nnew-passphrase\nnew-passphrase\ny\n", cmdChangepass)
	if err != nil {
		t.Fatalf("cmdChangepass() error = %v", err)
	}
	if strings.Join(fake.requests, ",") != protocol.MsgTypeChangeStorePass {
		t.Fatalf("requests = %v, want change_store_passphrase", fake.requests)
	}
	if string(fake.changePassphraseRequest.CurrentPassphrase) != "current-passphrase" {
		t.Fatalf("current passphrase = %q", string(fake.changePassphraseRequest.CurrentPassphrase))
	}
	if fake.adminPassphrase != "current-passphrase" {
		t.Fatalf("admin passphrase = %q, want current-passphrase", fake.adminPassphrase)
	}
	if string(fake.changePassphraseRequest.NewPassphrase) != "new-passphrase" {
		t.Fatalf("new passphrase = %q", string(fake.changePassphraseRequest.NewPassphrase))
	}
	if !fake.closed {
		t.Fatal("fake client was not closed")
	}
}

func TestCmdChangepassRejectsEqualNewPassphraseBeforeIPC(t *testing.T) {
	fake := &fakeApstoreAdminRequester{}
	withFakeApstoreAdminClient(t, fake)

	err := withTestStdin("same-passphrase\nsame-passphrase\nsame-passphrase\n", cmdChangepass)
	if err == nil {
		t.Fatal("cmdChangepass() error = nil, want equal passphrase rejection")
	}
	if !strings.Contains(err.Error(), "new passphrase must be different") {
		t.Fatalf("cmdChangepass() error = %v, want equal passphrase rejection", err)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("requests = %v, want no IPC request before validation failure", fake.requests)
	}
}

func TestCmdChangepassRejectsConfirmationMismatchBeforeIPC(t *testing.T) {
	fake := &fakeApstoreAdminRequester{}
	withFakeApstoreAdminClient(t, fake)

	err := withTestStdin("current-passphrase\nnew-passphrase\nother-passphrase\n", cmdChangepass)
	if err == nil {
		t.Fatal("cmdChangepass() error = nil, want confirmation mismatch")
	}
	if !strings.Contains(err.Error(), "passphrases do not match") {
		t.Fatalf("cmdChangepass() error = %v, want confirmation mismatch", err)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("requests = %v, want no IPC request before validation failure", fake.requests)
	}
}
