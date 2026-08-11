// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeinit

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/defaultkeytypes"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig"
)

func TestInitializeCreatesStoreMetadataKeysAndToken(t *testing.T) {
	lsig.RegisterClient()

	dataDir := t.TempDir()
	paths := storepaths.NewPaths(dataDir)
	identityID := "default"
	passphrase := []byte("init-passphrase")
	defer crypto.ZeroBytes(passphrase)

	result, err := Initialize(passphrase, Options{
		DataDir:    dataDir,
		Paths:      paths,
		IdentityID: identityID,
	})
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if result.MetadataDir != paths.KeystoreMetadataDir(identityID) {
		t.Fatalf("MetadataDir = %q, want %q", result.MetadataDir, paths.KeystoreMetadataDir(identityID))
	}
	if !crypto.KeyringExistsIn(paths.KeystoreMetadataDir(identityID)) {
		t.Fatal("keystore metadata missing after initialize")
	}
	// New stores are generational: active namespaces live in the first
	// generation behind CURRENT, and the metadata carries the layout gate.
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		t.Fatalf("ResolveActive() error = %v", err)
	}
	if _, err := os.Stat(active.KeysDir()); err != nil {
		t.Fatalf("generational keys dir stat error = %v", err)
	}
	if _, err := os.Stat(paths.LegacyKeysDir(identityID)); !os.IsNotExist(err) {
		t.Fatalf("legacy keys dir exists on a new store: err = %v", err)
	}
	gen, err := genstore.Resolve(paths, identityID)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if err := genstore.ValidateCurrent(gen); err != nil {
		t.Fatalf("initial generation failed validation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(paths.IdentityDir(identityID), "aplane.token")); err != nil {
		t.Fatalf("token stat error = %v", err)
	}
	kr, err := crypto.OpenKeyringStore(paths.KeystoreMetadataDir(identityID), passphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer kr.Zero()
	if _, err := policy.LoadVerifiedStoredConfigWithKeyring(dataDir, identityID, kr); err != nil {
		t.Fatalf("policy integrity baseline did not verify: %v", err)
	}
	role, err := noderole.LoadAndVerifyWithKeyring(paths, identityID, kr)
	if err != nil {
		t.Fatalf("node role integrity baseline did not verify: %v", err)
	}
	if role.Role != noderole.RoleSigner {
		t.Fatalf("node role = %q, want %q", role.Role, noderole.RoleSigner)
	}
	for _, keyType := range []string{defaultkeytypes.Falcon1024AllowlistKeyType} {
		rec, ok, err := keytypestate.GetActive(active, keyType)
		if err != nil {
			t.Fatalf("keytypestate.GetActive(default key type %s) error = %v", keyType, err)
		}
		if !ok {
			t.Fatalf("default key type %s state missing", keyType)
		}
		if rec.Source != keytypestate.SourceYAMLComposed || rec.State != keytypestate.StateEnabled {
			t.Fatalf("default key type %s state = (%s, %s), want (%s, %s)",
				keyType, rec.Source, rec.State, keytypestate.SourceYAMLComposed, keytypestate.StateEnabled)
		}
		if !templatestore.TemplateExistsActive(active, keyType, templatestore.TemplateTypeComposed) {
			t.Fatalf("default key type template %s missing", keyType)
		}
	}
}

func TestInitializeCreatesExplicitSentryNodeRole(t *testing.T) {
	dataDir := t.TempDir()
	paths := storepaths.NewPaths(dataDir)
	identityID := "default"
	passphrase := []byte("init-passphrase")
	defer crypto.ZeroBytes(passphrase)

	if _, err := Initialize(passphrase, Options{
		DataDir:    dataDir,
		Paths:      paths,
		IdentityID: identityID,
		Role:       noderole.RoleSentry,
	}); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	kr, err := crypto.OpenKeyringStore(paths.KeystoreMetadataDir(identityID), passphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer kr.Zero()
	role, err := noderole.LoadAndVerifyWithKeyring(paths, identityID, kr)
	if err != nil {
		t.Fatalf("node role integrity baseline did not verify: %v", err)
	}
	if role.Role != noderole.RoleSentry {
		t.Fatalf("node role = %q, want %q", role.Role, noderole.RoleSentry)
	}
	if _, err := policy.LoadVerifiedSentryConfigWithKeyring(dataDir, identityID, kr); err != nil {
		t.Fatalf("sentry policy integrity baseline did not verify: %v", err)
	}
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		t.Fatalf("ResolveActive() error = %v", err)
	}
	rec, ok, err := keytypestate.GetActive(active, defaultkeytypes.Falcon1024AllowlistKeyType)
	if err != nil {
		t.Fatalf("keytypestate.GetActive(default key type) error = %v", err)
	}
	if ok {
		t.Fatalf("sentry initialization installed signer default key type: %+v", rec)
	}
}

func TestInitializeRemovesNodeRoleOnLateFailure(t *testing.T) {
	dataDir := t.TempDir()
	paths := storepaths.NewPaths(dataDir)
	identityID := "default"
	identityDir := paths.IdentityDir(identityID)
	if err := os.MkdirAll(filepath.Join(identityDir, "aplane.token"), 0o700); err != nil {
		t.Fatalf("MkdirAll(aplane.token dir) error = %v", err)
	}

	_, err := Initialize([]byte("init-passphrase"), Options{
		DataDir:    dataDir,
		Paths:      paths,
		IdentityID: identityID,
		Role:       noderole.RoleSentry,
	})
	if err == nil || !strings.Contains(err.Error(), "failed to generate API token") {
		t.Fatalf("Initialize() error = %v, want token failure", err)
	}
	if _, statErr := os.Stat(paths.NodeRolePath()); !os.IsNotExist(statErr) {
		t.Fatalf("node role stat error = %v, want removed node.yaml after failed initialize", statErr)
	}
}

func TestInitializeRejectsExistingKeyring(t *testing.T) {
	dataDir := t.TempDir()
	paths := storepaths.NewPaths(dataDir)
	identityID := "default"
	kr, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(identityID), []byte("existing-passphrase"))
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	kr.Zero()

	_, err = Initialize([]byte("new-passphrase"), Options{
		DataDir:    dataDir,
		Paths:      paths,
		IdentityID: identityID,
	})
	if err == nil || !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("Initialize() error = %v, want already-initialized error", err)
	}
}

func TestHasPartialState(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"

	if HasPartialState(paths, identityID) {
		t.Fatal("empty identity dir should not be partial")
	}

	identityDir := paths.IdentityDir(identityID)
	if err := os.MkdirAll(identityDir, 0o770); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(identityDir, "aplane.token"), []byte("token"), 0o600); err != nil {
		t.Fatalf("WriteFile(aplane.token) error = %v", err)
	}
	if HasPartialState(paths, identityID) {
		t.Fatal("token-only identity dir should not be partial")
	}
	if err := os.WriteFile(filepath.Join(identityDir, "orphan.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if !HasPartialState(paths, identityID) {
		t.Fatal("expected orphaned identity dir state to be detected")
	}

	if err := os.WriteFile(filepath.Join(identityDir, ".keystore"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile(.keystore) error = %v", err)
	}
	if HasPartialState(paths, identityID) {
		t.Fatal("presence of .keystore should not be considered partial initialization")
	}
}

func TestChownIdentitiesTreeRejectsSymlinkWithoutTouchingTarget(t *testing.T) {
	dataDir := t.TempDir()
	paths := storepaths.NewPaths(dataDir)
	identitiesDir := filepath.Join(dataDir, "identities")
	identityDir := paths.IdentityDir("default")
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(identityDir): %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatalf("WriteFile(outside): %v", err)
	}
	before, err := os.Stat(outside)
	if err != nil {
		t.Fatalf("Stat(outside): %v", err)
	}
	link := filepath.Join(identityDir, "planted")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	err = chownIdentitiesTreeToDataDirOwner(dataDir, paths)
	if err == nil || !strings.Contains(err.Error(), "refusing symlink") {
		t.Fatalf("chownIdentitiesTreeToDataDirOwner() error = %v, want symlink rejection", err)
	}
	after, err := os.Stat(outside)
	if err != nil {
		t.Fatalf("Stat(outside) after rejection: %v", err)
	}
	beforeUID, beforeGID := fileOwnershipForTest(t, before)
	afterUID, afterGID := fileOwnershipForTest(t, after)
	if beforeUID != afterUID || beforeGID != afterGID {
		t.Fatalf("outside ownership changed from %d:%d to %d:%d", beforeUID, beforeGID, afterUID, afterGID)
	}
	if _, err := os.Stat(identitiesDir); err != nil {
		t.Fatalf("identities directory disappeared: %v", err)
	}
}

func TestInitializeChecksOwnershipTreeBeforeCreatingKeyring(t *testing.T) {
	dataDir := t.TempDir()
	paths := storepaths.NewPaths(dataDir)
	otherIdentity := paths.IdentityDir("other")
	if err := os.MkdirAll(otherIdentity, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(otherIdentity, "planted")); err != nil {
		t.Fatal(err)
	}

	_, err := Initialize([]byte("init-passphrase"), Options{
		DataDir: dataDir, Paths: paths, IdentityID: "default",
	})
	if err == nil || !strings.Contains(err.Error(), "prepare initialized identity ownership") {
		t.Fatalf("Initialize() error = %v, want ownership preflight failure", err)
	}
	if crypto.KeyringExistsIn(paths.KeystoreMetadataDir("default")) {
		t.Fatal("ownership preflight failure left a created keyring")
	}
}

func fileOwnershipForTest(t *testing.T, info os.FileInfo) (uint32, uint32) {
	t.Helper()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("ownership metadata unavailable")
	}
	return stat.Uid, stat.Gid
}
