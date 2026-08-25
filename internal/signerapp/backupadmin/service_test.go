// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

var backupAdminTestPassphrase = []byte("backup-admin-test-passphrase")

func TestManagedBackupTimestampIncludesNanoseconds(t *testing.T) {
	first := managedBackupTimestamp(time.Unix(1700000000, 1))
	second := managedBackupTimestamp(time.Unix(1700000000, 2))
	if first == second || !strings.HasSuffix(first, ".000000001") {
		t.Fatalf("timestamps = %q, %q", first, second)
	}
}

func TestBackupIdentityZeroesRequestPassphraseOnFailure(t *testing.T) {
	passphrase := []byte("export-passphrase")
	service := Service{
		Deps:    failingBackupDeps{paths: storepaths.NewPaths(t.TempDir())},
		Runtime: testBackupIdentityRuntime(),
	}
	result := service.BackupIdentity(adminproto.BackupIdentityRequest{
		ExportPassphrase: passphrase,
	})
	if result.Success {
		t.Fatal("BackupIdentity() success = true, want failure")
	}
	for i, value := range passphrase {
		if value != 0 {
			t.Fatalf("passphrase byte %d was not zeroed", i)
		}
	}
}

func TestBackupIdentityArchiveOmitsOperationalAuthority(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	if _, _, err := noderole.SaveInitial(paths, noderole.RoleSigner, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
	address, payload := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(payload)
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		sealed, err := kr.Seal(payload, crypto.AccountKeyContext(address))
		if err != nil {
			return err
		}
		return os.WriteFile(keys.AccountKeyFilePath(paths, address), sealed, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	result := (Service{Deps: backupServiceTestDeps{paths: paths}, Runtime: ir}).BackupIdentity(
		adminproto.BackupIdentityRequest{ExportPassphrase: []byte("export-passphrase")},
	)
	if !result.Success {
		t.Fatalf("BackupIdentity() = %+v", result)
	}
	root := t.TempDir()
	if err := backup.ExtractTarGzArchive(result.ArchivePath, root); err != nil {
		t.Fatal(err)
	}
	manifest, err := backup.OpenSealedManifest(root, []byte("export-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"user_auto_approve", "genesis_hash_mappings", "policy"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("manifest contains %q: %s", forbidden, encoded)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "policy")); !os.IsNotExist(err) {
		t.Fatalf("credential archive contains policy directory: %v", err)
	}
}

func TestPreviewRestoreRecordsLimiterFailureForMalformedArchive(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if err := os.MkdirAll(paths.ProductBackupsDir(), 0o770); err != nil {
		t.Fatal(err)
	}
	archivePath := backup.BuildManagedArchivePath(paths, "malformed")
	if err := os.WriteFile(archivePath, []byte("not an archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	limiter := NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) })
	ir := testBackupIdentityRuntime()
	service := Service{Deps: backupServiceTestDeps{paths: paths, limiter: limiter}, Runtime: ir}
	request := adminproto.PreviewRestoreRequest{
		ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase"),
	}
	if result := service.PreviewRestore(request); result.Code != protocol.ResultCodeRestorePreviewFailed {
		t.Fatalf("PreviewRestore() = %+v", result)
	}
	request.ExportPassphrase = []byte("export-passphrase")
	if result := service.PreviewRestore(request); result.Code != protocol.ResultCodeRestoreRateLimited {
		t.Fatalf("second PreviewRestore() = %+v", result)
	}
}

func TestPreviewRestoreDoesNotRateLimitAuthenticatedCredentialFailure(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, _ := writeMixedValidityManagedArchive(t, paths)
	limiter := NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) })
	service := Service{Deps: backupServiceTestDeps{paths: paths, limiter: limiter}, Runtime: ir}

	for i := 0; i < 2; i++ {
		result := service.PreviewRestore(adminproto.PreviewRestoreRequest{
			ArchivePath:      archivePath,
			ExportPassphrase: []byte("export-passphrase"),
		})
		if result.Code == protocol.ResultCodeRestoreRateLimited {
			t.Fatalf("authenticated preview attempt %d was rate limited: %+v", i+1, result)
		}
		if len(result.Errors) == 0 {
			t.Fatalf("authenticated preview attempt %d = %+v, want credential error", i+1, result)
		}
	}
}

func testUnlockedBackupIdentityRuntime(t *testing.T, paths storepaths.Paths, reloads *atomic.Int64) *productruntime.Runtime {
	t.Helper()
	if _, err := crypto.CreateKeyringStore(paths.ProductDir(), backupAdminTestPassphrase); err != nil {
		t.Fatal(err)
	}
	convertToGenerationalStore(t, paths)
	keyStore := keystore.NewFileKeyStoreForPaths(paths)
	if err := keyStore.Unlock(backupAdminTestPassphrase); err != nil {
		t.Fatal(err)
	}
	autoApprove := false
	ir := productruntime.New(productruntime.Config{
		KeyStore: keyStore, KeyPaths: paths,
		Authenticator: auth.NewTokenAuthenticator("token"), NodeRole: noderole.RoleSigner,
		UserAutoApprove: &autoApprove,
	})
	ir.SetReloadFunc(func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		reloads.Add(1)
		return &signertemplates.ReloadReport{}, nil
	})
	ir.SetUnlocked()
	return ir
}

func convertToGenerationalStore(t *testing.T, paths storepaths.Paths) string {
	t.Helper()
	if current, err := genstore.ReadCurrent(paths); err == nil {
		return current
	}
	generationID, err := genstore.NewGenerationID(time.Unix(1_753_700_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := genstore.Mint(paths, genstore.MintRequest{
		GenerationID: generationID, FirstGeneration: true, Operation: "test-init",
		OperationID: "init-" + generationID, CreatedAt: time.Unix(1_753_700_000, 0),
	}); err != nil {
		t.Fatal(err)
	}
	return generationID
}

func installBackupAdminPolicy(t *testing.T, ir *productruntime.Runtime, paths storepaths.Paths, stored *policy.StoredConfig) {
	t.Helper()
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		return policy.SaveStoredConfigWithKeyring(
			paths.Root(), stored, kr, time.Unix(1_700_000_000, 0),
		)
	}); err != nil {
		t.Fatal(err)
	}
	effective, err := stored.ApplySigning(nil)
	if err != nil {
		t.Fatal(err)
	}
	ir.SetPolicyState(stored, effective)
}

func testBackupIdentityRuntime() *productruntime.Runtime {
	return productruntime.New(productruntime.Config{
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
}

type backupServiceTestDeps struct {
	paths   storepaths.Paths
	limiter RestoreLimiter
}

func (d backupServiceTestDeps) KeyPaths() storepaths.Paths              { return d.paths }
func (d backupServiceTestDeps) GenesisHashMappings() map[string]string  { return nil }
func (d backupServiceTestDeps) RestoreLimiter() RestoreLimiter          { return d.limiter }
func (d backupServiceTestDeps) WithStoreMutation(fn func() error) error { return fn() }
func (d backupServiceTestDeps) Logf(string, ...interface{})             {}

type failingBackupDeps struct{ paths storepaths.Paths }

func (d failingBackupDeps) KeyPaths() storepaths.Paths             { return d.paths }
func (d failingBackupDeps) GenesisHashMappings() map[string]string { return nil }
func (d failingBackupDeps) RestoreLimiter() RestoreLimiter         { return nil }
func (d failingBackupDeps) WithStoreMutation(func() error) error {
	return errors.New("mutation failed")
}
func (d failingBackupDeps) Logf(string, ...interface{}) {}
