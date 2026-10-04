// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"bytes"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig"
)

func cosignerPolicyForRestoreTest(key, description string) []byte {
	return []byte(`{"format":"aplane.cosigner-policy.v1","key":"` + key + `","description":"` + description + `","transfer_policy":{"routes":[]}}`)
}

// unlockedCosignerRuntime initializes a cosigner store and returns its
// unlocked runtime.
func unlockedCosignerRuntime(t *testing.T, paths storepaths.Paths) *productruntime.Runtime {
	t.Helper()
	lsig.RegisterClient()
	if _, err := storeinit.Initialize(backupAdminTestPassphrase, storeinit.Options{ValidateCandidate: storevalidate.FirstGeneration, DataDir: paths.Root(), Paths: paths, Role: noderole.RoleCosigner}); err != nil {
		t.Fatal(err)
	}
	keyStore := keystore.NewAtomicFileKeyStoreForPaths(paths)
	if err := keyStore.Unlock(backupAdminTestPassphrase); err != nil {
		t.Fatal(err)
	}
	ir := productruntime.New(productruntime.Config{
		KeyStore: keyStore, KeyPaths: paths,
		Authenticator: auth.NewTokenAuthenticator("token"), NodeRole: noderole.RoleCosigner,
	})
	ir.SetReloadFunc(func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return &signertemplates.ReloadReport{}, nil
	})
	ir.SetUnlocked()
	return ir
}

// writeCosignerArchiveWithPolicy writes a cosigner archive holding one witness
// credential and its encrypted policy.
func writeCosignerArchiveWithPolicy(t *testing.T, paths storepaths.Paths, name string, document func(key string) []byte) (string, string, []byte) {
	t.Helper()
	root := t.TempDir()
	key, payload := keystest.CosignerComponentFalcon1024KeyJSON(t, 0x5a)
	defer crypto.ZeroBytes(payload)
	doc := document(key)
	for dir, data := range map[string][]byte{"apb": payload, "policies": doc} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			t.Fatal(err)
		}
		sealed, err := crypto.EncryptStandalone(data, []byte("export-passphrase"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, key+".apb"), sealed, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := backup.WriteSealedManifest(root, noderole.RoleCosigner, time.Unix(1_700_000_000, 0), []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	archivePath := backup.BuildManagedArchivePath(paths, name)
	if err := backup.CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatal(err)
	}
	return archivePath, key, doc
}

func activePolicyForRestoreTest(t *testing.T, paths storepaths.Paths, key string) ([]byte, bool) {
	t.Helper()
	active, kr, err := genstore.ResolveStoreRoot(paths, backupAdminTestPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	doc, ok, err := policy.LoadVerifiedCosignerPolicy(active, key, kr)
	if err != nil {
		t.Fatal(err)
	}
	return doc.Bytes, ok
}

func TestRestoreInstallsCosignerPolicyAndRollbackRemovesIt(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	ir := unlockedCosignerRuntime(t, paths)
	service := directRestoreTestService(paths, ir)
	archivePath, key, doc := writeCosignerArchiveWithPolicy(t, paths, "policy-restore", func(key string) []byte {
		return cosignerPolicyForRestoreTest(key, "archived")
	})
	restore := func(id string, replace bool) adminproto.RestoreBackupResult {
		return service.RestoreBackup(adminproto.RestoreBackupRequest{
			OperationID: id, ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase"), ReplaceExisting: replace,
		})
	}

	first := restore("restore-first", false)
	if !first.Success || len(first.Restored) != 1 || len(first.PoliciesRestored) != 1 || first.PoliciesRestored[0] != key {
		t.Fatalf("RestoreBackup(first) = %+v", first)
	}
	if got, ok := activePolicyForRestoreTest(t, paths, key); !ok || !bytes.Equal(got, doc) {
		t.Fatalf("restored policy = %q, %v", got, ok)
	}

	again := restore("restore-again", false)
	if !again.Success || len(again.PoliciesRestored) != 0 || again.GenerationID != first.GenerationID {
		t.Fatalf("RestoreBackup(identical) = %+v, want a no-op", again)
	}

	rolledBack := service.RollbackRestore(adminproto.RollbackRestoreRequest{OperationID: "rollback"})
	if !rolledBack.Success {
		t.Fatalf("RollbackRestore() = %+v", rolledBack)
	}
	if _, ok := activePolicyForRestoreTest(t, paths, key); ok {
		t.Fatal("rollback kept the policy the restore installed")
	}
}

func TestRestorePolicyConflictNeedsReplaceExisting(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	ir := unlockedCosignerRuntime(t, paths)
	service := directRestoreTestService(paths, ir)
	archivePath, key, archived := writeCosignerArchiveWithPolicy(t, paths, "policy-conflict", func(key string) []byte {
		return cosignerPolicyForRestoreTest(key, "archived")
	})
	if result := service.RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID: "restore-initial", ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase"),
	}); !result.Success {
		t.Fatalf("RestoreBackup(initial) = %+v", result)
	}
	local := cosignerPolicyForRestoreTest(key, "local")
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		active, err := genstore.ResolveStoreRootWithKeyring(paths, kr)
		if err != nil {
			return err
		}
		return policy.WriteCosignerPolicy(active, key, local, kr, time.Now())
	}); err != nil {
		t.Fatal(err)
	}

	refused := service.RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID: "restore-conflict", ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase"),
	})
	if refused.Success || len(refused.Conflicts) != 1 {
		t.Fatalf("RestoreBackup(conflict) = %+v, want a refused conflict", refused)
	}
	if got, _ := activePolicyForRestoreTest(t, paths, key); !bytes.Equal(got, local) {
		t.Fatal("a refused restore changed the destination policy")
	}

	replaced := service.RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID: "restore-replace", ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase"), ReplaceExisting: true,
	})
	if !replaced.Success || len(replaced.PoliciesRestored) != 1 {
		t.Fatalf("RestoreBackup(replace) = %+v", replaced)
	}
	if got, _ := activePolicyForRestoreTest(t, paths, key); !bytes.Equal(got, archived) {
		t.Fatal("replace_existing did not install the archived policy")
	}

	// Rolling back the replacing restore brings the replaced policy back.
	if result := service.RollbackRestore(adminproto.RollbackRestoreRequest{OperationID: "rollback-replace"}); !result.Success {
		t.Fatalf("RollbackRestore() = %+v", result)
	}
	if got, ok := activePolicyForRestoreTest(t, paths, key); !ok || !bytes.Equal(got, local) {
		t.Fatalf("rollback policy = %q, want the replaced local policy", got)
	}
}
