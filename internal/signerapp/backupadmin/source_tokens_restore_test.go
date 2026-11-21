// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func sourceTokensForRestoreTest(t *testing.T, selector, value string) *sourcetokens.File {
	t.Helper()
	f, err := sourcetokens.SetToken(nil, selector, "screening", []byte(value), time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// writeCosignerArchiveWithTokens writes a cosigner archive holding one
// witness credential and its source tokens: screening=value.
func writeCosignerArchiveWithTokens(t *testing.T, paths storepaths.Paths, name, value string) (string, string) {
	t.Helper()
	root := t.TempDir()
	key, payload := keystest.CosignerComponentFalcon1024KeyJSON(t, 0x5a)
	defer crypto.ZeroBytes(payload)
	f := sourceTokensForRestoreTest(t, key, value)
	tokens, err := sourcetokens.Encode(f)
	f.Zero()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(tokens)
	for dir, data := range map[string][]byte{"apb": payload, "source_tokens": tokens} {
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
	if err := backup.WriteSealedManifest(root, noderole.RoleCosigner, time.Unix(1_700_000_000, 0), []byte("export-passphrase"), nil); err != nil {
		t.Fatal(err)
	}
	archivePath := backup.BuildManagedArchivePath(paths, name)
	if err := backup.CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatal(err)
	}
	return archivePath, key
}

// activeTokenForRestoreTest is the screening token of selector in the
// selected generation, and whether it has one.
func activeTokenForRestoreTest(t *testing.T, paths storepaths.Paths, selector string) (string, bool) {
	t.Helper()
	active, kr, err := genstore.ResolveStoreRoot(paths, backupAdminTestPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	f, ok, err := sourcetokens.ReadFile(active, selector, kr)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Zero()
	if !ok {
		return "", false
	}
	return string(f.Tokens["screening"].Value), true
}

// setTokenInPlace writes selector's token file in the selected generation,
// as a source token set does.
func setTokenInPlace(t *testing.T, ir *productruntime.Runtime, paths storepaths.Paths, selector, value string) {
	t.Helper()
	f := sourceTokensForRestoreTest(t, selector, value)
	defer f.Zero()
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		active, err := genstore.ResolveStoreRootWithKeyring(paths, kr)
		if err != nil {
			return err
		}
		return sourcetokens.WriteFile(active, f, kr)
	}); err != nil {
		t.Fatal(err)
	}
}

func restoreForTokenTest(service Service, archivePath, id string, replace bool) adminproto.RestoreBackupResult {
	return service.RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID: id, ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase"), ReplaceExisting: replace,
	})
}

// Restore writes the key's archived tokens under the destination term, an
// identical restore is a no-op, and rolling the restore back removes them.
func TestRestoreInstallsSourceTokensAndRollbackRemovesThem(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	ir := unlockedCosignerRuntime(t, paths)
	service := directRestoreTestService(paths, ir)
	archivePath, key := writeCosignerArchiveWithTokens(t, paths, "tokens-restore", "tok-archived")

	first := restoreForTokenTest(service, archivePath, "restore-first", false)
	if !first.Success || len(first.Restored) != 1 || len(first.SourceTokensRestored) != 1 || first.SourceTokensRestored[0] != key {
		t.Fatalf("RestoreBackup(first) = %+v", first)
	}
	if got, ok := activeTokenForRestoreTest(t, paths, key); !ok || got != "tok-archived" {
		t.Fatalf("restored token = %q, %v", got, ok)
	}

	again := restoreForTokenTest(service, archivePath, "restore-again", false)
	if !again.Success || len(again.SourceTokensRestored) != 0 || again.GenerationID != first.GenerationID {
		t.Fatalf("RestoreBackup(identical) = %+v, want a no-op", again)
	}

	if rolled := service.RollbackRestore(adminproto.RollbackRestoreRequest{OperationID: "rollback"}); !rolled.Success {
		t.Fatalf("RollbackRestore() = %+v", rolled)
	}
	if _, ok := activeTokenForRestoreTest(t, paths, key); ok {
		t.Fatal("rollback kept the tokens the restore installed")
	}
}

// A destination token file that differs from the archive's is a conflict:
// refused without replace_existing, replaced with it, and brought back by
// rolling that restore back.
func TestRestoreSourceTokenConflictNeedsReplaceExisting(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	ir := unlockedCosignerRuntime(t, paths)
	service := directRestoreTestService(paths, ir)
	archivePath, key := writeCosignerArchiveWithTokens(t, paths, "tokens-conflict", "tok-archived")
	if result := restoreForTokenTest(service, archivePath, "restore-initial", false); !result.Success {
		t.Fatalf("RestoreBackup(initial) = %+v", result)
	}
	setTokenInPlace(t, ir, paths, key, "tok-local")

	refused := restoreForTokenTest(service, archivePath, "restore-conflict", false)
	if refused.Success || refused.Code != protocol.ResultCodeRestoreConflict || len(refused.Conflicts) != 1 ||
		refused.Conflicts[0].Reason != "existing source tokens differ from backup" {
		t.Fatalf("RestoreBackup(conflict) = %+v, want a refused token conflict", refused)
	}
	if got, _ := activeTokenForRestoreTest(t, paths, key); got != "tok-local" {
		t.Fatal("a refused restore changed the destination tokens")
	}

	replaced := restoreForTokenTest(service, archivePath, "restore-replace", true)
	if !replaced.Success || len(replaced.Restored) != 0 || len(replaced.Identical) != 1 || len(replaced.SourceTokensRestored) != 1 {
		t.Fatalf("RestoreBackup(replace) = %+v", replaced)
	}
	if got, _ := activeTokenForRestoreTest(t, paths, key); got != "tok-archived" {
		t.Fatalf("token after replace = %q, want the archived one", got)
	}

	// The replacing restore's parent holds the local token.
	if result := service.RollbackRestore(adminproto.RollbackRestoreRequest{OperationID: "rollback-replace"}); !result.Success {
		t.Fatalf("RollbackRestore() = %+v", result)
	}
	if got, ok := activeTokenForRestoreTest(t, paths, key); !ok || got != "tok-local" {
		t.Fatalf("token after rollback = %q, want the replaced local one", got)
	}
}

// Token files are in the inventory the rollback capability binds: a token
// set or removed after a restore makes rollback refuse rather than undo it.
func TestATokenChangeAfterARestoreMakesRollbackRefuse(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, ir *productruntime.Runtime, paths storepaths.Paths, key string){
		"set": func(t *testing.T, ir *productruntime.Runtime, paths storepaths.Paths, key string) {
			setTokenInPlace(t, ir, paths, key, "tok-later")
		},
		"removed": func(t *testing.T, _ *productruntime.Runtime, paths storepaths.Paths, key string) {
			if err := sourcetokens.RemoveFile(resolveAtomicTestGeneration(t, paths), key); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			ir := unlockedCosignerRuntime(t, paths)
			service := directRestoreTestService(paths, ir)
			archivePath, key := writeCosignerArchiveWithTokens(t, paths, "tokens-diverge", "tok-archived")
			if result := restoreForTokenTest(service, archivePath, "restore", false); !result.Success {
				t.Fatalf("RestoreBackup() = %+v", result)
			}
			change(t, ir, paths, key)
			result := service.RollbackRestore(adminproto.RollbackRestoreRequest{OperationID: "rollback"})
			if result.Success || result.Code != protocol.ResultCodeRestoreRollbackDiverged {
				t.Fatalf("RollbackRestore() after a token change = %+v, want diverged", result)
			}
		})
	}
}

// In recovery mode, restoring a key whose destination token file is damaged
// replaces it with the archived one when replace_existing is given.
func TestRecoveryRestoreRepairsADamagedTokenFileFromTheBackup(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	ir := unlockedCosignerRuntime(t, paths)
	service := directRestoreTestService(paths, ir)
	archivePath, key := writeCosignerArchiveWithTokens(t, paths, "tokens-repair", "tok-archived")
	if result := restoreForTokenTest(service, archivePath, "restore-initial", false); !result.Success {
		t.Fatalf("RestoreBackup(initial) = %+v", result)
	}
	if err := os.WriteFile(resolveAtomicTestGeneration(t, paths).SourceTokenPath(key), []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	ir.SetRecovery()

	refused := restoreForTokenTest(service, archivePath, "restore-refused", false)
	if refused.Success || refused.Code != protocol.ResultCodeRestoreConflict || len(refused.Conflicts) != 1 {
		t.Fatalf("recovery restore without replacement = %+v", refused)
	}
	repaired := restoreForTokenTest(service, archivePath, "restore-repair", true)
	if !repaired.Success || len(repaired.SourceTokensRestored) != 1 {
		t.Fatalf("recovery restore with replacement = %+v", repaired)
	}
	if got, ok := activeTokenForRestoreTest(t, paths, key); !ok || got != "tok-archived" {
		t.Fatalf("repaired token = %q, %v", got, ok)
	}
}

// A preview lists at most maxReportedSourceTokenNames source names across its
// keys; a key whose names do not fit reports how many it left out.
func TestPreviewBoundsTheSourceNamesItLists(t *testing.T) {
	names := make([]string, 8)
	for i := range names {
		names[i] = fmt.Sprintf("source-%d", i)
	}
	items := make([]backup.RestoreKeyInfo, maxReportedSourceTokenNames/len(names)+1)
	for i := range items {
		items[i] = backup.RestoreKeyInfo{Address: fmt.Sprintf("KEY%d", i), SourceTokens: names}
	}
	out := projectRestoreKeyInfos(items)
	listed := 0
	for _, item := range out[:len(out)-1] {
		listed += len(item.SourceTokens)
	}
	last := out[len(out)-1]
	if listed != maxReportedSourceTokenNames || len(last.SourceTokens) != 0 || last.SourceTokensOmitted != len(names) {
		t.Fatalf("listed %d names, last key %+v; want %d listed and the last key's %d counted",
			listed, last, maxReportedSourceTokenNames, len(names))
	}
}
