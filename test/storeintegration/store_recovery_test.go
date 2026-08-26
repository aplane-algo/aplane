// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeintegration_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestRestoreCleanupFailureBlocksSigningUntilRollbackPromotes(t *testing.T) {
	const (
		passphrase = "restore-recovery-passphrase"
		sourcePass = "restore-recovery-source"
		exportPass = "restore-recovery-export"
	)
	env := newFreshStoreEnv(t, passphrase)
	env.initialize()
	env.startSigner(passphrase)
	address := mustGenerateEd25519(t, env)
	mustWaitForAddresses(t, env, address)
	if err := env.stopSigner(); err != nil {
		t.Fatalf("stop destination before checkpoint restart: %v", err)
	}
	env.configureCheckpoint("restore.store_root_replaced", "error")
	env.startSigner(passphrase)

	source := newFreshStoreEnv(t, sourcePass)
	source.initialize()
	source.startSigner(sourcePass)
	restoredAddress := mustGenerateEd25519(t, source)
	mustWaitForAddresses(t, source, restoredAddress)
	archive := mustCreateAndExportBackup(t, source, exportPass)

	incoming := filepath.Join(env.root, "recovery-"+filepath.Base(archive))
	copyFile(t, archive, incoming)
	output, err := env.runApadminBatch(exportPass+"\n", "backup", "import", incoming)
	if err != nil {
		t.Fatalf("import recovery fixture: %v\n%s", err, output)
	}
	output, err = env.runApadminBatch(
		exportPass+"\n",
		"restore", "apply", filepath.Base(incoming),
		"--replace-existing",
	)
	if err == nil {
		t.Fatalf("restore checkpoint unexpectedly succeeded:\n%s", output)
	}
	assertSignerState(t, env, "recovery")
	assertSigningBlocked(t, env, address)

	output, err = env.runApadminBatch("y\n", "restore", "rollback")
	if err != nil {
		t.Fatalf("roll back interrupted restore: %v\n%s", err, output)
	}
	assertSignerState(t, env, "unlocked")
	assertCanSign(t, env, address)
	keysResult, err := storeClient(t, env).GetKeys()
	if err != nil {
		t.Fatalf("list keys after restore rollback: %v", err)
	}
	for _, key := range keysResult.Keys {
		if key.Address == restoredAddress {
			t.Fatalf("rolled-back credential %s remains active", restoredAddress)
		}
	}
}

func TestReconcileCommandPromotesVisibleUncertainRestore(t *testing.T) {
	const (
		sourcePass = "reconcile-source-passphrase"
		destPass   = "reconcile-destination-passphrase"
		exportPass = "reconcile-export-passphrase"
	)
	source := newFreshStoreEnv(t, sourcePass)
	source.initialize()
	source.startSigner(sourcePass)
	address := mustGenerateEd25519(t, source)
	mustWaitForAddresses(t, source, address)
	archive := mustCreateAndExportBackup(t, source, exportPass)

	destination := newFreshStoreEnv(t, destPass)
	destination.initialize()
	destination.configureCheckpoint("restore.store_root_replaced", "error")
	destination.startSigner(destPass)
	incoming := filepath.Join(destination.root, "reconcile-"+filepath.Base(archive))
	copyFile(t, archive, incoming)
	output, err := destination.runApadminBatch(exportPass+"\n", "backup", "import", incoming)
	if err != nil {
		t.Fatalf("import reconcile fixture: %v\n%s", err, output)
	}
	output, err = destination.runApadminBatch(exportPass+"\n", "restore", "apply", filepath.Base(incoming))
	if err == nil {
		t.Fatalf("restore checkpoint unexpectedly succeeded:\n%s", output)
	}
	assertSignerState(t, destination, "recovery")
	assertSigningBlocked(t, destination, address)

	output, err = destination.runApadminBatch("", "restore", "reconcile")
	if err != nil {
		t.Fatalf("restore reconcile: %v\n%s", err, output)
	}
	assertSignerState(t, destination, "unlocked")
	mustWaitForAddresses(t, destination, address)
	assertCanSign(t, destination, address)
}

func TestInterruptedRestoreAfterStoreRootReplacementLoadsCommittedGeneration(t *testing.T) {
	const (
		sourcePass = "restore-crash-source"
		destPass   = "restore-crash-destination"
		exportPass = "restore-crash-export"
	)
	source := newFreshStoreEnv(t, sourcePass)
	source.initialize()
	source.startSigner(sourcePass)
	address := mustGenerateEd25519(t, source)
	mustWaitForAddresses(t, source, address)
	archive := mustCreateAndExportBackup(t, source, exportPass)

	destination := newFreshStoreEnv(t, destPass)
	destination.initialize()
	destination.configureCheckpoint("restore.store_root_replaced", "block")
	destination.startSigner(destPass)
	incoming := filepath.Join(destination.root, "crash-"+filepath.Base(archive))
	copyFile(t, archive, incoming)
	output, err := destination.runApadminBatch(exportPass+"\n", "backup", "import", incoming)
	if err != nil {
		t.Fatalf("import restore crash fixture: %v\n%s", err, output)
	}
	restore := destination.startApadminBatch(
		exportPass+"\n",
		"restore", "apply", filepath.Base(incoming),
	)
	destination.waitForCheckpoint(15 * time.Second)
	if err := destination.crashSigner(); err != nil {
		t.Fatalf("crash signer after store-root replacement: %v", err)
	}
	_, _ = restore.wait(10 * time.Second)

	destination.clearCheckpoint()
	destination.startSigner(destPass)
	assertSignerState(t, destination, "unlocked")
	mustWaitForAddresses(t, destination, address)
	assertCanSign(t, destination, address)
	active, keyring, err := genstore.ResolveStoreRoot(
		storepaths.NewPaths(destination.dataDir),
		[]byte(destPass),
	)
	if err != nil {
		t.Fatalf("resolve committed restore after restart: %v", err)
	}
	keyring.Zero()
	manifest, err := genstore.ReadManifest(active)
	if err != nil {
		t.Fatalf("read committed restore manifest: %v", err)
	}
	if manifest.Operation != genstore.OperationCredentialRestore || manifest.ParentID == "" {
		t.Fatalf("restart selected operation %q parent %q", manifest.Operation, manifest.ParentID)
	}
}

func TestRestoreReloadFailureEntersRecoveryUntilExplicitRollback(t *testing.T) {
	const (
		sourcePass = "reload-failure-source"
		destPass   = "reload-failure-destination"
		exportPass = "reload-failure-export"
	)
	source := newFreshStoreEnv(t, sourcePass)
	source.initialize()
	source.startSigner(sourcePass)
	address := mustGenerateEd25519(t, source)
	mustWaitForAddresses(t, source, address)
	archive := mustCreateAndExportBackup(t, source, exportPass)

	destination := newFreshStoreEnv(t, destPass)
	destination.initialize()
	destination.configureCheckpoint("restore.reload_started", "error")
	destination.startSigner(destPass)
	incoming := filepath.Join(destination.root, "reload-"+filepath.Base(archive))
	copyFile(t, archive, incoming)
	output, err := destination.runApadminBatch(exportPass+"\n", "backup", "import", incoming)
	if err != nil {
		t.Fatalf("import reload-failure fixture: %v\n%s", err, output)
	}
	output, err = destination.runApadminBatch(
		exportPass+"\n", "restore", "apply", filepath.Base(incoming),
	)
	if err == nil || !strings.Contains(output, "signing is blocked pending recovery") {
		t.Fatalf("reload failure did not report blocked recovery: err=%v\n%s", err, output)
	}
	assertSignerState(t, destination, "recovery")
	assertSigningBlocked(t, destination, address)

	output, err = destination.runApadminBatch("y\n", "restore", "rollback")
	if err != nil {
		t.Fatalf("explicit rollback after reload failure: %v\n%s", err, output)
	}
	assertSignerState(t, destination, "unlocked")
	keysResult, err := storeClient(t, destination).GetKeys()
	if err != nil {
		t.Fatalf("list keys after explicit rollback: %v", err)
	}
	for _, key := range keysResult.Keys {
		if key.Address == address {
			t.Fatalf("explicitly rolled-back credential %s remains active", address)
		}
	}
}

func TestInterruptedChangePassBeforeRootReplacementKeepsOldAuthority(t *testing.T) {
	const (
		oldPass = "changepass-before-root-old"
		newPass = "changepass-before-root-new"
	)
	env := newFreshStoreEnv(t, oldPass)
	env.initialize()
	env.startSigner(oldPass)
	address := mustGenerateEd25519(t, env)
	mustWaitForAddresses(t, env, address)
	if err := env.stopSigner(); err != nil {
		t.Fatalf("stop signer before checkpoint restart: %v", err)
	}
	env.configureCheckpoint("changepass.successor_published", "block")
	env.startSigner(oldPass)

	input := strings.Join([]string{oldPass, newPass, newPass, "y", ""}, "\n")
	change := env.startApadminBatch(input, "changepass")
	env.waitForCheckpoint(15 * time.Second)
	if err := env.crashSigner(); err != nil {
		t.Fatalf("crash signer before store-root replacement: %v", err)
	}
	_, _ = change.wait(10 * time.Second)

	env.clearCheckpoint()
	env.startSigner(oldPass)
	assertSignerState(t, env, "unlocked")
	mustWaitForAddresses(t, env, address)
	assertCanSign(t, env, address)
	assertPassphraseRejected(t, env, newPass)
	records, err := genstore.ListQuarantined(storepaths.NewPaths(env.dataDir))
	if err != nil {
		t.Fatalf("list quarantined successor: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("quarantined successors = %d, want 1", len(records))
	}
}

func TestInterruptedChangePassAfterRootReplacementUsesNewAuthority(t *testing.T) {
	const (
		oldPass = "changepass-after-root-old"
		newPass = "changepass-after-root-new"
	)
	env := newFreshStoreEnv(t, oldPass)
	env.initialize()
	env.startSigner(oldPass)
	address := mustGenerateEd25519(t, env)
	mustWaitForAddresses(t, env, address)
	if err := env.stopSigner(); err != nil {
		t.Fatalf("stop signer before checkpoint restart: %v", err)
	}
	env.configureCheckpoint("changepass.store_root_replaced", "block")
	env.startSigner(oldPass)

	input := strings.Join([]string{oldPass, newPass, newPass, "y", ""}, "\n")
	change := env.startApadminBatch(input, "changepass")
	env.waitForCheckpoint(15 * time.Second)
	if err := env.crashSigner(); err != nil {
		t.Fatalf("crash signer after store-root replacement: %v", err)
	}
	_, _ = change.wait(10 * time.Second)

	env.clearCheckpoint()
	env.passphrase = newPass
	env.startSigner(newPass)
	assertSignerState(t, env, "unlocked")
	mustWaitForAddresses(t, env, address)
	assertCanSign(t, env, address)
	assertPassphraseRejected(t, env, oldPass)
}

func TestRestoreRepairsDamagedCredentialFromRecoveryMode(t *testing.T) {
	const (
		passphrase = "repair-store-passphrase"
		exportPass = "repair-store-export"
	)
	env := newFreshStoreEnv(t, passphrase)
	env.initialize()
	env.startSigner(passphrase)
	address := mustGenerateEd25519(t, env)
	mustWaitForAddresses(t, env, address)
	archive := mustCreateAndExportBackup(t, env, exportPass)
	if err := env.stopSigner(); err != nil {
		t.Fatalf("stop signer before damage: %v", err)
	}

	paths := storepaths.NewPaths(env.dataDir)
	active, keyring, err := genstore.ResolveStoreRoot(paths, []byte(passphrase))
	if err != nil {
		t.Fatalf("resolve current generation: %v", err)
	}
	keyring.Zero()
	keyPath := filepath.Join(active.KeysDir(), address+".key")
	if err := os.WriteFile(keyPath, []byte("deliberately malformed credential"), 0o600); err != nil {
		t.Fatalf("damage current credential: %v", err)
	}

	env.startSigner(passphrase)
	assertSignerState(t, env, "recovery")
	assertSigningBlocked(t, env, address)
	incoming := filepath.Join(env.root, "repair-"+filepath.Base(archive))
	copyFile(t, archive, incoming)
	output, err := env.runApadminBatch(exportPass+"\n", "backup", "import", incoming)
	if err != nil {
		t.Fatalf("import repair archive: %v\n%s", err, output)
	}
	output, err = env.runApadminBatch(
		exportPass+"\n",
		"restore", "apply", filepath.Base(incoming), "--replace-existing",
	)
	if err != nil {
		t.Fatalf("repair damaged credential by restore: %v\n%s", err, output)
	}
	assertSignerState(t, env, "unlocked")
	mustWaitForAddresses(t, env, address)
	assertCanSign(t, env, address)
	current, repairedKeyring, err := genstore.ResolveStoreRoot(paths, []byte(passphrase))
	if err != nil {
		t.Fatalf("resolve repaired generation: %v", err)
	}
	repairedKeyring.Zero()
	manifest, err := genstore.ReadManifest(current)
	if err != nil {
		t.Fatalf("read repaired generation manifest: %v", err)
	}
	if manifest.RollbackCapability != nil {
		t.Fatal("recovery-mode repair must not be rollback-eligible")
	}
}

func TestMalformedCurrentCredentialRemainsRecoveryBlocked(t *testing.T) {
	const passphrase = "corrupt-store-passphrase"
	env := newFreshStoreEnv(t, passphrase)
	env.initialize()
	env.startSigner(passphrase)
	address := mustGenerateEd25519(t, env)
	mustWaitForAddresses(t, env, address)
	if err := env.stopSigner(); err != nil {
		t.Fatalf("stop signer before corruption: %v", err)
	}

	paths := storepaths.NewPaths(env.dataDir)
	active, keyring, err := genstore.ResolveStoreRoot(paths, []byte(passphrase))
	if err != nil {
		t.Fatalf("resolve current generation: %v", err)
	}
	keyring.Zero()
	keyPath := filepath.Join(active.KeysDir(), address+".key")
	if err := os.WriteFile(keyPath, []byte("deliberately malformed credential"), 0o600); err != nil {
		t.Fatalf("damage current credential: %v", err)
	}

	env.startSigner(passphrase)
	assertSignerState(t, env, "recovery")
	assertSigningBlocked(t, env, address)
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read damaged credential after recovery entry: %v", err)
	}
	if string(data) != "deliberately malformed credential" {
		t.Fatal("recovery startup silently rewrote damaged credential evidence")
	}
}
