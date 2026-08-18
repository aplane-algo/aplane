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

func TestInterruptedRotationResumesOnUnlock(t *testing.T) {
	for _, checkpoint := range []string{
		"rotation.pending_root_published",
		"rotation.root_settled",
	} {
		t.Run(checkpoint, func(t *testing.T) {
			const (
				oldPass = "interrupted-rotation-old"
				newPass = "interrupted-rotation-new"
			)
			env := newFreshStoreEnv(t, oldPass)
			env.initialize()
			env.configureCheckpoint(checkpoint, "block")
			env.startSigner(oldPass)
			address := mustGenerateEd25519(t, env)
			mustWaitForAddresses(t, env, address)

			input := strings.Join([]string{oldPass, newPass, newPass, "y", ""}, "\n")
			change := env.startApadminBatch(input, "changepass")
			env.waitForCheckpoint(15 * time.Second)
			if err := env.crashSigner(); err != nil {
				t.Fatalf("crash signer at %s: %v", checkpoint, err)
			}
			_, _ = change.wait(10 * time.Second)

			env.clearCheckpoint()
			env.passphrase = newPass
			env.startSigner(newPass)
			assertSignerState(t, env, "unlocked")
			mustWaitForAddresses(t, env, address)
			assertCanSign(t, env, address)
			assertPassphraseRejected(t, env, oldPass)
			kr := mustOpenKeyring(t, env, newPass)
			if _, pending := kr.PendingRotation(); pending {
				kr.Zero()
				t.Fatal("restart did not settle interrupted rotation")
			}
			kr.Zero()
			assertNoRotationSnapshot(t, env)
		})
	}
}

func TestInterruptedRotationBeforeRootCommitKeepsOldAuthority(t *testing.T) {
	const (
		oldPass = "precommit-rotation-old"
		newPass = "precommit-rotation-new"
	)
	env := newFreshStoreEnv(t, oldPass)
	env.initialize()
	env.configureCheckpoint("rotation.snapshot_published", "block")
	env.startSigner(oldPass)
	address := mustGenerateEd25519(t, env)
	mustWaitForAddresses(t, env, address)

	input := strings.Join([]string{oldPass, newPass, newPass, "y", ""}, "\n")
	change := env.startApadminBatch(input, "changepass")
	env.waitForCheckpoint(15 * time.Second)
	if err := env.crashSigner(); err != nil {
		t.Fatalf("crash signer before rotation root commit: %v", err)
	}
	_, _ = change.wait(10 * time.Second)

	env.clearCheckpoint()
	env.startSigner(oldPass)
	assertSignerState(t, env, "unlocked")
	mustWaitForAddresses(t, env, address)
	assertCanSign(t, env, address)
	assertPassphraseRejected(t, env, newPass)
	kr := mustOpenKeyring(t, env, oldPass)
	if _, pending := kr.PendingRotation(); pending {
		kr.Zero()
		t.Fatal("pre-commit interruption unexpectedly published a pending root")
	}
	kr.Zero()
	assertNoRotationSnapshot(t, env)
}

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
	env.configureCheckpoint("restore.current_flipped", "error")
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
	destination.configureCheckpoint("restore.current_flipped", "error")
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

func TestInterruptedRestoreAfterCurrentFlipLoadsCommittedGeneration(t *testing.T) {
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
	destination.configureCheckpoint("restore.current_flipped", "block")
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
		t.Fatalf("crash signer after CURRENT flip: %v", err)
	}
	_, _ = restore.wait(10 * time.Second)

	destination.clearCheckpoint()
	destination.startSigner(destPass)
	assertSignerState(t, destination, "unlocked")
	mustWaitForAddresses(t, destination, address)
	assertCanSign(t, destination, address)
	active, err := genstore.Resolve(storepaths.NewPaths(destination.dataDir), "default")
	if err != nil {
		t.Fatalf("resolve committed restore after restart: %v", err)
	}
	manifest, err := genstore.ReadManifest(active)
	if err != nil {
		t.Fatalf("read committed restore manifest: %v", err)
	}
	if manifest.Operation != genstore.OperationCredentialRestore || manifest.ParentID == "" {
		t.Fatalf("restart selected operation %q parent %q", manifest.Operation, manifest.ParentID)
	}
}

func TestRestoreReloadFailureRollsBackAutomatically(t *testing.T) {
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
	if err == nil || !strings.Contains(output, "restore rolled back") {
		t.Fatalf("reload failure did not report automatic rollback: err=%v\n%s", err, output)
	}
	assertSignerState(t, destination, "unlocked")
	keysResult, err := storeClient(t, destination).GetKeys()
	if err != nil {
		t.Fatalf("list keys after automatic rollback: %v", err)
	}
	for _, key := range keysResult.Keys {
		if key.Address == address {
			t.Fatalf("automatically rolled-back credential %s remains active", address)
		}
	}
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
	active, err := genstore.ResolveActive(paths, "default")
	if err != nil {
		t.Fatalf("resolve current generation: %v", err)
	}
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
	current, err := genstore.Resolve(paths, "default")
	if err != nil {
		t.Fatalf("resolve repaired generation: %v", err)
	}
	manifest, err := genstore.ReadManifest(current)
	if err != nil {
		t.Fatalf("read repaired generation manifest: %v", err)
	}
	if manifest.RestoreRollbackEligible {
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
	active, err := genstore.ResolveActive(paths, "default")
	if err != nil {
		t.Fatalf("resolve current generation: %v", err)
	}
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
