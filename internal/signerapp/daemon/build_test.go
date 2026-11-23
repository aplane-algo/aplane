// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// buildOnce runs the reload's build over the generation the store selects,
// with the keyring in service, and returns what it built.
func buildOnce(t *testing.T, server *Signer) (*productruntime.Loaded, error) {
	t.Helper()
	ir := server.productRuntime()
	var loaded *productruntime.Loaded
	var buildErr error
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		loaded, buildErr = signerstartup.Build(ir, testProductBuildOptions(server), kr)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(loaded.Discard)
	return loaded, buildErr
}

// The build changes nothing live. It prepares the generation's templates and
// registers none, verifies the policy and publishes none, and scans the keys
// and publishes no key maps. Here the store holds an enabled template whose
// provider is not registered, as a reload after a restore finds one.
func TestTheBuildChangesNothingLive(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	importCharacterizedTemplate(t, server)
	keyType := testTemplateKeyType(characterizedFamily(server))
	lsigprovider.Unregister(keyType)
	t.Cleanup(func() { lsigprovider.Unregister(keyType) })
	policy, revision, keys := ir.NodePolicy(), ir.KeysetRevision(), ir.KeyCount()

	loaded, err := buildOnce(t, server)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	if lsigprovider.Get(keyType) != nil {
		t.Fatal("the build registered the template's provider")
	}
	if ir.NodePolicy() != policy || ir.KeysetRevision() != revision || ir.KeyCount() != keys {
		t.Fatal("the build changed the policy or the key maps in service")
	}
	if !loaded.PolicyVerified || loaded.Policy == nil || loaded.Policy == policy || len(loaded.Contents.Keys) != keys {
		t.Fatalf("the build returned policy verified %v and %d key(s), want its own verified policy and the %d key(s) held", loaded.PolicyVerified, len(loaded.Contents.Keys), keys)
	}
}

// writeTokenEntry writes name into the selected generation's source token
// directory.
func writeTokenEntry(t *testing.T, server *Signer, name string) {
	t.Helper()
	active, err := server.productRuntime().ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(active.SourceTokensDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(active.SourceTokensDir(), name), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The build classifies what it finds among the source tokens, which decides
// the outcome of a failed reload. A damaged token file is a content defect of
// the selected generation, after the policy was verified, so the recovery it
// enters shows the policy. A token file on a signer node is a role conflict,
// which fails the node closed, and not a content defect.
func TestTheBuildClassifiesTheSourceTokens(t *testing.T) {
	t.Run("damaged on a cosigner", func(t *testing.T) {
		server, cleanup := setupTestNode(t, noderole.RoleCosigner, cosignerDefaultWithSources(t))
		t.Cleanup(cleanup)
		t.Cleanup(server.productRuntime().StopKeyWatcher)
		writeTokenEntry(t, server, "notes.txt")
		loaded, err := buildOnce(t, server)
		if !errors.Is(err, sourcetokens.ErrDamaged) || !errors.Is(err, signertemplates.ErrGenerationValidation) {
			t.Fatalf("Build() = %v, want a damaged token file as a generation validation failure", err)
		}
		if !loaded.PolicyVerified {
			t.Fatal("the build failed before it verified the policy")
		}
	})
	t.Run("a token file on a signer", func(t *testing.T) {
		server := characterizedSigner(t)
		writeTokenEntry(t, server, storepaths.SourceTokensDefaultSelector+storepaths.SourceTokenFileExtension)
		_, err := buildOnce(t, server)
		if !errors.Is(err, keyclass.ErrNodeRoleConflict) || errors.Is(err, signertemplates.ErrGenerationValidation) {
			t.Fatalf("Build() = %v, want a role conflict and no generation validation failure", err)
		}
	})
}

// A restore or a rollback begun in recovery publishes recovery's view, with
// no keys, and the reconcile that follows it publishes them as it lifts
// recovery: the answer counts the keys the signer ends serving.
func TestARestoreOrRollbackInRecoveryAnswersTheKeysItEndsWith(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	backupThenDeleteTheKey(t, server)
	ir.EnterRecovery(nil)
	restored := restoreForTokenTest(server, latestArchive(t, server), "restore", true)
	if !restored.Success || !ir.IsUnlocked() || restored.KeyCount != ir.KeyCount() || ir.KeyCount() == 0 {
		t.Fatalf("RestoreBackup() in recovery = %+v, state %v, %d key(s); want unlocked, answering the keys it serves", restored, ir.GetState(), ir.KeyCount())
	}

	server = characterizedSigner(t)
	ir = server.productRuntime()
	backupThenDeleteTheKey(t, server)
	if result := restoreForTokenTest(server, latestArchive(t, server), "restore", true); !result.Success {
		t.Fatalf("RestoreBackup() = %+v", result)
	}
	ir.EnterRecovery(nil)
	rolled := server.adminServices().backupServices().RollbackRestore(adminproto.RollbackRestoreRequest{OperationID: "rollback"})
	if !rolled.Success || !ir.IsUnlocked() || rolled.KeyCount != ir.KeyCount() {
		t.Fatalf("RollbackRestore() in recovery = %+v, state %v, %d key(s); want unlocked, answering the keys it serves", rolled, ir.GetState(), ir.KeyCount())
	}
}

// A reconcile that a lock overtakes during its build publishes, and the
// lock's cleanup clears what it published: the answer is the locked signer's,
// not recovery_blocked, since no recovery was entered.
func TestAReconcileALockOvertookAnswersLocked(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	opts := testProductBuildOptions(server)
	var lockDone sync.WaitGroup
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*productruntime.Loaded, error) {
		lockDone.Add(1)
		go func() {
			defer lockDone.Done()
			ir.Lock()
		}()
		for ir.GetState() != signerruntime.SignerStateLocked {
			time.Sleep(time.Millisecond)
		}
		return signerstartup.Build(ir, opts, kr)
	}, productruntime.ReloadEffects{})
	result := server.adminServices().backupServices().ReconcileStore()
	lockDone.Wait()
	if result.Success || result.Code != protocol.ErrCodeSignerLocked || result.State != signerruntime.SignerStateLocked.String() {
		t.Fatalf("ReconcileStore() overtaken by a lock = %+v, want the locked answer", result)
	}
}

// wireBuildWith wires the reload's own build, with before run ahead of each
// build. fromPassphrase is set for a build with a keyring an unlock or a
// passphrase change opened, rather than the keyring in service; an error
// from before is the build's.
func wireBuildWith(server *Signer, before func(fromPassphrase bool) error) {
	ir := server.productRuntime()
	opts := testProductBuildOptions(server)
	hooks := server.productBuildHooks()
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*productruntime.Loaded, error) {
		inService := false
		_ = ir.KeyStore().WithKeyring(func(current *crypto.Keyring) error {
			inService = current == kr
			return nil
		})
		if err := before(!inService); err != nil {
			return nil, err
		}
		return signerstartup.Build(ir, opts, kr)
	}, productruntime.ReloadEffects{
		Audit: hooks.ReloadAuditLog, NotifyKeysChanged: hooks.NotifyKeysChanged,
		Info: hooks.Info, Warn: hooks.Warn, NodeFailClosed: hooks.NodeFailClosed,
	})
}

// countBuilds wires the reload's own build and counts the builds: all of
// them, and those with a keyring an unlock opened.
func countBuilds(server *Signer) (all, fromPassphrase *atomic.Int32) {
	all, fromPassphrase = &atomic.Int32{}, &atomic.Int32{}
	wireBuildWith(server, func(passphrase bool) error {
		all.Add(1)
		if passphrase {
			fromPassphrase.Add(1)
		}
		return nil
	})
	return all, fromPassphrase
}
