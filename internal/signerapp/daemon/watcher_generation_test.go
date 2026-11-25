// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"

	"github.com/aplane-algo/aplane/internal/adminproto"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
)

// watchedGenerations records the directories of every watcher a runtime
// starts through it, and the last one's context.
type watchedGenerations struct {
	mu   sync.Mutex
	dirs [][]string
	last context.Context
}

func (w *watchedGenerations) start(dirs []string, ctx context.Context, _ func() error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.dirs = append(w.dirs, slices.Clone(dirs))
	w.last = ctx
	return nil
}

func (w *watchedGenerations) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.dirs)
}

// requireOnTheActiveGeneration checks that n watchers have started and that
// the last, still running, watches the store root and the generation in
// service's key and key type directories, and nothing else.
func (w *watchedGenerations) requireOnTheActiveGeneration(t *testing.T, ir *productruntime.Runtime, n int) {
	t.Helper()
	active, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	want := []string{ir.KeyPaths().ProductDir(), active.KeysDir(), active.KeyTypeRecordsDir()}
	if len(w.dirs) != n || w.last.Err() != nil || !slices.Equal(w.dirs[len(w.dirs)-1], want) {
		t.Fatalf("%d watchers started, want %d; the last, running = %v, watches\n%q\nwant\n%q",
			len(w.dirs), n, w.last.Err() == nil, w.dirs[len(w.dirs)-1], want)
	}
}

// watcherTestASAChain maps private-dev to a chain that serves asset 9.
type watcherTestASAChain struct{}

const (
	watcherTestGenesis = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	watcherTestCreator = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"
)

func (watcherTestASAChain) Networks() apconfig.GenesisHashNetworkResolver {
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{watcherTestGenesis: "private-dev"})
	if err != nil {
		panic(err)
	}
	return resolver
}

func (watcherTestASAChain) ReadAsset(context.Context, []byte, uint64) (models.AssetParams, error) {
	return models.AssetParams{Creator: watcherTestCreator, Decimals: 2, Total: 1_000_000, UnitName: "XYZ", Name: "Example"}, nil
}

func lockThenUnlock(t *testing.T, server *Signer, passphrase []byte) {
	t.Helper()
	server.productRuntime().Lock()
	if ok, _, msg, code := server.adminServices().UnlockIdentity(context.Background(), passphrase); !ok || code != "" {
		t.Fatalf("UnlockIdentity() = %v, %q, %q", ok, msg, code)
	}
}

// Every admin change that commits a generation moves the key watcher onto it,
// and a reconcile, which commits none, renews the watcher there. Lock and unlock
// start no other.
func TestEveryGenerationCommitMovesTheKeyWatcher(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	backupThenDeleteTheKey(t, server)
	archive := latestArchive(t, server)
	var watched watchedGenerations
	ir.EnsureKeyWatcher(watched.start)
	watched.requireOnTheActiveGeneration(t, ir, 1)

	settings := server.adminServices().adminApp()
	settings.ASAChain = watcherTestASAChain{}
	passphrase, newPassphrase := testPassphrase, []byte("a-new-watcher-passphrase")
	for _, step := range []struct {
		name    string
		commits bool
		run     func(t *testing.T) bool
	}{
		{"apply policy", true, func(t *testing.T) bool {
			return applySignerPolicyDoc(t, server, policytest.Signer(t, policy.DefaultKey, `{"max_fee_microalgos":"4321"}`)).Success
		}},
		{"add an ASA", true, func(t *testing.T) bool {
			looked := settings.LookupASA(adminproto.LookupASARequest{Network: "private-dev", AssetID: 9})
			return settings.AddASA(adminproto.AddASARequest{Confirmed: looked.Asset}).Success
		}},
		{"remove an ASA", true, func(t *testing.T) bool {
			return settings.RemoveASA(adminproto.RemoveASARequest{Network: "private-dev", AssetID: 9}).Success
		}},
		{"restore", true, func(t *testing.T) bool { return restoreForTokenTest(server, archive, "restore", true).Success }},
		{"roll the restore back", true, func(t *testing.T) bool {
			return server.adminServices().backupServices().RollbackRestore(adminproto.RollbackRestoreRequest{OperationID: "rollback"}).Success
		}},
		{"change the store passphrase", true, func(t *testing.T) bool {
			result := server.adminServices().ChangeStorePassphrase(context.Background(), adminproto.ChangeStorePassphraseRequest{
				CurrentPassphrase: slices.Clone(passphrase), NewPassphrase: slices.Clone(newPassphrase)})
			passphrase = newPassphrase
			return result.Success
		}},
		{"reconcile", false, func(t *testing.T) bool { return server.adminServices().backupServices().ReconcileStore().Success }},
		{"a policy apply in doubt", true, func(t *testing.T) bool {
			return watcherTestUncertainApply(t, server).CommitUncertain && ir.IsRecovery()
		}},
		{"reconcile out of recovery", false, func(t *testing.T) bool {
			return server.adminServices().backupServices().ReconcileStore().Success && ir.IsUnlocked()
		}},
	} {
		started := watched.count()
		before, err := ir.ActivePaths()
		if err != nil {
			t.Fatal(err)
		}
		ir.MarkDirty()
		if !step.run(t) {
			t.Fatalf("%s failed", step.name)
		}
		after, err := ir.ActivePaths()
		if err != nil {
			t.Fatal(err)
		}
		if committed := after.GenerationID() != before.GenerationID(); committed != step.commits {
			t.Fatalf("%s committed a generation = %v", step.name, committed)
		}
		t.Log(step.name)
		watched.requireOnTheActiveGeneration(t, ir, started+1)
		if ir.IsUnlocked() {
			lockThenUnlock(t, server, passphrase)
			watched.requireOnTheActiveGeneration(t, ir, started+1)
		}
	}
}

// watcherTestUncertainApply applies a policy whose commit may or may not have
// landed.
func watcherTestUncertainApply(t *testing.T, server *Signer) adminproto.ApplyPolicyResult {
	t.Helper()
	identityDir := server.keyPaths.ProductDir()
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == identityDir {
			return errors.New("simulated directory sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()
	return applySignerPolicyDoc(t, server, policytest.Signer(t, policy.DefaultKey, `{"max_fee_microalgos":"8765"}`))
}

// A passphrase change that ends locked leaves the watcher on the generation it
// was on, not on the store root alone, and the unlock that follows moves it.
func TestAPassphraseChangeThatEndsLockedLeavesTheWatcher(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	var watched watchedGenerations
	ir.EnsureKeyWatcher(watched.start)
	newPassphrase := []byte("a-new-watcher-passphrase")

	failing, opts := true, testProductBuildOptions(server)
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*productruntime.Loaded, error) {
		if failing {
			return nil, errors.New("injected build failure")
		}
		return signerstartup.Build(ir, opts, kr)
	}, productruntime.ReloadEffects{})
	result := server.adminServices().ChangeStorePassphrase(context.Background(), adminproto.ChangeStorePassphraseRequest{
		CurrentPassphrase: slices.Clone(testPassphrase), NewPassphrase: slices.Clone(newPassphrase)})
	failing = false
	if result.Success || !result.RootCommitted || ir.IsUnlocked() || ir.IsRecovery() {
		t.Fatalf("ChangeStorePassphrase() = %+v, state %v; want a committed change that ends locked", result, ir.GetState())
	}
	if n := watched.count(); n != 1 || watched.last.Err() != nil {
		t.Fatalf("%d watchers started, the last running = %v; want the first, left running", n, watched.last.Err() == nil)
	}
	if ok, _, msg, code := server.adminServices().UnlockIdentity(context.Background(), newPassphrase); !ok || code != "" {
		t.Fatalf("UnlockIdentity() = %v, %q, %q", ok, msg, code)
	}
	watched.requireOnTheActiveGeneration(t, ir, 2)
}

// A restore, a rollback and a reconcile asked of a locked signer leave the
// running watcher as it is.
func TestBackupChangesOfALockedSignerLeaveTheWatcher(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	backupThenDeleteTheKey(t, server)
	var watched watchedGenerations
	ir.EnsureKeyWatcher(watched.start)
	ir.Lock()
	backups := server.adminServices().backupServices()
	if restoreForTokenTest(server, latestArchive(t, server), "restore", true).Success ||
		backups.RollbackRestore(adminproto.RollbackRestoreRequest{OperationID: "rollback"}).Success ||
		backups.ReconcileStore().Success {
		t.Fatal("a locked signer restored, rolled back or reconciled")
	}
	if n := watched.count(); n != 1 || watched.last.Err() != nil {
		t.Fatalf("%d watchers started, the last running = %v; want the first, left running", n, watched.last.Err() == nil)
	}
}

// A reconcile out of recovery then reloads what the watcher saw in recovery,
// which marks the store dirty there.
func TestAReconcileOutOfRecoveryReloadsWhatTheWatcherSaw(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	var watched watchedGenerations
	ir.EnsureKeyWatcher(watched.start)
	opts := testProductBuildOptions(server)
	builds := 0
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*productruntime.Loaded, error) {
		builds++
		return signerstartup.Build(ir, opts, kr)
	}, productruntime.ReloadEffects{})
	for _, dirty := range []bool{false, true} {
		ir.EnterRecovery(nil)
		if dirty {
			ir.MarkDirty()
		}
		builds = 0
		if result := server.adminServices().backupServices().ReconcileStore(); !result.Success || !ir.IsUnlocked() {
			t.Fatalf("ReconcileStore() = %+v, state %v", result, ir.GetState())
		}
		want := 1
		if dirty {
			want = 2
		}
		if builds != want {
			t.Fatalf("dirty %v: %d builds, want %d", dirty, builds, want)
		}
	}
}

// With the real watcher, a file dropped into the generation in service is seen
// after a commit, after a reconcile, a restore or a rollback that leaves a
// recovery no unlock started a watcher for, and after a reconcile of a generation
// whose directory was replaced.
func TestTheKeyWatcherSeesTheGenerationInService(t *testing.T) {
	for name, enter := range map[string]func(t *testing.T, server *Signer){
		"after a policy apply": func(t *testing.T, server *Signer) {
			server.productRuntime().EnsureKeyWatcher(startKeyWatcherForDir)
			if result := applySignerPolicyDoc(t, server, policytest.Signer(t, policy.DefaultKey, `{"max_fee_microalgos":"4321"}`)); !result.Success {
				t.Fatalf("ApplyPolicy() = %+v", result)
			}
		},
		"after a reconcile out of recovery": func(t *testing.T, server *Signer) {
			server.productRuntime().EnterRecovery(nil)
			if result := server.adminServices().backupServices().ReconcileStore(); !result.Success {
				t.Fatalf("ReconcileStore() = %+v", result)
			}
		},
		"after a reconcile of a replaced directory": func(t *testing.T, server *Signer) {
			ir := server.productRuntime()
			ir.EnsureKeyWatcher(startKeyWatcherForDir)
			active, err := ir.ActivePaths()
			if err != nil {
				t.Fatal(err)
			}
			aside := filepath.Join(t.TempDir(), "keys")
			if err := os.Rename(active.KeysDir(), aside); err != nil {
				t.Fatal(err)
			}
			if err := os.CopyFS(active.KeysDir(), os.DirFS(aside)); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(active.KeysDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			if result := server.adminServices().backupServices().ReconcileStore(); !result.Success {
				t.Fatalf("ReconcileStore() = %+v", result)
			}
		},
		"after a restore out of recovery": func(t *testing.T, server *Signer) {
			backupThenDeleteTheKey(t, server)
			server.productRuntime().EnterRecovery(nil)
			if result := restoreForTokenTest(server, latestArchive(t, server), "restore", true); !result.Success {
				t.Fatalf("RestoreBackup() = %+v", result)
			}
		},
		"after a rollback out of recovery": func(t *testing.T, server *Signer) {
			backupThenDeleteTheKey(t, server)
			if result := restoreForTokenTest(server, latestArchive(t, server), "restore", true); !result.Success {
				t.Fatalf("RestoreBackup() = %+v", result)
			}
			server.productRuntime().StopKeyWatcher()
			server.productRuntime().EnterRecovery(nil)
			if result := server.adminServices().backupServices().RollbackRestore(adminproto.RollbackRestoreRequest{OperationID: "rollback"}); !result.Success {
				t.Fatalf("RollbackRestore() = %+v", result)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := characterizedSigner(t)
			ir := server.productRuntime()
			enter(t, server)
			if !ir.IsUnlocked() {
				t.Fatalf("state = %v, want unlocked", ir.GetState())
			}
			// Past the debounce of any event of the change itself, so only the
			// file below can cause the reload.
			time.Sleep(time.Second)
			active, err := ir.ActivePaths()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(active.KeysDir(), "stray.key"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			for deadline := time.Now().Add(5 * time.Second); !ir.IsRecovery(); time.Sleep(20 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatal("the watcher did not see a file dropped into the generation in service")
				}
			}
		})
	}
}
