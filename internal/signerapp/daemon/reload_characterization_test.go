// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
)

// These tests record what each caller of a reload leaves behind when the
// reload fails, as the code stands. They are the reference for the reload
// redesign (build first, publish last): each later change either keeps a row
// as it is or changes it on purpose. A row is what the signer does, not what
// it should do; the rows the redesign means to change say so.

// reloadFault is a condition planted in the store or the configuration just
// before a caller's reload runs, so the caller's own work, a commit or a
// write, is done on a sound store and only the reload meets the fault.
type reloadFault struct {
	name  string
	plant func(t *testing.T, server *Signer)
	// atScan plants the fault when the reload reaches its key scan, after it
	// has published the policy and the source tokens, not when it begins.
	atScan bool
	// scanErr, when set, is what the key scan returns in place of scanning,
	// with the store bound to the root's selection as a scan that fails
	// leaves it.
	scanErr error
}

// plantAtScan is the keystore a reload scans, with a fault planted first.
type plantAtScan struct {
	*keystore.FileKeyStore
	plant   func()
	scanErr error
}

func (k plantAtScan) Scan() error {
	k.plant()
	if k.scanErr == nil {
		return k.FileKeyStore.Scan()
	}
	if err := k.BindStoreRootSelection(); err != nil {
		return err
	}
	return fmt.Errorf("failed to scan keys directory: %w", k.scanErr)
}

// everyGeneration calls fn with each generation directory's paths. A fault in
// a generation's content is planted in all of them: the caller may have just
// committed a new one, and the reload reads whichever the store root selects.
func everyGeneration(t *testing.T, server *Signer, fn func(dir string)) {
	t.Helper()
	entries, err := os.ReadDir(server.keyPaths.GenerationsDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		fn(server.keyPaths.GenerationDir(entry.Name()))
	}
}

var reloadFaults = []reloadFault{
	// The store root file is damaged and no longer parses. A reload on the
	// keyring in service fails where it follows the root's selection, and
	// leaves no binding; a reload with a passphrase fails before that, where
	// it opens the root, and leaves the binding it found.
	{name: "root", plant: func(t *testing.T, server *Signer) {
		path := server.keyPaths.StoreRootPath()
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("damaged"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.WriteFile(path, original, 0o600) })
	}},
	// The configured networks no longer pass the policy verification: a
	// failure that is not a defect in the generation, before the reload has
	// published anything.
	{name: "policy", plant: func(t *testing.T, server *Signer) {
		server.config.GenesisHashNetworks = map[string]string{"not-a-genesis-hash": "lab"}
		t.Cleanup(func() { server.config.GenesisHashNetworks = nil })
	}},
	// A key type record that does not parse: a content defect the template
	// registration reports, after the policy and the tokens are published.
	{name: "keytype", plant: func(t *testing.T, server *Signer) {
		everyGeneration(t, server, func(dir string) {
			if err := os.WriteFile(filepath.Join(dir, "keytypes", "broken.json"), []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}},
	// A keys directory that cannot be read from the key scan on: a failure
	// that is not a defect in the generation, after the reload has published
	// the policy and the source tokens.
	{name: "scan", atScan: true, plant: func(t *testing.T, server *Signer) {
		everyGeneration(t, server, func(dir string) {
			keys := filepath.Join(dir, "keys")
			if err := os.Chmod(keys, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(keys, 0o700) })
		})
	}},
	// Two key files that resolve to one address. No store this suite can
	// write holds such a pair, so the scan's answer for one is put in its
	// place.
	{name: "collision", atScan: true, plant: func(*testing.T, *Signer) {},
		scanErr: &apkeys.AddressCollisionError{Collisions: map[string][]string{"ADDR": {"keys/ADDR.key", "keys/ADDR.cos"}}}},
	// A file in keys/ that is no credential: a content defect the scan
	// reports.
	{name: "stray", plant: func(t *testing.T, server *Signer) {
		everyGeneration(t, server, func(dir string) {
			if err := os.WriteFile(filepath.Join(dir, "keys", "notes.txt"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}},
}

// plantBeforeReload plants fault when the next reload begins, and runs the
// reload as wired.
func plantBeforeReload(t *testing.T, server *Signer, fault reloadFault) {
	t.Helper()
	ir := server.productRuntime()
	opts, hooks := testProductBuildOptions(server), server.productBuildHooks()
	var once sync.Once
	ir.SetReloadFunc(func(passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		svc := signerstartup.NewReloadService(ir, opts, hooks, session)
		plant := func() { once.Do(func() { fault.plant(t, server) }) }
		if fault.atScan {
			svc.KeyStore = plantAtScan{FileKeyStore: ir.KeyStore(), plant: plant, scanErr: fault.scanErr}
		} else {
			plant()
		}
		return svc.Reload(passphrase)
	})
	// The callers that build before they publish meet the same faults. A
	// fault at the scan fails the build where its scan stands: everything
	// before it is built from the store as it was, and then the scan runs
	// on the planted fault, or answers with the injected error.
	effects := productruntime.ReloadEffects{
		Audit: hooks.ReloadAuditLog, NotifyKeysChanged: hooks.NotifyKeysChanged,
		Info: hooks.Info, Warn: hooks.Warn, NodeFailClosed: hooks.NodeFailClosed,
	}
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*productruntime.Loaded, error) {
		if !fault.atScan {
			once.Do(func() { fault.plant(t, server) })
			return signerstartup.Build(ir, opts, kr)
		}
		loaded, err := signerstartup.Build(ir, opts, kr)
		if err != nil {
			return loaded, err
		}
		once.Do(func() { fault.plant(t, server) })
		if fault.scanErr == nil {
			loaded.Contents, err = keystore.ScanGeneration(*loaded.Selection, kr)
		} else {
			loaded.Contents, err = keystore.Contents{Selection: loaded.Selection}, fmt.Errorf("failed to scan keys directory: %w", fault.scanErr)
		}
		if err != nil {
			return loaded, fmt.Errorf("failed to rescan keys directory: %w", err)
		}
		return loaded, nil
	}, effects)
}

// servedView is what a signer served before a caller ran.
type servedView struct {
	policy *policyruntime.NodePolicy
}

func viewBefore(server *Signer) servedView {
	return servedView{policy: server.productRuntime().NodePolicy()}
}

// newTestPassphrase is the passphrase the passphrase change moves the store
// to.
var newTestPassphrase = []byte("new-admin-passphrase")

// rootSelection returns the generation the store root selects, read from the
// file with whichever passphrase opens it.
func rootSelection(server *Signer) (string, bool) {
	for _, passphrase := range [][]byte{testPassphrase, newTestPassphrase} {
		if selected, kr, err := genstore.OpenStoreRootSelection(server.keyPaths, passphrase); err == nil {
			kr.Zero()
			return selected.GenerationID(), true
		}
	}
	return "", false
}

// describe renders what the signer serves now: its state; whether a keyring
// is open; whether the runtime is bound to the generation the store root
// selects, to one the root has left (superseded), or to none; whether the
// policy is the one served before; and the key count. The source tokens are
// recorded apart (TestAFailedReconcileLeavesRecoveryNoSourceTokens): a
// signer node's store holds none.
func (before servedView) describe(server *Signer) string {
	ir := server.productRuntime()
	keyring := "open"
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err != nil {
		keyring = "closed"
	}
	generation := "none"
	if active, err := ir.ActivePaths(); err == nil {
		switch selected, readable := rootSelection(server); {
		case !readable:
			generation = "bound"
		case selected == active.GenerationID():
			generation = "selected"
		default:
			generation = "superseded"
		}
	}
	policyView := "replaced"
	switch ir.NodePolicy() {
	case nil:
		policyView = "none"
	case before.policy:
		policyView = "kept"
	}
	return fmt.Sprintf("%v keyring=%s generation=%s policy=%s keys=%d",
		ir.GetState(), keyring, generation, policyView, ir.KeyCount())
}

// reloadCaller is one way into a reload: from sets the signer up, and run
// makes the call and returns its answer's code.
type reloadCaller struct {
	name string
	from func(t *testing.T, server *Signer)
	run  func(t *testing.T, server *Signer) string
}

// characterizedSigner is an unlocked test signer with one key, and the key
// watcher stopped at the end.
func characterizedSigner(t *testing.T) *Signer {
	t.Helper()
	server, cleanup := setupTestSigner(t)
	t.Cleanup(cleanup)
	t.Cleanup(server.productRuntime().StopKeyWatcher)
	generateTestKey(t, server, "ed25519")
	return server
}

// backupThenDeleteTheKey makes a backup that holds the signer's key, deletes
// the key and generates another, so a restore of the backup has a key to
// bring back and commits a generation, and the signer serves one key that a
// failed reload either keeps or empties.
func backupThenDeleteTheKey(t *testing.T, server *Signer) {
	t.Helper()
	backupForTokenTest(t, server)
	if result := server.adminServices().keyApp().DeleteKey(context.Background(), adminproto.DeleteKeyRequest{Address: heldAddress(t, server)}); !result.Success {
		t.Fatalf("DeleteKey() = %+v", result)
	}
	generateTestKey(t, server, "ed25519")
}

// heldAddress returns the address of the one key the signer holds.
func heldAddress(t *testing.T, server *Signer) string {
	t.Helper()
	for address := range server.productRuntime().KnownAddresses() {
		return address
	}
	t.Fatal("the signer holds no key")
	return ""
}

// characterizedFamily names a generic template family for server alone: the
// LogicSig provider registry is process-wide, and a family one subtest
// registered would be met by the next.
func characterizedFamily(server *Signer) string {
	return "characterized-" + filepath.Base(filepath.Dir(server.dataDir))
}

// characterizedProvider reports whether the template's LogicSig provider is
// in the process-wide registry: "registered" or "none".
func characterizedProvider(server *Signer) string {
	if lsigprovider.Get(testTemplateKeyType(characterizedFamily(server))) != nil {
		return "registered"
	}
	return "none"
}

func importCharacterizedTemplate(t *testing.T, server *Signer) {
	t.Helper()
	result := server.adminServices().templateServices().ImportInstalledTemplate(adminproto.ImportInstalledTemplateRequest{
		TemplateYAML: renderGenericTemplateYAML(characterizedFamily(server), 1, "Characterized", "installed before the reload under test"),
	})
	if !result.Success {
		t.Fatalf("ImportInstalledTemplate() = %+v", result)
	}
}

// latestArchive returns the path of the backup archive made last.
func latestArchive(t *testing.T, server *Signer) string {
	t.Helper()
	archives, err := filepath.Glob(filepath.Join(server.keyPaths.ProductBackupsDir(), "*"))
	if err != nil || len(archives) == 0 {
		t.Fatalf("no backup archive: %v", err)
	}
	return archives[len(archives)-1]
}

func unlockCode(success bool, _ int, errMsg, code string) string {
	if success && code == "" {
		return "ok"
	}
	if code == "" {
		return "error: " + errMsg
	}
	return code
}

var reloadCallers = []reloadCaller{
	{
		name: "unlock from locked",
		from: func(_ *testing.T, server *Signer) { server.productRuntime().Lock() },
		run: func(_ *testing.T, server *Signer) string {
			return unlockCode(server.adminServices().UnlockIdentity(testPassphrase))
		},
	},
	{
		name: "unlock from recovery",
		from: func(_ *testing.T, server *Signer) { server.productRuntime().EnterRecovery(nil) },
		run: func(_ *testing.T, server *Signer) string {
			return unlockCode(server.adminServices().UnlockIdentity(testPassphrase))
		},
	},
	{
		name: "startup unlock",
		from: func(_ *testing.T, server *Signer) { server.productRuntime().Lock() },
		run: func(_ *testing.T, server *Signer) string {
			passphrase := append([]byte(nil), testPassphrase...)
			return fmt.Sprintf("started=%v", server.unlockAtStartup(server.productRuntime(), passphrase))
		},
	},
	{
		name: "passphrase change",
		run: func(_ *testing.T, server *Signer) string {
			result := server.adminServices().ChangeStorePassphrase(context.Background(), adminproto.ChangeStorePassphraseRequest{
				CurrentPassphrase: testPassphrase, NewPassphrase: newTestPassphrase,
			})
			return fmt.Sprintf("success=%v code=%s committed=%v", result.Success, result.Code, result.RootCommitted)
		},
	},
	{
		name: "policy apply",
		run: func(t *testing.T, server *Signer) string {
			result := applySignerPolicyDoc(t, server, policytest.Signer(t, policy.DefaultKey, `{"max_fee_microalgos":"4321"}`))
			return fmt.Sprintf("success=%v code=%s uncertain=%v", result.Success, result.Code, result.CommitUncertain)
		},
	},
	{
		name: "reconcile",
		run: func(_ *testing.T, server *Signer) string {
			result := server.adminServices().backupServices().ReconcileStore()
			return fmt.Sprintf("success=%v code=%s", result.Success, result.Code)
		},
	},
	{
		name: "reconcile in recovery",
		from: func(_ *testing.T, server *Signer) { server.productRuntime().EnterRecovery(nil) },
		run: func(_ *testing.T, server *Signer) string {
			result := server.adminServices().backupServices().ReconcileStore()
			return fmt.Sprintf("success=%v code=%s", result.Success, result.Code)
		},
	},
	{
		name: "key generation",
		run: func(_ *testing.T, server *Signer) string {
			result := server.adminServices().keyApp().GenerateKey(context.Background(), adminproto.GenerateKeyRequest{KeyType: "ed25519"})
			return fmt.Sprintf("success=%v code=%s", result.Success, result.Code)
		},
	},
	{
		name: "key import",
		run: func(_ *testing.T, server *Signer) string {
			result := server.adminServices().keyApp().ImportKey(context.Background(), adminproto.ImportKeyRequest{
				KeyType: "ed25519", Mnemonic: []byte(testImportMnemonic),
			})
			return fmt.Sprintf("success=%v code=%s", result.Success, result.Code)
		},
	},
	{
		name: "key deletion",
		run: func(t *testing.T, server *Signer) string {
			result := server.adminServices().keyApp().DeleteKey(context.Background(), adminproto.DeleteKeyRequest{Address: heldAddress(t, server)})
			return fmt.Sprintf("success=%v code=%s", result.Success, result.Code)
		},
	},
	{
		name: "template import",
		run: func(_ *testing.T, server *Signer) string {
			result := server.adminServices().templateServices().ImportInstalledTemplate(adminproto.ImportInstalledTemplateRequest{
				TemplateYAML: renderGenericTemplateYAML(characterizedFamily(server), 1, "Characterized", "imported before a failed reload"),
			})
			return fmt.Sprintf("success=%v code=%s provider=%v", result.Success, result.Code, characterizedProvider(server))
		},
	},
	{
		name: "template removal",
		from: importCharacterizedTemplate,
		run: func(_ *testing.T, server *Signer) string {
			result := server.adminServices().templateServices().RemoveInstalledTemplate(adminproto.RemoveInstalledTemplateRequest{
				KeyType: testTemplateKeyType(characterizedFamily(server)),
			})
			return fmt.Sprintf("success=%v code=%s provider=%v", result.Success, result.Code, characterizedProvider(server))
		},
	},
	{
		name: "key type deactivation",
		from: importCharacterizedTemplate,
		run: func(_ *testing.T, server *Signer) string {
			result := server.adminServices().templateServices().DeactivateKeyType(adminproto.DeactivateKeyTypeRequest{
				KeyType: testTemplateKeyType(characterizedFamily(server)),
			})
			return fmt.Sprintf("success=%v code=%s provider=%v", result.Success, result.Code, characterizedProvider(server))
		},
	},
	{
		name: "key type activation",
		from: func(t *testing.T, server *Signer) {
			importCharacterizedTemplate(t, server)
			keyType := testTemplateKeyType(characterizedFamily(server))
			if result := server.adminServices().templateServices().DeactivateKeyType(adminproto.DeactivateKeyTypeRequest{KeyType: keyType}); !result.Success {
				t.Fatalf("DeactivateKeyType() = %+v", result)
			}
		},
		run: func(_ *testing.T, server *Signer) string {
			result := server.adminServices().templateServices().ActivateKeyType(adminproto.ActivateKeyTypeRequest{
				KeyType: testTemplateKeyType(characterizedFamily(server)),
			})
			return fmt.Sprintf("success=%v code=%s provider=%v", result.Success, result.Code, characterizedProvider(server))
		},
	},
	{
		name: "restore",
		from: backupThenDeleteTheKey,
		run: func(t *testing.T, server *Signer) string {
			result := restoreForTokenTest(server, latestArchive(t, server), "restore", true)
			return fmt.Sprintf("success=%v code=%s uncertain=%v", result.Success, result.Code, result.CommitUncertain)
		},
	},
	{
		name: "rollback",
		from: func(t *testing.T, server *Signer) {
			backupThenDeleteTheKey(t, server)
			if result := restoreForTokenTest(server, latestArchive(t, server), "restore", true); !result.Success {
				t.Fatalf("RestoreBackup() = %+v", result)
			}
		},
		run: func(_ *testing.T, server *Signer) string {
			result := server.adminServices().backupServices().RollbackRestore(adminproto.RollbackRestoreRequest{OperationID: "rollback"})
			return fmt.Sprintf("success=%v code=%s uncertain=%v", result.Success, result.Code, result.CommitUncertain)
		},
	},
	{
		name: "watcher",
		run: func(_ *testing.T, server *Signer) string {
			var onChange func() error
			server.productRuntime().StopKeyWatcher()
			server.productRuntime().EnsureKeyWatcher(func(_ []string, _ context.Context, reload func() error) error {
				onChange = reload
				return nil
			})
			return fmt.Sprintf("failed=%v", onChange() != nil)
		},
	},
}

// afterAFailedReload is, for each caller and each fault, the caller's answer and
// the view the signer is left serving (servedView.describe).
//
// The callers that build before they publish (a store-root commit's and the
// reconcile's) end every failure in recovery's own view: no keys, and the
// policy their build verified, or none when it failed before verifying one.
// Recovery entered any other way holds no keys either.
var afterAFailedReload = map[string]map[string]string{
	"unlock from locked": {
		"root":      "unlock_failed -> locked keyring=closed generation=none policy=kept keys=0",
		"policy":    "unlock_failed -> locked keyring=closed generation=none policy=kept keys=0",
		"keytype":   "recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "unlock_failed -> locked keyring=closed generation=none policy=replaced keys=0",
		"collision": "recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0", // an address collision is a content defect: recovery
		"stray":     "recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"unlock from recovery": {
		"root":      "unlock_failed -> recovery keyring=open generation=bound policy=kept keys=0",
		"policy":    "unlock_failed -> recovery keyring=open generation=selected policy=kept keys=0",
		"keytype":   "recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "unlock_failed -> recovery keyring=open generation=selected policy=replaced keys=0",
		"collision": "recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0", // an address collision is a content defect: recovery
		"stray":     "recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"startup unlock": {
		"root":      "started=false -> locked keyring=closed generation=none policy=kept keys=0",
		"policy":    "started=false -> locked keyring=closed generation=none policy=kept keys=0",
		"keytype":   "started=true -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "started=false -> locked keyring=closed generation=none policy=replaced keys=0",
		"collision": "started=true -> recovery keyring=open generation=selected policy=replaced keys=0", // an address collision is a content defect: recovery
		"stray":     "started=true -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"passphrase change": {
		"root":      "success=false code=passphrase_change_failed committed=true -> locked keyring=closed generation=none policy=kept keys=0",
		"policy":    "success=false code=passphrase_change_failed committed=true -> locked keyring=closed generation=none policy=kept keys=0",
		"keytype":   "success=false code=passphrase_change_failed committed=true -> locked keyring=closed generation=none policy=replaced keys=0",
		"scan":      "success=false code=passphrase_change_failed committed=true -> locked keyring=closed generation=none policy=replaced keys=0",
		"collision": "success=false code=passphrase_change_failed committed=true -> locked keyring=closed generation=none policy=replaced keys=0",
		"stray":     "success=false code=passphrase_change_failed committed=true -> locked keyring=closed generation=none policy=replaced keys=0",
	},
	"policy apply": {
		"root":      "success=false code=policy_reload_failed uncertain=true -> recovery keyring=open generation=none policy=none keys=0",
		"policy":    "success=false code=policy_reload_failed uncertain=true -> recovery keyring=open generation=selected policy=none keys=0",
		"keytype":   "success=false code=policy_reload_failed uncertain=true -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "success=false code=policy_reload_failed uncertain=true -> recovery keyring=open generation=selected policy=replaced keys=0",
		"collision": "success=false code=policy_reload_failed uncertain=true -> recovery keyring=open generation=selected policy=replaced keys=0",
		"stray":     "success=false code=policy_reload_failed uncertain=true -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"reconcile": {
		"root":      "success=false code=recovery_blocked -> recovery keyring=open generation=none policy=none keys=0",
		"policy":    "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=none keys=0",
		"keytype":   "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
		"collision": "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
		"stray":     "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"reconcile in recovery": {
		"root":      "success=false code=recovery_blocked -> recovery keyring=open generation=none policy=none keys=0",
		"policy":    "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=none keys=0",
		"keytype":   "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
		"collision": "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
		"stray":     "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"key generation": {
		"root":      "success=false code=internal_error -> unlocked keyring=open generation=none policy=kept keys=1",
		"policy":    "success=false code=internal_error -> unlocked keyring=open generation=selected policy=kept keys=1",
		"keytype":   "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "success=false code=internal_error -> unlocked keyring=open generation=selected policy=replaced keys=1",
		"collision": "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
		"stray":     "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"key import": {
		"root":      "success=false code=internal_error -> unlocked keyring=open generation=none policy=kept keys=1",
		"policy":    "success=false code=internal_error -> unlocked keyring=open generation=selected policy=kept keys=1",
		"keytype":   "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "success=false code=internal_error -> unlocked keyring=open generation=selected policy=replaced keys=1",
		"collision": "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
		"stray":     "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"key deletion": {
		"root":      "success=false code=internal_error -> unlocked keyring=open generation=none policy=kept keys=1",
		"policy":    "success=false code=internal_error -> unlocked keyring=open generation=selected policy=kept keys=1",
		"keytype":   "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "success=false code=internal_error -> unlocked keyring=open generation=selected policy=replaced keys=1",
		"collision": "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
		"stray":     "success=false code=recovery_blocked -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"template import": {
		"root":      "success=false code=reload_failed provider=none -> unlocked keyring=open generation=none policy=kept keys=1",
		"policy":    "success=false code=reload_failed provider=none -> unlocked keyring=open generation=selected policy=kept keys=1",
		"keytype":   "success=false code=recovery_blocked provider=none -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "success=false code=reload_failed provider=none -> unlocked keyring=open generation=selected policy=replaced keys=1",
		"collision": "success=false code=recovery_blocked provider=none -> recovery keyring=open generation=selected policy=replaced keys=0",
		"stray":     "success=false code=recovery_blocked provider=none -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"template removal": {
		"root":      "success=false code=reload_failed provider=none -> unlocked keyring=open generation=none policy=kept keys=1",
		"policy":    "success=false code=reload_failed provider=none -> unlocked keyring=open generation=selected policy=kept keys=1",
		"keytype":   "success=false code=recovery_blocked provider=none -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "success=false code=reload_failed provider=none -> unlocked keyring=open generation=selected policy=replaced keys=1",
		"collision": "success=false code=recovery_blocked provider=none -> recovery keyring=open generation=selected policy=replaced keys=0",
		"stray":     "success=false code=recovery_blocked provider=none -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"key type deactivation": {
		"root":      "success=false code=reload_failed provider=none -> unlocked keyring=open generation=none policy=kept keys=1",
		"policy":    "success=false code=reload_failed provider=none -> unlocked keyring=open generation=selected policy=kept keys=1",
		"keytype":   "success=false code=recovery_blocked provider=none -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "success=false code=reload_failed provider=none -> unlocked keyring=open generation=selected policy=replaced keys=1",
		"collision": "success=false code=recovery_blocked provider=none -> recovery keyring=open generation=selected policy=replaced keys=0",
		"stray":     "success=false code=recovery_blocked provider=none -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"key type activation": {
		"root":      "success=false code=reload_failed provider=none -> unlocked keyring=open generation=none policy=kept keys=1",
		"policy":    "success=false code=reload_failed provider=none -> unlocked keyring=open generation=selected policy=kept keys=1",
		"keytype":   "success=false code=recovery_blocked provider=registered -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "success=false code=reload_failed provider=registered -> unlocked keyring=open generation=selected policy=replaced keys=1",
		"collision": "success=false code=recovery_blocked provider=registered -> recovery keyring=open generation=selected policy=replaced keys=0",
		"stray":     "success=false code=recovery_blocked provider=registered -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"restore": {
		"root":      "success=false code=restore_rollback_failed uncertain=false -> recovery keyring=open generation=none policy=none keys=0",
		"policy":    "success=false code=restore_rollback_failed uncertain=false -> recovery keyring=open generation=selected policy=none keys=0",
		"keytype":   "success=false code=restore_rollback_failed uncertain=false -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "success=false code=restore_rollback_failed uncertain=false -> recovery keyring=open generation=selected policy=replaced keys=0",
		"collision": "success=false code=restore_rollback_failed uncertain=false -> recovery keyring=open generation=selected policy=replaced keys=0",
		"stray":     "success=false code=restore_rollback_failed uncertain=false -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"rollback": {
		"root":      "success=false code=restore_rollback_failed uncertain=false -> recovery keyring=open generation=none policy=none keys=0",
		"policy":    "success=false code=restore_rollback_failed uncertain=false -> recovery keyring=open generation=selected policy=none keys=0",
		"keytype":   "success=false code=restore_rollback_failed uncertain=false -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "success=false code=restore_rollback_failed uncertain=false -> recovery keyring=open generation=selected policy=replaced keys=0",
		"collision": "success=false code=restore_rollback_failed uncertain=false -> recovery keyring=open generation=selected policy=replaced keys=0",
		"stray":     "success=false code=restore_rollback_failed uncertain=false -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
	"watcher": {
		"root":      "failed=true -> unlocked keyring=open generation=none policy=kept keys=1",
		"policy":    "failed=true -> unlocked keyring=open generation=selected policy=kept keys=1",
		"keytype":   "failed=true -> recovery keyring=open generation=selected policy=replaced keys=0",
		"scan":      "failed=true -> unlocked keyring=open generation=selected policy=replaced keys=1",
		"collision": "failed=true -> recovery keyring=open generation=selected policy=replaced keys=0",
		"stray":     "failed=true -> recovery keyring=open generation=selected policy=replaced keys=0",
	},
}

func TestWhatAFailedReloadLeavesBehind(t *testing.T) {
	for _, caller := range reloadCallers {
		for _, fault := range reloadFaults {
			t.Run(caller.name+"/"+fault.name, func(t *testing.T) {
				server := characterizedSigner(t)
				if caller.from != nil {
					caller.from(t, server)
				}
				before := viewBefore(server)
				plantBeforeReload(t, server, fault)
				answer := caller.run(t, server)
				got := answer + " -> " + before.describe(server)
				if want := afterAFailedReload[caller.name][fault.name]; got != want {
					t.Errorf("\n got: %s\nwant: %s", got, want)
				}
			})
		}
	}
}

// A cosigner's source tokens after a reconcile whose build failed: the
// reconcile ends in recovery's view, which holds no token index, whatever
// the fault. Nothing reads a token in recovery, since a token lookup runs
// only inside a key use, which only an unlocked signer grants. The token
// files stay in the generation, and the reconcile that lifts recovery
// publishes them again. Recovery once kept the index it found.
func TestAFailedReconcileLeavesRecoveryNoSourceTokens(t *testing.T) {
	for _, fault := range reloadFaults {
		t.Run(fault.name, func(t *testing.T) {
			server, cleanup := setupTestNode(t, noderole.RoleCosigner, cosignerDefaultWithSources(t))
			t.Cleanup(cleanup)
			ir := server.productRuntime()
			t.Cleanup(ir.StopKeyWatcher)
			setTokenForBackupTest(t, server, sourcetokens.DefaultSelector, "tok-kept")

			plantBeforeReload(t, server, fault)
			if result := server.adminServices().backupServices().ReconcileStore(); result.Success {
				t.Fatalf("ReconcileStore() = %+v, want the reload's failure", result)
			}
			if !ir.IsRecovery() {
				t.Fatalf("state = %v after a failed reconcile, want recovery", ir.GetState())
			}
			requireServedToken(t, server, sourcetokens.DefaultSelector, "")
		})
	}
}
