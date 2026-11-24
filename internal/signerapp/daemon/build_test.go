// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keyclass"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
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

// A lock that overtakes ReconcileStore during its generational reconcile step
// (whether that step succeeds or fails, and from unlocked or recovery) must
// answer signer_locked with state locked, never recovery_blocked.
func TestReconcileStoreOvertakenByLockDuringStepAnswersLocked(t *testing.T) {
	for _, startRecovery := range []bool{false, true} {
		for _, stepErr := range []error{nil, errors.New("simulated step error after lock")} {
			name := fmt.Sprintf("fromRecovery=%v/stepErr=%v", startRecovery, stepErr != nil)
			t.Run(name, func(t *testing.T) {
				server := characterizedSigner(t)
				ir := server.productRuntime()
				if startRecovery {
					ir.EnterRecovery(nil)
				}
				stagingDir := filepath.Join(server.keyPaths.GenerationsDir(), storepaths.GenerationStagingPrefix+"lock-probe")
				if err := os.MkdirAll(stagingDir, 0o700); err != nil {
					t.Fatal(err)
				}
				generationsDir := server.keyPaths.GenerationsDir()
				var lockOnce sync.Once
				var lockDone sync.WaitGroup
				fsutil.TestHook = func(op fsutil.HookOp, path string) error {
					if op == fsutil.OpDirSync && path == generationsDir {
						lockOnce.Do(func() {
							lockDone.Add(1)
							go func() {
								defer lockDone.Done()
								ir.Lock()
							}()
							for ir.GetState() != signerruntime.SignerStateLocked {
								time.Sleep(time.Millisecond)
							}
						})
						return stepErr
					}
					return nil
				}
				t.Cleanup(func() { fsutil.TestHook = nil })

				result := server.adminServices().backupServices().ReconcileStore()
				lockDone.Wait()
				fsutil.TestHook = nil

				if result.Success || result.Code != protocol.ErrCodeSignerLocked || result.State != signerruntime.SignerStateLocked.String() {
					t.Fatalf("ReconcileStore() overtaken during step = %+v, want %s/%s", result, protocol.ErrCodeSignerLocked, signerruntime.SignerStateLocked.String())
				}
				if ir.GetState() != signerruntime.SignerStateLocked {
					t.Fatalf("state = %v, want locked", ir.GetState())
				}
			})
		}
	}
}

// wireBuildWith wires the reload's own build, with before run ahead of each
// build. fromPassphrase is set for a build with a keyring an unlock or a
// passphrase change opened, rather than the keyring in service. An error
// from before is the build's, failing as a build does after it has
// authenticated the root: with the selection.
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
			selection, authErr := genstore.AuthenticateStoreRootSelection(ir.KeyPaths(), kr)
			if authErr != nil {
				return nil, err
			}
			return &productruntime.Loaded{Selection: &selection}, err
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

func plantWitnessKey(t *testing.T, server *Signer) string {
	t.Helper()
	RegisterProviders()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(priv)
	payload := apkeys.NewWitnessPayload(witness.Ed25519V1, pub, priv)
	defer payload.ZeroSecrets()
	var selector string
	if err := server.productRuntime().WithKeyring(func(kr *crypto.Keyring) error {
		res, saveErr := apkeys.SaveNewPayload(mustActiveKeyPaths(t, server), payload, false, kr)
		if saveErr != nil {
			return saveErr
		}
		selector = res.Address
		return nil
	}); err != nil {
		t.Fatalf("SaveNewPayload(witness) error = %v", err)
	}
	return selector
}

func plantSpendingKey(t *testing.T, server *Signer) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(priv)
	payload := apkeys.NewEd25519Payload(pub, priv)
	defer payload.ZeroSecrets()
	payload.ValidRekeyTarget = true
	var address string
	if err := server.productRuntime().WithKeyring(func(kr *crypto.Keyring) error {
		res, saveErr := apkeys.SaveNewPayload(mustActiveKeyPaths(t, server), payload, false, kr)
		if saveErr != nil {
			return saveErr
		}
		address = res.Address
		return nil
	}); err != nil {
		t.Fatalf("SaveNewPayload(spending) error = %v", err)
	}
	return address
}

func runWatcherReload(t *testing.T, server *Signer) error {
	t.Helper()
	ir := server.productRuntime()
	var onChange func() error
	ir.StopKeyWatcher()
	ir.EnsureKeyWatcher(func(_ []string, _ context.Context, reload func() error) error {
		onChange = reload
		return nil
	})
	if onChange == nil {
		t.Fatal("EnsureKeyWatcher did not deliver reload callback")
	}
	return onChange()
}

// Build checks scanned key types against the node role before anything is
// published. A witness (.cos) credential on a signer node or a spending (.key)
// credential on a cosigner node must fail the node closed and publish nothing,
// both through a watcher reload and through an unlock.
func TestReloadAndUnlockFailClosedOnConflictingKeyType(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T) *Signer
	}{
		{
			name: "witness key on a signer",
			setup: func(t *testing.T) *Signer {
				server := characterizedSigner(t)
				plantWitnessKey(t, server)
				return server
			},
		},
		{
			name: "spending key on a cosigner",
			setup: func(t *testing.T) *Signer {
				server, cleanup := setupTestNode(t, noderole.RoleCosigner, cosignerDefaultWithSources(t))
				t.Cleanup(cleanup)
				t.Cleanup(server.productRuntime().StopKeyWatcher)
				plantWitnessKey(t, server)
				if err := server.adminServices().withStoreMutation(func() error {
					_, err := server.productRuntime().Reload()
					return err
				}); err != nil {
					t.Fatalf("initial cosigner Reload() = %v", err)
				}
				if got := server.productRuntime().KeyCount(); got != 1 {
					t.Fatalf("initial cosigner KeyCount() = %d, want 1", got)
				}
				plantSpendingKey(t, server)
				return server
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("watcher reload", func(t *testing.T) {
				server := tc.setup(t)
				ir := server.productRuntime()

				err := runWatcherReload(t, server)
				if !errors.Is(err, keyclass.ErrNodeRoleConflict) || errors.Is(err, signertemplates.ErrGenerationValidation) {
					t.Fatalf("watcher reload error = %v, want keyclass.ErrNodeRoleConflict without ErrGenerationValidation", err)
				}
				if closeErr := server.nodeFailState.Err(); !errors.Is(closeErr, productruntime.ErrNodeFailClosed) {
					t.Fatalf("nodeFailState.Err() = %v, want ErrNodeFailClosed", closeErr)
				}
				if !ir.IsRecovery() {
					t.Fatalf("state = %v, want recovery", ir.GetState())
				}
				if ir.KeyCount() != 0 || len(ir.KeyStore().GetKeyTypes()) != 0 {
					t.Fatalf("published keys after role conflict: KeyCount=%d KeyStore=%d, want 0", ir.KeyCount(), len(ir.KeyStore().GetKeyTypes()))
				}
			})

			t.Run("unlock", func(t *testing.T) {
				server := tc.setup(t)
				ir := server.productRuntime()
				ir.Lock()
				if ir.GetState() != signerruntime.SignerStateLocked {
					t.Fatalf("state after Lock() = %v, want locked", ir.GetState())
				}

				success, keyCount, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase)
				if success || keyCount != 0 || code != protocol.ErrCodeUnlockFailed || !strings.Contains(errMsg, keyclass.ErrNodeRoleConflict.Error()) {
					t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want unlock_failed carrying ErrNodeRoleConflict", success, keyCount, errMsg, code)
				}
				if closeErr := server.nodeFailState.Err(); !errors.Is(closeErr, productruntime.ErrNodeFailClosed) {
					t.Fatalf("nodeFailState.Err() = %v, want ErrNodeFailClosed", closeErr)
				}
				if ir.GetState() != signerruntime.SignerStateLocked {
					t.Fatalf("state = %v, want locked", ir.GetState())
				}
				if ir.KeyCount() != 0 || len(ir.KeyStore().GetKeyTypes()) != 0 {
					t.Fatalf("published keys after unlock role conflict: KeyCount=%d KeyStore=%d, want 0", ir.KeyCount(), len(ir.KeyStore().GetKeyTypes()))
				}
				if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); !errors.Is(err, keystore.ErrStoreLocked) {
					t.Fatalf("WithKeyring() after failed unlock = %v, want ErrStoreLocked", err)
				}
			})
		})
	}
}

// Build refuses a generation whose authenticated store role disagrees with the
// runtime's configured node role before policy verification runs.
func TestBuildRejectsRuntimeAndVerifiedRoleMismatch(t *testing.T) {
	server := characterizedSigner(t)
	mismatched := productruntime.New(productruntime.Config{
		KeyStore: keystore.NewFileKeyStore(),
		KeyPaths: server.keyPaths,
		NodeRole: noderole.RoleCosigner,
	})
	var loaded *productruntime.Loaded
	var buildErr error
	if err := server.productRuntime().WithKeyring(func(kr *crypto.Keyring) error {
		loaded, buildErr = signerstartup.Build(mismatched, testProductBuildOptions(server), kr)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(loaded.Discard)

	if buildErr == nil || !strings.Contains(buildErr.Error(), "does not match verified role") {
		t.Fatalf("Build() error = %v, want runtime/verified role mismatch", buildErr)
	}
	if strings.Contains(buildErr.Error(), "policy verification failed") {
		t.Fatalf("Build() failed at policy instead of the role check: %v", buildErr)
	}
	if loaded.Selection == nil {
		t.Fatal("loaded.Selection = nil, want the authenticated selection")
	}
	if loaded.PolicyVerified {
		t.Fatal("loaded.PolicyVerified = true, want false before policy load")
	}
}

// Build records the authenticated selection before validating the selected
// generation so a validation failure after a store-root commit still leaves
// recovery bound to the generation the root selects.
func TestBuildRecordsSelectionBeforeValidatingGeneration(t *testing.T) {
	server := characterizedSigner(t)
	selected, err := server.productRuntime().ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(selected.Dir()); err != nil {
		t.Fatal(err)
	}

	loaded, buildErr := buildOnce(t, server)
	if buildErr == nil || !strings.Contains(buildErr.Error(), "authenticate active product generation") {
		t.Fatalf("Build() error = %v, want generation validation failure", buildErr)
	}
	if loaded.Selection == nil || loaded.Selection.GenerationID() != selected.GenerationID() {
		t.Fatalf("loaded.Selection = %v, want generation %q", loaded.Selection, selected.GenerationID())
	}
	if loaded.PolicyVerified {
		t.Fatal("loaded.PolicyVerified = true, want false")
	}
}

// A build scans keys before registering the generation's templates at publish,
// so the scan's signature-size lookup sizes a dsa_lsig key through its base
// key type on the first unlock and through the composed provider on later
// reloads. Both must produce the exact same KeyScanInfo (including
// LogicSigResources), and every registered composed/DSA provider with a base
// key type must report the same CryptoSignatureSize as its base.
func TestKeyScanMatchesBeforeAndAfterComposedTemplateRegistration(t *testing.T) {
	RegisterProviders()

	type baseKeyTyper interface {
		BaseKeyType() string
	}
	for _, dsa := range logicsigdsa.GetAll() {
		withBase, ok := dsa.(baseKeyTyper)
		if !ok {
			continue
		}
		base := withBase.BaseKeyType()
		if base == "" || base == dsa.KeyType() {
			continue
		}
		baseSize := logicsigdsa.GetCryptoSignatureSize(base)
		if baseSize <= 0 || dsa.CryptoSignatureSize() != baseSize {
			t.Errorf("provider %q reports CryptoSignatureSize=%d, base %q reports %d",
				dsa.KeyType(), dsa.CryptoSignatureSize(), base, baseSize)
		}
	}

	server, cleanup := setupTestSigner(t)
	t.Cleanup(cleanup)
	t.Cleanup(server.productRuntime().StopKeyWatcher)

	bases := []struct {
		baseKeyType string
		family      string
		wantSigSize int
		bytecode    []byte
	}{
		{
			baseKeyType: "aplane.falcon1024.v1",
			family:      fmt.Sprintf("scan-inv-falcon-%d", time.Now().UnixNano()),
			wantSigSize: 1423,
			bytecode:    []byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x01}, // #pragma version 6; int 1
		},
		{
			baseKeyType: "aplane.ed25519.v1",
			family:      fmt.Sprintf("scan-inv-ed25519-%d", time.Now().UnixNano()),
			wantSigSize: 64,
			bytecode:    []byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x02}, // #pragma version 6; int 2
		},
	}

	const argBytes = 32
	savedAddrs := make(map[string]int, len(bases))
	keyTypes := make([]string, 0, len(bases))
	for _, tc := range bases {
		if got := logicsigdsa.GetCryptoSignatureSize(tc.baseKeyType); got != tc.wantSigSize {
			t.Fatalf("base %q CryptoSignatureSize = %d, want %d", tc.baseKeyType, got, tc.wantSigSize)
		}
		keyType := "test." + tc.family + ".v1"
		keyTypes = append(keyTypes, keyType)
		t.Cleanup(func() { lsigprovider.Unregister(keyType) })

		yamlDoc := fmt.Sprintf(`schema_version: 1
derivation_version: 3
template_type: composed
base_key_type: %s
template_mode: generated
publisher: test
family: %s
version: 1
display_name: "Scan Invariance %s"
description: "unbounded composed template for scan invariance check"
max_opcode_cost: 20000
valid_rekey_target: true
runtime_args:
  - name: nonce
    label: "Nonce"
    type: bytes
    required: true
    byte_length: %d
teal: |
  int 1
  assert
`, tc.baseKeyType, tc.family, tc.baseKeyType, argBytes)

		res := server.adminServices().templateServices().ImportInstalledTemplate(adminproto.ImportInstalledTemplateRequest{
			TemplateYAML: []byte(yamlDoc),
		})
		if !res.Success {
			t.Fatalf("ImportInstalledTemplate(%s) = %+v", keyType, res)
		}

		// Save an unbounded dsa_lsig key for this composed template so the
		// scan exercises cryptoSignatureSizeForKey (bounded keys carry their
		// own per-path argument sizes instead).
		var addr string
		if err := server.productRuntime().WithKeyring(func(kr *crypto.Keyring) error {
			signingArgs := []apkeys.StoredSigningArg{{
				Name:       "nonce",
				Label:      "Nonce",
				Type:       "bytes",
				Required:   true,
				ByteLength: argBytes,
			}}
			payload := apkeys.NewDSALSigPayload(
				keyType,
				tc.baseKeyType,
				[]byte{0x01, 0x02, 0x03, 0x04},
				[]byte{0x05, 0x06, 0x07, 0x08},
				nil,
				tc.bytecode,
				"#pragma version 6\nint 1",
				signingArgs,
				"",
			)
			defer payload.ZeroSecrets()
			if err := payload.SetLogicSigOpcodeProfile(lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling), false); err != nil {
				return err
			}
			saved, saveErr := apkeys.SaveNewPayload(mustActiveKeyPaths(t, server), payload, false, kr)
			if saveErr != nil {
				return saveErr
			}
			addr = saved.Address
			return nil
		}); err != nil {
			t.Fatalf("SaveNewPayload(%s) error = %v", keyType, err)
		}
		savedAddrs[addr] = tc.wantSigSize + argBytes
	}

	// Unregister both composed providers to simulate a fresh process before
	// the first publish registers the generation's templates.
	for _, kt := range keyTypes {
		lsigprovider.Unregister(kt)
		if lsigprovider.Get(kt) != nil {
			t.Fatalf("provider %q still registered after Unregister", kt)
		}
	}

	before, err := buildOnce(t, server)
	if err != nil {
		t.Fatalf("Build() before registration error = %v", err)
	}
	if len(before.Contents.Warnings) != 0 {
		t.Fatalf("Build() before registration warnings = %v, want none", before.Contents.Warnings)
	}
	for _, kt := range keyTypes {
		if lsigprovider.Get(kt) != nil {
			t.Fatalf("Build() registered %q before publish", kt)
		}
	}

	// Publish through production Reload to register both composed providers.
	if err := server.adminServices().withStoreMutation(func() error {
		_, err := server.productRuntime().Reload()
		return err
	}); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	for i, kt := range keyTypes {
		dsa := logicsigdsa.Get(kt)
		if dsa == nil {
			t.Fatalf("provider %q not registered after Reload", kt)
		}
		if got := dsa.CryptoSignatureSize(); got != bases[i].wantSigSize {
			t.Fatalf("registered %q CryptoSignatureSize = %d, want %d (same as base %q)", kt, got, bases[i].wantSigSize, bases[i].baseKeyType)
		}
	}

	after, err := buildOnce(t, server)
	if err != nil {
		t.Fatalf("Build() after registration error = %v", err)
	}
	if len(after.Contents.Warnings) != 0 {
		t.Fatalf("Build() after registration warnings = %v, want none", after.Contents.Warnings)
	}
	if !reflect.DeepEqual(before.Contents.Keys, after.Contents.Keys) {
		t.Fatalf("key scan changed after composed template registration:\nbefore: %#v\nafter:  %#v", before.Contents.Keys, after.Contents.Keys)
	}
	for addr, wantArgBytes := range savedAddrs {
		info, ok := before.Contents.Keys[addr]
		if !ok {
			t.Fatalf("scan missing composed key %q", addr)
		}
		if info.LogicSigResources == nil || info.LogicSigResources.Default == nil {
			t.Fatalf("key %q missing default LogicSigResources profile: %#v", addr, info.LogicSigResources)
		}
		if got := info.LogicSigResources.Default.ArgumentBytes; got != uint64(wantArgBytes) {
			t.Fatalf("key %q (%s) ArgumentBytes = %d, want %d", addr, info.KeyType, got, wantArgBytes)
		}
	}
}
