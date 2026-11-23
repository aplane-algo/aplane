// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/protocol"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
)

// These tests record what a signer in recovery shows, and what a lock that
// lands during a reload leaves.

// Recovery publishes no keys, however it was entered: a store change that
// ended in doubt and a reload that found a content defect both leave it with
// none. The admin requests a session in recovery is answered read the key
// maps in one place: the policy views mark each per-key document as held or
// not, so in recovery every per-key document shows as not held. The snapshot
// digest does not cover the marking and is the same throughout. A store
// change in doubt once entered recovery with the key maps as they were, and
// its per-key document showed as the key's own.
func TestThePolicyViewsInRecoveryMarkEveryPerKeyDocumentNotHeld(t *testing.T) {
	for _, tc := range []struct {
		name  string
		enter func(t *testing.T, server *Signer)
		want  string
	}{
		{name: "a store change that ended in doubt", want: "key_not_held 0",
			enter: func(_ *testing.T, server *Signer) {
				_ = server.adminServices().withStoreMutation(func() error {
					_, err := server.productRuntime().FollowCommit(genstore.Uncertain)
					return err
				})
			}},
		{name: "a reload that found a content defect", want: "key_not_held 0",
			enter: func(t *testing.T, server *Signer) {
				ir := server.productRuntime()
				active, err := ir.ActivePaths()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(active.KeysDir(), "notes.txt"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				_ = server.adminServices().withStoreMutation(func() error {
					_, err := ir.Reload()
					return err
				})
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := characterizedSigner(t)
			ir := server.productRuntime()
			address := heldAddress(t, server)
			app := server.adminServices().adminApp()
			applied := app.ApplyPolicy(adminproto.ApplyPolicyRequest{
				Documents:               []adminproto.PolicyDocument{{Key: address, Document: policytest.Signer(t, address, `{"max_fee_microalgos":"4321"}`)}},
				ExpectedPolicySetSHA256: app.GetPolicy().PolicySetSHA256,
				ExpectedSnapshotSHA256:  app.GetPolicyContext().SnapshotSHA256,
			})
			if !applied.Success {
				t.Fatalf("ApplyPolicy() = %+v", applied)
			}
			unlocked := app.GetPolicyContext().SnapshotSHA256

			tc.enter(t, server)
			if !ir.IsRecovery() {
				t.Fatalf("state = %v, want recovery", ir.GetState())
			}
			view := app.GetPolicy()
			if !view.Success || len(view.Keys) != 1 || view.Keys[0].Key != address {
				t.Fatalf("GetPolicy() in recovery = %+v, want the one per-key document", view)
			}
			if got := fmt.Sprintf("%s %d", view.Keys[0].Status, ir.KeyCount()); got != tc.want {
				t.Fatalf("held marking and key count in recovery = %q, want %q", got, tc.want)
			}
			if context := app.GetPolicyContext(); !context.Success || context.SnapshotSHA256 != unlocked {
				t.Fatalf("GetPolicyContext() in recovery = %+v, want the snapshot digest %s it had unlocked", context, unlocked)
			}
			if doc := app.GetPolicyDocumentAt(adminproto.GetPolicyDocumentRequest{Key: policy.DefaultKey, ExpectedSnapshotSHA256: unlocked}); !doc.Success {
				t.Fatalf("GetPolicyDocumentAt() in recovery = %+v, want the default document", doc)
			}
		})
	}
}

// A commit that may have landed enters recovery and then builds, so the
// runtime follows the generation the root now selects. The build succeeds,
// and recovery's view of it publishes no keys: the signer is in recovery with
// none, and the policy the commit wrote, until the reconcile publishes the
// keys as it promotes. A restore or a rollback begun in recovery publishes
// the same way. The reload once published the key maps in recovery.
func TestAnUncertainCommitLeavesRecoveryWithNoKeysUntilTheReconcile(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	before := viewBefore(server)
	identityDir := server.keyPaths.ProductDir()
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == identityDir {
			return errors.New("simulated directory sync failure")
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	result := applySignerPolicyDoc(t, server, policytest.Signer(t, policy.DefaultKey, `{"max_fee_microalgos":"4321"}`))
	fsutil.TestHook = nil
	if result.Success || !result.CommitUncertain {
		t.Fatalf("ApplyPolicy() = %+v, want an uncertain commit", result)
	}

	const want = "recovery keyring=open generation=selected policy=replaced keys=0"
	if got := before.describe(server); got != want {
		t.Fatalf("after an uncertain commit:\n got: %s\nwant: %s", got, want)
	}
	if got := ir.NodePolicy().PolicyFor(""); got == nil || got.MaxFeeMicroAlgos != 4321 {
		t.Fatalf("PolicyFor() = %+v, want the policy the commit wrote", got)
	}
	if result := server.adminServices().backupServices().ReconcileStore(); !result.Success || !ir.IsUnlocked() || ir.KeyCount() != 1 {
		t.Fatalf("ReconcileStore() = %+v, state %v, %d key(s); want unlocked with the key", result, ir.GetState(), ir.KeyCount())
	}
}

// A key type with an aplane key cannot be deactivated: the request is
// refused before anything is written or reloaded. The redesign relies on it:
// a deactivation's reload that fails for a passing reason keeps the view in
// service, which must not leave a key of a deactivated type able to sign.
func TestAKeyTypeWithAKeyCannotBeDeactivated(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	loads := countReloads(server)

	result := server.adminServices().templateServices().DeactivateKeyType(adminproto.DeactivateKeyTypeRequest{KeyType: "ed25519"})
	if result.Success || result.Code != protocol.ResultCodeKeyTypeInUse {
		t.Fatalf("DeactivateKeyType(ed25519) = %+v with a key of the type held, want it refused as in use", result)
	}
	if loads.Load() != 0 {
		t.Fatalf("the refused deactivation reloaded %d time(s), want none", loads.Load())
	}
	if !ir.IsUnlocked() || ir.KeyCount() != 1 {
		t.Fatalf("state = %v with %d key(s) after the refusal, want unlocked with the key", ir.GetState(), ir.KeyCount())
	}
	if _, listed := findKeyTypeInfo(fetchKeyTypesForTest(t, server), "ed25519"); !listed {
		t.Fatal("ed25519 is not offered after the refused deactivation")
	}
}

// sessionMessageTypes renders the messages pushed to the admin session, in
// order: each type, with the state or key count it carries.
func sessionMessageTypes(t *testing.T, session *ipcJSONRecorderConn) string {
	t.Helper()
	var out []string
	for _, msg := range session.messages(t) {
		entry := fmt.Sprint(msg["type"])
		if state, ok := msg["state"]; ok {
			entry += fmt.Sprintf(" state=%v", state)
		}
		if count, ok := msg["key_count"]; ok {
			entry += fmt.Sprintf(" key_count=%v", count)
		}
		out = append(out, entry)
	}
	return strings.Join(out, "; ")
}

// A lock that lands while a reload on the keyring in service builds flips the
// state at once; its cleanup waits for the reload to end. The reload goes on
// and publishes into the locked signer, and the cleanup then clears all of
// it, so the signer ends locked with nothing published. The reload sends its
// notifications only while the signer is still unlocked, so the admin session
// is told nothing: it once was told keys_changed with the new count, keys on a
// locked signer. The key the request wrote is on disk, and the request
// answers a success.
func TestALockDuringAReloadPublishesAndTellsTheSessionNothing(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	session := &ipcJSONRecorderConn{}
	server.ipcServer = newIPCServerWithActiveConn(session)
	server.hub = server.ipcServer

	lockDone := make(chan struct{})
	var stateInReload signerruntime.SignerState
	plantBeforeReload(t, server, reloadFault{plant: func(*testing.T, *Signer) {
		go func() {
			ir.Lock()
			close(lockDone)
		}()
		// The state flips before the cleanup, which waits for this reload.
		waitForState(t, ir, signerruntime.SignerStateLocked)
		stateInReload = ir.GetState()
	}})
	result := server.adminServices().keyApp().GenerateKey(context.Background(), adminproto.GenerateKeyRequest{KeyType: "ed25519"})
	<-lockDone

	if stateInReload != signerruntime.SignerStateLocked {
		t.Fatalf("state during the reload = %v, want locked", stateInReload)
	}
	if !result.Success || result.Address == "" {
		t.Fatalf("GenerateKey() = %+v, want a success: the reload ran to its end", result)
	}
	if got := ir.GetState(); got != signerruntime.SignerStateLocked || ir.KeyCount() != 0 {
		t.Fatalf("state = %v with %d key(s) after the lock's cleanup, want locked with none", got, ir.KeyCount())
	}
	if _, err := ir.ActivePaths(); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("ActivePaths() error = %v after the cleanup, want no keyring", err)
	}
	// The test signer wires no lock notification, so the lock itself tells
	// the session nothing here.
	if got := sessionMessageTypes(t, session); got != "" {
		t.Fatalf("the admin session was sent %q, want nothing", got)
	}
}

// A lock whose cleanup has finished before a reload begins leaves it nothing
// to read: the reload fails as locked, publishes and notifies nothing, and
// the signer stays locked. No request reaches a reload this way today; each
// checks the state under the store mutation lock first.
func TestAReloadAfterALocksCleanupPublishesNothing(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	session := &ipcJSONRecorderConn{}
	server.ipcServer = newIPCServerWithActiveConn(session)
	server.hub = server.ipcServer
	ir.Lock()
	told := sessionMessageTypes(t, session)

	err := server.adminServices().withStoreMutation(func() error {
		_, err := ir.Reload()
		return err
	})
	if !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("Reload() on a locked signer = %v, want a locked refusal", err)
	}
	if got := ir.GetState(); got != signerruntime.SignerStateLocked || ir.KeyCount() != 0 {
		t.Fatalf("state = %v with %d key(s), want locked with none", got, ir.KeyCount())
	}
	if got := sessionMessageTypes(t, session); got != told {
		t.Fatalf("the admin session was sent %q, want nothing after %q", got, told)
	}
}

// countReloads counts the reloads, with a passphrase or without, and runs
// each as wired.
func countReloads(server *Signer) *atomic.Int32 {
	all, _ := countBuilds(server)
	return all
}
