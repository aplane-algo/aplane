// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keyclass"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// countingAudit counts the reload audit records written to it.
type countingAudit struct {
	mu                sync.Mutex
	rejected, reloads int
}

func (a *countingAudit) LogKeyReload(int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reloads++
}

func (a *countingAudit) LogKeyRejected(string, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rejected++
}

// rejectedScan is a key scan of selection whose one key file the scan
// rejected as a tampered LogicSig key.
func rejectedScan(selection storepaths.GenPaths) keystore.Contents {
	return keystore.Contents{Selection: &selection, Warnings: []apkeys.KeyScanWarning{
		{Code: apkeys.KeyScanWarningLogicSigAddressInvalid, KeyFile: "keys/BAD.key"},
	}}
}

// noReconcile is an unlock's reconcile that finds nothing to do.
func noReconcile(*crypto.Keyring) error { return nil }

// zeroed reports whether kr, a keyring a build was handed, has been zeroed.
func zeroed(kr *crypto.Keyring) bool { return kr != nil && kr.CurrentTerm() == 0 }

// tokenZeroed reports whether ix, a build's token index, has been zeroed.
func tokenZeroed(ix *sourcetokens.Index, token string) bool {
	value, _ := ix.TokenFor(sourcetokens.DefaultSelector, "screening")
	return value != token
}

// Every unlock exit audits what its build found, published or not: the
// LogicSig keys the scan rejected are recorded, and a role conflict fails the
// node closed. A build that fails is how a tampered key file shows itself, so
// an exit that skipped the audit would hide it.
func TestEveryUnlockExitAuditsWhatItsBuildFound(t *testing.T) {
	defect := fmt.Errorf("%w: 1 malformed key file(s)", signertemplates.ErrGenerationValidation)
	conflict := fmt.Errorf("key snapshot rejected: %w", keyclass.ErrNodeRoleConflict)
	for _, entry := range []string{"unlock from locked", "unlock from recovery", "unlock whose reconcile fails", "passphrase change"} {
		for _, buildErr := range []error{defect, conflict} {
			t.Run(entry+": "+buildErr.Error(), func(t *testing.T) {
				ir, bound, _ := viewInService(t)
				if entry == "unlock from recovery" {
					ir.EnterRecovery(nil)
				} else {
					ir.Lock()
				}
				audit := &countingAudit{}
				failedClosed := 0
				ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
					return &Loaded{Selection: &bound, Contents: rejectedScan(bound)}, buildErr
				}, ReloadEffects{Audit: audit, NodeFailClosed: func(error) { failedClosed++ }})

				switch entry {
				case "passphrase change":
					_, _ = ir.ReloadWithPassphrase([]byte(secondUnlockPassphrase))
				case "unlock whose reconcile fails":
					_, _ = ir.Unlock([]byte(secondUnlockPassphrase), func(*crypto.Keyring) error { return errors.New("injected reconcile failure") }, nil)
				default:
					_, _ = ir.Unlock([]byte(secondUnlockPassphrase), noReconcile, nil)
				}
				wantFailedClosed := 0
				if errors.Is(buildErr, keyclass.ErrNodeRoleConflict) {
					wantFailedClosed = 1
				}
				if audit.rejected != 1 || failedClosed != wantFailedClosed {
					t.Fatalf("rejected key audits %d, node failed closed %d time(s); want 1 and %d", audit.rejected, failedClosed, wantFailedClosed)
				}
			})
		}
	}
}

// An unlock begun in recovery whose build enters recovery's view (a content
// defect, a root that moved, or a root that did not authenticate) binds
// recovery to what the build found and keeps recovery's own keyring, still
// usable, for the reconcile, restore and rollback it needs. The keyring and
// the token index the build was handed are zeroed.
func TestAnUnlockInRecoveryThatEntersRecoveryKeepsRecoverysKeyring(t *testing.T) {
	transient := errors.New("injected read failure")
	defect := fmt.Errorf("%w: 1 malformed key file(s)", signertemplates.ErrGenerationValidation)
	for _, tc := range []struct {
		name    string
		err     error
		moved   bool
		noRoot  bool
		binding string
	}{
		{name: "content defect", err: defect, binding: "bound"},
		{name: "root moved", err: transient, moved: true, binding: "moved"},
		{name: "root does not authenticate", err: transient, noRoot: true, binding: "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ir, bound, _ := viewInService(t)
			moved := ir.KeyPaths().GenerationPaths("gen-1800000000-0a0b0c0d")
			ir.EnterRecovery(nil)
			var recoverys *crypto.Keyring
			if err := ir.WithKeyring(func(kr *crypto.Keyring) error { recoverys = kr; return nil }); err != nil {
				t.Fatal(err)
			}
			built := viewTokens(t, "tok-built")
			var opened *crypto.Keyring
			ir.SetBuildFunc(func(kr *crypto.Keyring) (*Loaded, error) {
				opened = kr
				loaded := &Loaded{Tokens: built}
				switch {
				case tc.noRoot:
				case tc.moved:
					loaded.Selection = &moved
				default:
					loaded.Selection = &bound
				}
				return loaded, tc.err
			}, ReloadEffects{})

			outcome, err := ir.Unlock([]byte(secondUnlockPassphrase), noReconcile, nil)
			if err != nil || !outcome.Recovery || !ir.IsRecovery() {
				t.Fatalf("Unlock() = %+v, %v in state %v; want an answer of recovery", outcome, err, ir.GetState())
			}
			binding := "none"
			if active, err := ir.ActivePaths(); err == nil {
				binding = map[string]string{bound.GenerationID(): "bound", moved.GenerationID(): "moved"}[active.GenerationID()]
			}
			if binding != tc.binding {
				t.Fatalf("recovery bound to %s, want %s", binding, tc.binding)
			}
			var current *crypto.Keyring
			if err := ir.WithKeyring(func(kr *crypto.Keyring) error { current = kr; return nil }); err != nil || current != recoverys || zeroed(current) {
				t.Fatalf("recovery's keyring = %p (%v), want its own %p, usable", current, err, recoverys)
			}
			if !zeroed(opened) || opened == recoverys {
				t.Fatal("the keyring the build opened was not zeroed")
			}
			if !tokenZeroed(built, "tok-built") {
				t.Fatal("the build's token index was not zeroed")
			}
		})
	}
}

// An unlock from locked whose build finds a content defect, but which a lock
// overtook during the build, enters no recovery: it answers that the signer
// locked, and zeroes the keyring and the token index the build was handed.
func TestAnUnlockALockOvertookBeforeItsRecoveryZeroesWhatItBuilt(t *testing.T) {
	ir, bound, _ := viewInService(t)
	ir.Lock()
	built := viewTokens(t, "tok-built")
	var opened *crypto.Keyring
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*Loaded, error) {
		opened = kr
		// The lock lands whole: the build holds no passphrase lock.
		var lockDone sync.WaitGroup
		lockDone.Add(1)
		go func() {
			defer lockDone.Done()
			ir.Lock()
		}()
		lockDone.Wait()
		return &Loaded{Selection: &bound, Tokens: built}, fmt.Errorf("%w: injected", signertemplates.ErrGenerationValidation)
	}, ReloadEffects{})

	if _, err := ir.Unlock([]byte(secondUnlockPassphrase), noReconcile, nil); !errors.Is(err, signerruntime.ErrLockedDuringUnlock) {
		t.Fatalf("Unlock() = %v, want %v", err, signerruntime.ErrLockedDuringUnlock)
	}
	if ir.GetState() != signerruntime.SignerStateLocked {
		t.Fatalf("state %v, want locked", ir.GetState())
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err == nil {
		t.Fatal("the overtaken unlock left a keyring")
	}
	if !zeroed(opened) {
		t.Fatal("the keyring the build opened was not zeroed")
	}
	if !tokenZeroed(built, "tok-built") {
		t.Fatal("the build's token index was not zeroed")
	}
}

// A passphrase change whose build fails installs nothing, and zeroes the
// keyring it opened with the new passphrase and the token index its build
// made.
func TestAPassphraseChangeWhoseBuildFailsZeroesWhatItBuilt(t *testing.T) {
	ir, bound, _ := viewInService(t)
	ir.Lock()
	built := viewTokens(t, "tok-built")
	var opened *crypto.Keyring
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*Loaded, error) {
		opened = kr
		return &Loaded{Selection: &bound, Tokens: built}, errors.New("injected read failure")
	}, ReloadEffects{})

	if _, err := ir.ReloadWithPassphrase([]byte(secondUnlockPassphrase)); err == nil {
		t.Fatal("ReloadWithPassphrase() succeeded though its build failed")
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err == nil {
		t.Fatal("the failed passphrase change installed a keyring")
	}
	if !zeroed(opened) {
		t.Fatal("the keyring the build opened was not zeroed")
	}
	if !tokenZeroed(built, "tok-built") {
		t.Fatal("the build's token index was not zeroed")
	}
}

// An unlock whose build succeeds but which a lock overtook publishes, loses
// at its fence, and still audits what its build found, though no key went
// into service and no key reload is recorded.
func TestAnUnlockALockOvertookAtItsFenceStillAuditsWhatItsBuildFound(t *testing.T) {
	ir, bound, _ := viewInService(t)
	ir.Lock()
	audit := &countingAudit{}
	ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
		var lockDone sync.WaitGroup
		lockDone.Add(1)
		go func() {
			defer lockDone.Done()
			ir.Lock()
		}()
		lockDone.Wait()
		return &Loaded{Selection: &bound, Contents: rejectedScan(bound)}, nil
	}, ReloadEffects{Audit: audit})

	if _, err := ir.Unlock([]byte(secondUnlockPassphrase), noReconcile, nil); !errors.Is(err, signerruntime.ErrLockedDuringUnlock) {
		t.Fatalf("Unlock() = %v, want %v", err, signerruntime.ErrLockedDuringUnlock)
	}
	if audit.rejected != 1 || audit.reloads != 0 {
		t.Fatalf("rejected key audits %d, key reloads %d; want 1 and none", audit.rejected, audit.reloads)
	}
}

// A role conflict on an unlock begun in recovery installs nothing, even
// where the build found the root moved, which would otherwise rebind
// recovery: the node fails closed, and recovery keeps its own keyring and
// binding. The keyring the attempt opened is zeroed.
func TestARoleConflictOnAnUnlockInRecoveryInstallsNothing(t *testing.T) {
	ir, bound, _ := viewInService(t)
	moved := ir.KeyPaths().GenerationPaths("gen-1800000000-0a0b0c0d")
	ir.EnterRecovery(nil)
	var recoverys *crypto.Keyring
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error { recoverys = kr; return nil }); err != nil {
		t.Fatal(err)
	}
	failedClosed := 0
	var opened *crypto.Keyring
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*Loaded, error) {
		opened = kr
		return &Loaded{Selection: &moved}, fmt.Errorf("key snapshot rejected: %w", keyclass.ErrNodeRoleConflict)
	}, ReloadEffects{NodeFailClosed: func(error) { failedClosed++ }})

	if _, err := ir.Unlock([]byte(secondUnlockPassphrase), noReconcile, nil); !errors.Is(err, keyclass.ErrNodeRoleConflict) {
		t.Fatalf("Unlock() = %v, want the role conflict", err)
	}
	if failedClosed != 1 || !ir.IsRecovery() {
		t.Fatalf("node failed closed %d time(s), state %v; want once, recovery", failedClosed, ir.GetState())
	}
	if active, err := ir.ActivePaths(); err != nil || active.GenerationID() != bound.GenerationID() {
		t.Fatalf("recovery bound to %v (%v), want %s kept", active.GenerationID(), err, bound.GenerationID())
	}
	var current *crypto.Keyring
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error { current = kr; return nil }); err != nil || current != recoverys {
		t.Fatalf("recovery's keyring = %p (%v), want its own %p", current, err, recoverys)
	}
	if !zeroed(opened) {
		t.Fatal("the keyring the attempt opened was not zeroed")
	}
}

// An unlock attempt that loses to a lock before it builds zeroes the keyring
// it opened, and loads nothing: a lock that lands just after the store
// root's opening, or during the reconcile. The keyring is the attempt's from
// its opening to its install, so no exit may leave it unzeroed.
func TestAnUnlockThatLosesBeforeItsBuildZeroesTheKeyringItOpened(t *testing.T) {
	for _, when := range []string{"after the opening", "during the reconcile"} {
		t.Run(when, func(t *testing.T) {
			ir, _, loads, _ := unlockedRuntimeForTest(t)
			ir.Lock()
			lockNow := func() {
				var lockDone sync.WaitGroup
				lockDone.Add(1)
				go func() {
					defer lockDone.Done()
					ir.Lock()
				}()
				lockDone.Wait()
			}
			var opened *crypto.Keyring
			open := openStoreRoot
			t.Cleanup(func() { openStoreRoot = open })
			openStoreRoot = func(dir string, passphrase []byte) (*crypto.Keyring, crypto.StoreRootSelection, error) {
				kr, selection, err := open(dir, passphrase)
				opened = kr
				if when == "after the opening" {
					lockNow()
				}
				return kr, selection, err
			}
			reconcile := func(*crypto.Keyring) error {
				if when == "during the reconcile" {
					lockNow()
				}
				return nil
			}

			if _, err := ir.Unlock([]byte(secondUnlockPassphrase), reconcile, nil); !errors.Is(err, signerruntime.ErrLockedDuringUnlock) {
				t.Fatalf("Unlock() = %v, want %v", err, signerruntime.ErrLockedDuringUnlock)
			}
			if loads.Load() != 0 || ir.GetState() != signerruntime.SignerStateLocked {
				t.Fatalf("%d load(s), state %v; want none, locked", loads.Load(), ir.GetState())
			}
			if !zeroed(opened) {
				t.Fatal("the keyring the attempt opened was not zeroed")
			}
		})
	}
}
