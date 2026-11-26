// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
)

// A reload without a passphrase whose build finds a content defect in the
// selected generation, a failed validation or an address collision, enters
// recovery before it returns, and so before its caller releases the store
// mutation lock, and its error carries ErrEnteredRecovery. Recovery keeps the
// keyring, for the reconcile that lifts it. A signer already in recovery
// stays there, and a locked one stays locked, with no keyring to build with.
// Any other failure, such as a keys directory that cannot be read, keeps the
// view in service, for the caller to answer. Each entry is passed to the hook
// the process root set, which tells the admin session and the log.
func TestAReloadThatFindsAContentDefectEntersRecovery(t *testing.T) {
	validation := fmt.Errorf("%w: 1 malformed key file(s)", signertemplates.ErrGenerationValidation)
	// As the reload wraps the scan's collision error.
	collision := fmt.Errorf("failed to rescan keys directory: %w", fmt.Errorf("failed to scan keys directory: %w",
		&apkeys.AddressCollisionError{Collisions: map[string][]string{"ADDR": {"keys/ADDR.key", "keys/ADDR.cos"}}}))
	other := errors.New("failed to rescan keys directory: injected read failure")
	for _, tc := range []struct {
		name string
		from func(*Runtime)
		err  error
		want signerruntime.SignerState
	}{
		{name: "unlocked, validation", from: func(*Runtime) {}, err: validation, want: signerruntime.SignerStateRecovery},
		{name: "unlocked, address collision", from: func(*Runtime) {}, err: collision, want: signerruntime.SignerStateRecovery},
		{name: "recovery, address collision", from: func(ir *Runtime) { ir.EnterRecovery(nil) }, err: collision, want: signerruntime.SignerStateRecovery},
		{name: "unlocked, other failure", from: func(*Runtime) {}, err: other, want: signerruntime.SignerStateUnlocked},
		{name: "recovery, validation", from: func(ir *Runtime) { ir.EnterRecovery(nil) }, err: validation, want: signerruntime.SignerStateRecovery},
		{name: "locked, validation", from: func(ir *Runtime) { ir.Lock() }, err: validation, want: signerruntime.SignerStateLocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ir, mutation, _, _ := unlockedRuntimeForTest(t)
			bound, err := ir.ActivePaths()
			if err != nil {
				t.Fatal(err)
			}
			tc.from(ir)
			ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
				return &Loaded{Selection: &bound}, tc.err
			}, ReloadEffects{})
			var told []error
			ir.SetReloadRecoveryHook(func(cause error) {
				if ir.GetState() != signerruntime.SignerStateRecovery {
					t.Errorf("the hook ran in state %v, before the entry into recovery", ir.GetState())
				}
				told = append(told, cause)
			})

			mutation.Lock() // as every caller of Reload holds it
			_, err = ir.Reload()
			state := ir.GetState()
			mutation.Unlock()

			// A locked signer has no keyring to build with.
			wantErr := tc.err
			if tc.want == signerruntime.SignerStateLocked {
				wantErr = keystore.ErrStoreLocked
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("Reload() error = %v, want %v", err, wantErr)
			}
			if entered := errors.Is(err, ErrEnteredRecovery); entered != (tc.want == signerruntime.SignerStateRecovery) {
				t.Fatalf("Reload() error marks an entry into recovery: %v, want %v", entered, tc.want == signerruntime.SignerStateRecovery)
			}
			if state != tc.want {
				t.Fatalf("state = %v when Reload returned, want %v", state, tc.want)
			}
			// The hook is told of each entry into recovery, once, with the
			// defect; a lock that came first, and a failure of another
			// kind, tell it nothing.
			wantTold := tc.want == signerruntime.SignerStateRecovery
			if (len(told) == 1 && errors.Is(told[0], tc.err)) != wantTold || len(told) > 1 {
				t.Fatalf("the hook was told %v, want it told of the defect: %v", told, wantTold)
			}
			if state == signerruntime.SignerStateLocked {
				return
			}
			if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err != nil {
				t.Fatalf("the keyring is closed after the reload: %v", err)
			}
		})
	}
}
