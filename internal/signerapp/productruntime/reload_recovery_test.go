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

// A reload without a passphrase that finds a content defect in the selected
// generation, a failed validation or an address collision, enters recovery
// before it returns, and so before its caller
// releases the store mutation lock: such a reload has published an empty key
// snapshot, and an unlocked signer serving it says it can sign with no keys.
// Recovery keeps the keyring, for the reconcile that lifts it. A signer
// already in recovery stays there, and a locked one stays locked. Any other
// failure, such as a keys directory that cannot be read, leaves the state as
// it was, for the caller to answer. Each entry is passed to the hook the
// process root set, which tells the admin session and the log.
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
		{name: "recovery, address collision", from: (*Runtime).SetRecovery, err: collision, want: signerruntime.SignerStateRecovery},
		{name: "unlocked, other failure", from: func(*Runtime) {}, err: other, want: signerruntime.SignerStateUnlocked},
		{name: "recovery, validation", from: (*Runtime).SetRecovery, err: validation, want: signerruntime.SignerStateRecovery},
		{name: "locked, validation", from: (*Runtime).Lock, err: validation, want: signerruntime.SignerStateLocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ir, mutation, _, _ := unlockedRuntimeForTest(t)
			tc.from(ir)
			ir.SetReloadFunc(func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
				return nil, tc.err
			})
			var told []error
			ir.SetReloadRecoveryHook(func(cause error) {
				if ir.GetState() != signerruntime.SignerStateRecovery {
					t.Errorf("the hook ran in state %v, before the entry into recovery", ir.GetState())
				}
				told = append(told, cause)
			})

			mutation.Lock() // as every caller of Reload holds it
			_, err := ir.Reload()
			state := ir.GetState()
			mutation.Unlock()

			if !errors.Is(err, tc.err) {
				t.Fatalf("Reload() error = %v, want %v", err, tc.err)
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
