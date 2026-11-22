// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
)

// The startup unlock runs the unlock an admin request runs
// (productruntime.Unlock), with the passphrase a helper supplied. These pin
// what the daemon does with each outcome: it starts unlocked, or in recovery
// for a damaged generation, and does not start for a wrong passphrase. The
// failure table covers the faults a reload can meet
// (TestWhatAFailedReloadLeavesBehind, "startup unlock").

// startupLocked is a test signer with one key, locked, with its log captured,
// as the daemon is before its startup unlock.
func startupLocked(t *testing.T) (*Signer, *syncBuffer) {
	t.Helper()
	server := characterizedSigner(t)
	server.productRuntime().Lock()
	logs := &syncBuffer{}
	appLogger.SetOutput(logs)
	t.Cleanup(func() { appLogger.SetOutput(os.Stderr) })
	return server, logs
}

// A good passphrase publishes: the signer starts unlocked with its key, and
// the passphrase the helper supplied is zeroed.
func TestTheStartupUnlockPublishes(t *testing.T) {
	server, _ := startupLocked(t)
	ir := server.productRuntime()
	passphrase := append([]byte(nil), testPassphrase...)

	if !server.unlockAtStartup(ir, passphrase) {
		t.Fatal("unlockAtStartup() = false, want the daemon to start")
	}
	if !ir.IsUnlocked() || ir.KeyCount() != 1 {
		t.Fatalf("state = %v with %d key(s), want unlocked with the key", ir.GetState(), ir.KeyCount())
	}
	if strings.Trim(string(passphrase), "\x00") != "" {
		t.Fatal("the startup unlock left the passphrase in memory")
	}
}

// A wrong passphrase stops the daemon, from the reconcile that found it: the
// signer stays locked with no keyring, and the log names the cause once. The
// startup unlock once went on from the failed reconcile to an entry into
// recovery, which opened the store root again and logged that the
// recovery-blocked store would not unlock.
func TestTheStartupUnlockStopsTheDaemonForAWrongPassphrase(t *testing.T) {
	server, logs := startupLocked(t)
	ir := server.productRuntime()

	if server.unlockAtStartup(ir, []byte("not the passphrase")) {
		t.Fatal("unlockAtStartup() = true for a wrong passphrase, want the daemon not to start")
	}
	if got := ir.GetState(); got != signerruntime.SignerStateLocked {
		t.Fatalf("state = %v, want locked", got)
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("WithKeyring() = %v, want no keyring", err)
	}
	got := logs.String()
	if strings.Count(got, "[ERROR] error unlocking the store: invalid passphrase") != 1 || strings.Contains(got, "recovery") {
		t.Fatalf("logs = %q, want one error line naming the wrong passphrase and no recovery", got)
	}
}

// A damaged generation starts the daemon in recovery, with the keyring the
// reconcile and the restore it needs use, and the log names the defect.
func TestTheStartupUnlockEntersRecoveryForADamagedGeneration(t *testing.T) {
	server, logs := startupLocked(t)
	ir := server.productRuntime()
	everyGeneration(t, server, func(dir string) {
		if err := os.WriteFile(filepath.Join(dir, "keys", "notes.txt"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	})

	if !server.unlockAtStartup(ir, append([]byte(nil), testPassphrase...)) {
		t.Fatal("unlockAtStartup() = false for a damaged generation, want the daemon to start in recovery")
	}
	if !ir.IsRecovery() || ir.KeyCount() != 0 {
		t.Fatalf("state = %v with %d key(s), want recovery with none", ir.GetState(), ir.KeyCount())
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err != nil {
		t.Fatalf("WithKeyring() = %v, want the keyring recovery needs", err)
	}
	if got := logs.String(); !strings.Contains(got, "[WARN] identity is recovery-blocked: ") || !strings.Contains(got, "notes.txt") {
		t.Fatalf("logs = %q, want the entry into recovery and its cause", got)
	}
}

// What an admin unlock request is answered for each way it ends, decided by
// the error values productruntime.Unlock returns: success, recovery_blocked,
// invalid_passphrase, or unlock_failed with the cause.
func TestTheUnlockAnswerForEachOutcome(t *testing.T) {
	validation := fmt.Errorf("the store would not load: %w", fmt.Errorf("%w: 1 malformed key file(s)", signertemplates.ErrGenerationValidation))
	collision := &apkeys.AddressCollisionError{Collisions: map[string][]string{"ADDR": {"keys/ADDR.key", "keys/ADDR.cos"}}}
	for _, tc := range []struct {
		name       string
		passphrase []byte
		recovery   bool // the request begins in recovery
		load       func(ir *productruntime.Runtime) error
		before     func(t *testing.T, server *Signer)
		want       string // success, code and message
	}{
		{name: "unlocks", want: "true  "},
		{name: "wrong passphrase", passphrase: []byte("not the passphrase"),
			want: "false invalid_passphrase invalid passphrase"},
		{name: "validation failure", load: func(*productruntime.Runtime) error { return validation },
			want: "true recovery_blocked "},
		{name: "address collision", load: func(*productruntime.Runtime) error { return collision },
			want: "true recovery_blocked "},
		// The store root no longer opens with the passphrase the request's
		// check passed: a failed unlock, logged, not a wrong passphrase.
		{name: "load cannot open the store root",
			load: func(*productruntime.Runtime) error {
				return fmt.Errorf("failed to unlock the keystore: %w", crypto.ErrInvalidPassphrase)
			},
			want: "false unlock_failed failed to load keys"},
		{name: "lost to a lock", load: func(ir *productruntime.Runtime) error { ir.Lock(); return nil },
			want: "false unlock_failed signer locked during unlock"},
		{name: "met a recovery", recovery: true, load: func(ir *productruntime.Runtime) error { ir.SetRecovery(); return nil },
			want: "true recovery_blocked "},
		{name: "maintenance in progress",
			before: func(t *testing.T, server *Signer) {
				ir := server.productRuntime()
				token := ir.BeginStoreMaintenance()
				t.Cleanup(func() { ir.FinishStoreMaintenance(token, false) })
			},
			want: "false unlock_failed store maintenance in progress"},
		{name: "store root unreadable",
			before: func(t *testing.T, server *Signer) {
				if err := os.WriteFile(server.keyPaths.StoreRootPath(), []byte("damaged"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "false unlock_failed store root could not be opened"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := characterizedSigner(t)
			ir := server.productRuntime()
			if tc.recovery {
				ir.SetRecovery()
			} else {
				ir.Lock()
			}
			if tc.load != nil {
				opts, hooks := testProductBuildOptions(server), server.productBuildHooks()
				ir.SetReloadFunc(func(passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
					if passphrase != nil {
						if err := tc.load(ir); err != nil {
							return nil, err
						}
					}
					return signerstartup.NewReloadService(ir, opts, hooks, session).Reload(passphrase)
				})
			}
			if tc.before != nil {
				tc.before(t, server)
			}
			passphrase := tc.passphrase
			if passphrase == nil {
				passphrase = testPassphrase
			}
			success, _, errMsg, code := server.adminServices().UnlockIdentity(passphrase)
			if got := fmt.Sprintf("%v %s %s", success, code, errMsg); !strings.HasPrefix(got, tc.want) {
				t.Fatalf("UnlockIdentity() = %q, want %q", got, tc.want)
			}
		})
	}
}
