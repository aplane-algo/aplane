// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/storelock"
)

type normalizeCall struct {
	dataDir  string
	uid, gid int
}

// rootRescueHooks runs the offline mutation as root on a store the hooks call
// managed or not, with the service principal 123:456 unless ownerErr, and
// records each normalization.
func rootRescueHooks(t *testing.T, managed bool, ownerErr error) *[]normalizeCall {
	t.Helper()
	oldUID, oldManaged, oldOwner, oldNormalize := EffectiveUID, IsManagedStore, ManagedStoreOwner, NormalizeStore
	t.Cleanup(func() {
		EffectiveUID, IsManagedStore, ManagedStoreOwner, NormalizeStore = oldUID, oldManaged, oldOwner, oldNormalize
	})
	EffectiveUID = func() int { return 0 }
	IsManagedStore = func(string) (bool, error) { return managed, nil }
	ManagedStoreOwner = func(string) (int, int, error) { return 123, 456, ownerErr }
	calls := &[]normalizeCall{}
	NormalizeStore = func(dataDir string, uid, gid int) error {
		*calls = append(*calls, normalizeCall{dataDir: dataDir, uid: uid, gid: gid})
		return nil
	}
	return calls
}

func requireStoreLockFree(t *testing.T, dataDir string) {
	t.Helper()
	lock, err := storelock.AcquireExclusive(dataDir)
	if err != nil {
		t.Fatalf("store lock still held: %v", err)
	}
	_ = lock.Close()
}

// A root rescue of a managed store hands the files back to the service
// principal, resolved before anything changes. It reads nothing from
// config.yaml, so one that does not parse does not stop it.
func TestOfflineMutationNormalizesAManagedStoreAsItsPrincipal(t *testing.T) {
	calls := rootRescueHooks(t, true, nil)
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("ipc_path: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	guard, err := AcquireOfflineMutation(dataDir)
	if err != nil {
		t.Fatalf("AcquireOfflineMutation() error = %v", err)
	}
	if err := guard.Normalize(); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	guard.Close()
	if want := []normalizeCall{{dataDir: dataDir, uid: 123, gid: 456}}; len(*calls) != 1 || (*calls)[0] != want[0] {
		t.Fatalf("normalizations = %+v, want %+v", *calls, want)
	}
	requireStoreLockFree(t, dataDir)
}

func TestOfflineMutationRefusesBeforeChangesWithoutAPrincipal(t *testing.T) {
	calls := rootRescueHooks(t, true, errors.New("no principal record"))
	dataDir := t.TempDir()

	_, err := AcquireOfflineMutation(dataDir)
	if want := "resolve managed signer service principal: no principal record"; err == nil || err.Error() != want {
		t.Fatalf("AcquireOfflineMutation() error = %v, want %q", err, want)
	}
	if len(*calls) != 0 {
		t.Fatalf("normalizations = %+v, want none", *calls)
	}
	requireStoreLockFree(t, dataDir)
}

// Only a root rescue of a managed store changes ownership afterwards.
func TestOfflineMutationLeavesOtherStoresAlone(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T) *[]normalizeCall{
		"local store as root": func(t *testing.T) *[]normalizeCall { return rootRescueHooks(t, false, nil) },
		"not root": func(t *testing.T) *[]normalizeCall {
			calls := rootRescueHooks(t, true, nil)
			EffectiveUID = func() int { return 1000 }
			IsManagedStore = func(string) (bool, error) {
				t.Error("a rescue without root asked whether the store is managed")
				return true, nil
			}
			return calls
		},
	} {
		t.Run(name, func(t *testing.T) {
			calls := setup(t)
			dataDir := t.TempDir()
			guard, err := AcquireOfflineMutation(dataDir)
			if err != nil {
				t.Fatalf("AcquireOfflineMutation() error = %v", err)
			}
			if err := guard.Normalize(); err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			guard.Close()
			if len(*calls) != 0 {
				t.Fatalf("normalizations = %+v, want none", *calls)
			}
			requireStoreLockFree(t, dataDir)
		})
	}
}
