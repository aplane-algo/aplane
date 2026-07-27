// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templateadmin

import (
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

func init() {
	lsigsignerreg.RegisterSigner()
}

type stubDeps struct {
	keyPaths storepaths.Paths
	mu       sync.Mutex
}

func (d *stubDeps) KeyPaths() storepaths.Paths { return d.keyPaths }

func (d *stubDeps) WithIdentityMutation(_ string, fn func() error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fn()
}

func (d *stubDeps) Logf(string, ...interface{}) {}

var testPassphrase = []byte("test-passphrase-for-templateadmin")

// setupServiceWithReloadCounter constructs a templateadmin.Service with a real
// identity runtime whose reload function increments the returned counter.
func setupServiceWithReloadCounter(t *testing.T) (Service, *identity.Runtime, *atomic.Int64) {
	t.Helper()

	tmpDir := t.TempDir()
	keyPaths := storepaths.NewPaths(tmpDir)
	genstoretest.MintFirst(t, keyPaths, "default")
	userDir := filepath.Join(tmpDir, "identities", auth.DefaultIdentityID)
	if err := os.MkdirAll(keyPaths.KeysDir(auth.DefaultIdentityID), 0o750); err != nil {
		t.Fatalf("MkdirAll(keysDir): %v", err)
	}
	if _, _, err := crypto.CreateKeystoreMetadata(userDir, testPassphrase); err != nil {
		t.Fatalf("CreateKeystoreMetadata: %v", err)
	}
	ks := keystore.NewFileKeyStoreForPaths(keyPaths, auth.DefaultIdentityID)
	if _, err := ks.InitializeMasterKey(testPassphrase); err != nil {
		t.Fatalf("InitializeMasterKey: %v", err)
	}

	var reloadCount atomic.Int64
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		KeyStore:      ks,
		KeyPaths:      keyPaths,
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	ir.SetReloadFunc(func(string, []byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		reloadCount.Add(1)
		return &signertemplates.ReloadReport{}, nil
	})
	ir.SetUnlocked()

	svc := Service{Deps: &stubDeps{keyPaths: keyPaths}}
	return svc, ir, &reloadCount
}

// Locks in B2 regression coverage: ActivateKeyType's compiled-provider branch
// writes a state record via keytypestate.Put and MUST call ir.Reload() before
// returning, so the in-memory key index does not diverge from on-disk state.
func TestActivateKeyTypeCompiledProviderTriggersReload(t *testing.T) {
	svc, ir, reloadCount := setupServiceWithReloadCounter(t)

	result := svc.ActivateKeyType(ir, adminproto.ActivateKeyTypeRequest{
		KeyType: "aplane.ed25519.v1",
	})
	if !result.Success {
		t.Fatalf("ActivateKeyType failed: code=%q error=%q", result.Code, result.Error)
	}
	if got := reloadCount.Load(); got < 1 {
		t.Fatalf("reloadCount = %d, want >= 1 (admin handler missed ir.Reload after state-record write)", got)
	}
}

func TestActivateKeyTypeDoesNotInferPublisher(t *testing.T) {
	svc, ir, _ := setupServiceWithReloadCounter(t)

	result := svc.ActivateKeyType(ir, adminproto.ActivateKeyTypeRequest{
		KeyType: "ed25519.v1",
	})
	if result.Success {
		t.Fatal("ActivateKeyType(unqualified) succeeded, want failure")
	}
	if result.KeyType != "ed25519.v1" {
		t.Fatalf("KeyType = %q, want ed25519.v1", result.KeyType)
	}
	if _, ok, err := keytypestate.Get(ir.KeyPaths(), ir.ID(), "aplane.ed25519.v1"); err != nil {
		t.Fatalf("Get after Activate: %v", err)
	} else if ok {
		t.Fatal("canonical state record was created for unqualified key type")
	}
}

// Locks in B2 regression coverage for the deactivation handler. Both internal
// branches (YAML disable + compiled deactivate) flow through one Reload call
// site after the state-record write.
func TestDeactivateKeyTypeCompiledProviderTriggersReload(t *testing.T) {
	svc, ir, reloadCount := setupServiceWithReloadCounter(t)

	if result := svc.ActivateKeyType(ir, adminproto.ActivateKeyTypeRequest{
		KeyType: "aplane.ed25519.v1",
	}); !result.Success {
		t.Fatalf("setup ActivateKeyType failed: code=%q error=%q", result.Code, result.Error)
	}
	reloadCount.Store(0)

	result := svc.DeactivateKeyType(ir, adminproto.DeactivateKeyTypeRequest{
		KeyType: "aplane.ed25519.v1",
	})
	if !result.Success {
		t.Fatalf("DeactivateKeyType failed: code=%q error=%q", result.Code, result.Error)
	}
	if got := reloadCount.Load(); got < 1 {
		t.Fatalf("reloadCount = %d, want >= 1 (admin handler missed ir.Reload after state-record delete)", got)
	}

	if _, ok, err := keytypestate.Get(ir.KeyPaths(), ir.ID(), "aplane.ed25519.v1"); err != nil {
		t.Fatalf("Get after Deactivate: %v", err)
	} else if ok {
		t.Fatal("state record still present after Deactivate; record should have been removed")
	}
}

func TestDeactivateKeyTypeDoesNotInferPublisher(t *testing.T) {
	svc, ir, _ := setupServiceWithReloadCounter(t)

	if result := svc.ActivateKeyType(ir, adminproto.ActivateKeyTypeRequest{
		KeyType: "aplane.ed25519.v1",
	}); !result.Success {
		t.Fatalf("setup ActivateKeyType failed: code=%q error=%q", result.Code, result.Error)
	}

	result := svc.DeactivateKeyType(ir, adminproto.DeactivateKeyTypeRequest{
		KeyType: "ed25519.v1",
	})
	if result.KeyType != "ed25519.v1" {
		t.Fatalf("KeyType = %q, want ed25519.v1", result.KeyType)
	}
	if result.Removed {
		t.Fatal("DeactivateKeyType(unqualified).Removed = true, want false")
	}
	if _, ok, err := keytypestate.Get(ir.KeyPaths(), ir.ID(), "aplane.ed25519.v1"); err != nil {
		t.Fatalf("Get after Deactivate: %v", err)
	} else if !ok {
		t.Fatal("canonical state record was removed by unqualified deactivation")
	}
}
