// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templateadmin

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

func init() {
	lsigsignerreg.RegisterSigner()
}

type stubDeps struct {
	keyPaths              storepaths.Paths
	mu                    sync.Mutex
	mutationActive        atomic.Bool
	reloadOutsideMutation atomic.Bool
}

func (d *stubDeps) KeyPaths() storepaths.Paths { return d.keyPaths }

func (d *stubDeps) WithStoreMutation(fn func() error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.mutationActive.Store(true)
	defer d.mutationActive.Store(false)
	return fn()
}

func (d *stubDeps) Logf(string, ...interface{}) {}

var testPassphrase = []byte("test-passphrase-for-templateadmin")

// setupServiceWithReloadCounter constructs a templateadmin.Service with a real
// identity runtime whose reload function increments the returned counter.
func setupServiceWithReloadCounter(t *testing.T) (Service, *identity.Runtime, *atomic.Int64) {
	t.Helper()
	svc, ir, reloadCount, _ := setupServiceWithReload(t, nil)
	return svc, ir, reloadCount
}

func setupServiceWithReload(
	t *testing.T,
	reload func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error),
) (Service, *identity.Runtime, *atomic.Int64, *stubDeps) {
	t.Helper()

	tmpDir := t.TempDir()
	keyPaths := storepaths.NewPaths(tmpDir)
	genstoretest.MintFirst(t, keyPaths)
	userDir := filepath.Join(tmpDir, "identities", auth.DefaultIdentityID)
	if err := os.MkdirAll(keyPaths.LegacyKeysDir(), 0o750); err != nil {
		t.Fatalf("MkdirAll(keysDir): %v", err)
	}
	if _, err := crypto.CreateKeyringStore(userDir, testPassphrase); err != nil {
		t.Fatalf("CreateKeystoreMetadata: %v", err)
	}
	ks := keystore.NewFileKeyStoreForPaths(keyPaths)
	if err := ks.Unlock(testPassphrase); err != nil {
		t.Fatalf("InitializeMasterKey: %v", err)
	}

	deps := &stubDeps{keyPaths: keyPaths}
	var reloadCount atomic.Int64
	ir := identity.New(identity.Config{

		KeyStore:      ks,
		KeyPaths:      keyPaths,
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	ir.SetReloadFunc(func(masterKey []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		reloadCount.Add(1)
		if !deps.mutationActive.Load() {
			deps.reloadOutsideMutation.Store(true)
		}
		if reload != nil {
			return reload(masterKey, session)
		}
		return &signertemplates.ReloadReport{}, nil
	})
	ir.SetUnlocked()

	svc := Service{Deps: deps}
	return svc, ir, &reloadCount, deps
}

func putInstalledTemplateForServiceTest(t *testing.T, ir *identity.Runtime, keyType string, state keytypestate.State) {
	t.Helper()
	err := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
		if _, err := templatestore.SaveTemplateActive(
			genstoretest.Active(t, ir.KeyPaths()),
			[]byte("schema_version: 1\ntemplate_type: generic\n"),
			keyType,
			templatestore.TemplateTypeGeneric,
			masterKey,
		); err != nil {
			return err
		}
		return keytypestate.Put(ir.KeyPaths(), keytypestate.Record{
			KeyType: keyType,
			Source:  keytypestate.SourceYAMLGeneric,
			State:   state,
		})
	})
	if err != nil {
		t.Fatalf("install template fixture: %v", err)
	}
}

func assertReloadInsideMutation(t *testing.T, reloadCount *atomic.Int64, deps *stubDeps) {
	t.Helper()
	if got := reloadCount.Load(); got != 1 {
		t.Fatalf("reloadCount = %d, want 1", got)
	}
	if deps.reloadOutsideMutation.Load() {
		t.Fatal("reload ran outside WithStoreMutation")
	}
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
	if _, ok, err := keytypestate.Get(ir.KeyPaths(), "aplane.ed25519.v1"); err != nil {
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

	if _, ok, err := keytypestate.Get(ir.KeyPaths(), "aplane.ed25519.v1"); err != nil {
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
	if _, ok, err := keytypestate.Get(ir.KeyPaths(), "aplane.ed25519.v1"); err != nil {
		t.Fatalf("Get after Deactivate: %v", err)
	} else if !ok {
		t.Fatal("canonical state record was removed by unqualified deactivation")
	}
}

func TestActivateCompiledProviderReloadFailureLeavesStateRecord(t *testing.T) {
	reloadErr := errors.New("reload failed")
	svc, ir, reloadCount, deps := setupServiceWithReload(t, func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, reloadErr
	})

	result := svc.ActivateKeyType(ir, adminproto.ActivateKeyTypeRequest{KeyType: "aplane.ed25519.v1"})
	if result.Success || result.Code != protocol.ResultCodeReloadFailed {
		t.Fatalf("ActivateKeyType() = %+v, want reload_failed", result)
	}
	rec, ok, err := keytypestate.Get(ir.KeyPaths(), "aplane.ed25519.v1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok || rec.State != keytypestate.StateEnabled || rec.Source != keytypestate.SourceCompiled {
		t.Fatalf("state after reload failure = (%+v, %v), want enabled compiled record", rec, ok)
	}
	assertReloadInsideMutation(t, reloadCount, deps)
}

func TestDeactivateCompiledProviderReloadFailureLeavesStateRemoved(t *testing.T) {
	reloadErr := errors.New("reload failed")
	svc, ir, reloadCount, deps := setupServiceWithReload(t, func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, reloadErr
	})
	keyType := "aplane.ed25519.v1"
	if err := keytypestate.Put(ir.KeyPaths(), keytypestate.Record{
		KeyType: keyType,
		Source:  keytypestate.SourceCompiled,
		State:   keytypestate.StateEnabled,
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	result := svc.DeactivateKeyType(ir, adminproto.DeactivateKeyTypeRequest{KeyType: keyType})
	if result.Success || result.Code != protocol.ResultCodeReloadFailed || !result.Removed {
		t.Fatalf("DeactivateKeyType() = %+v, want reload_failed with removed=true", result)
	}
	if _, ok, err := keytypestate.Get(ir.KeyPaths(), keyType); err != nil {
		t.Fatalf("Get() error = %v", err)
	} else if ok {
		t.Fatal("compiled state record restored after reload failure, want removal retained")
	}
	assertReloadInsideMutation(t, reloadCount, deps)
}

func TestActivateInstalledTemplateFailureRestoresDisabledState(t *testing.T) {
	tests := []struct {
		name     string
		reload   func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error)
		wantCode string
	}{
		{
			name: "reload error",
			reload: func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
				return nil, errors.New("reload failed")
			},
			wantCode: protocol.ResultCodeReloadFailed,
		},
		{
			name: "reload report rejection",
			reload: func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
				return &signertemplates.ReloadReport{}, nil
			},
			wantCode: protocol.ResultCodeActivationFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, ir, reloadCount, deps := setupServiceWithReload(t, tt.reload)
			keyType := "test.templateadmin-enable-rollback.v1"
			putInstalledTemplateForServiceTest(t, ir, keyType, keytypestate.StateDisabled)

			result := svc.ActivateKeyType(ir, adminproto.ActivateKeyTypeRequest{KeyType: keyType})
			if result.Success || result.Code != tt.wantCode {
				t.Fatalf("ActivateKeyType() = %+v, want code %q", result, tt.wantCode)
			}
			rec, ok, err := keytypestate.Get(ir.KeyPaths(), keyType)
			if err != nil {
				t.Fatalf("Get() error = %v", err)
			}
			if !ok || rec.State != keytypestate.StateDisabled {
				t.Fatalf("state after activation failure = (%+v, %v), want disabled record", rec, ok)
			}
			assertReloadInsideMutation(t, reloadCount, deps)
		})
	}
}

func TestDeactivateInstalledTemplateReloadFailureLeavesDisabledState(t *testing.T) {
	svc, ir, reloadCount, deps := setupServiceWithReload(t, func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, errors.New("reload failed")
	})
	keyType := "test.templateadmin-disable-reload.v1"
	putInstalledTemplateForServiceTest(t, ir, keyType, keytypestate.StateEnabled)

	result := svc.DeactivateKeyType(ir, adminproto.DeactivateKeyTypeRequest{KeyType: keyType})
	if result.Success || result.Code != protocol.ResultCodeReloadFailed || !result.Removed {
		t.Fatalf("DeactivateKeyType() = %+v, want reload_failed with removed=true", result)
	}
	rec, ok, err := keytypestate.Get(ir.KeyPaths(), keyType)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok || rec.State != keytypestate.StateDisabled {
		t.Fatalf("state after reload failure = (%+v, %v), want disabled record", rec, ok)
	}
	assertReloadInsideMutation(t, reloadCount, deps)
}

func TestRemoveInstalledTemplateReloadFailureLeavesArchivedState(t *testing.T) {
	svc, ir, reloadCount, deps := setupServiceWithReload(t, func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, errors.New("reload failed")
	})
	keyType := "test.templateadmin-remove-reload.v1"
	putInstalledTemplateForServiceTest(t, ir, keyType, keytypestate.StateEnabled)

	result := svc.RemoveInstalledTemplate(ir, adminproto.RemoveInstalledTemplateRequest{KeyType: keyType})
	if result.Success || result.Code != protocol.ResultCodeReloadFailed || !result.Removed {
		t.Fatalf("RemoveInstalledTemplate() = %+v, want reload_failed with removed=true", result)
	}
	if _, ok, err := keytypestate.Get(ir.KeyPaths(), keyType); err != nil {
		t.Fatalf("Get() error = %v", err)
	} else if ok {
		t.Fatal("template state restored after reload failure, want removal retained")
	}
	if _, err := os.Stat(ir.KeyPaths().DeletedKeyTypeTemplate(keyType)); err != nil {
		t.Fatalf("archived template stat error = %v", err)
	}
	assertReloadInsideMutation(t, reloadCount, deps)
}
