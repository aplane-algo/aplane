// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templateadmin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keystore/keystoretest"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatespec"
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
// product runtime whose reload function increments the returned counter.
func setupServiceWithReloadCounter(t *testing.T) (Service, *productruntime.Runtime, *atomic.Int64) {
	t.Helper()
	svc, ir, reloadCount, _ := setupServiceWithReload(t, nil)
	return svc, ir, reloadCount
}

func setupServiceWithReload(
	t *testing.T,
	reload func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error),
) (Service, *productruntime.Runtime, *atomic.Int64, *stubDeps) {
	t.Helper()

	tmpDir := t.TempDir()
	keyPaths := storepaths.NewPaths(tmpDir)
	keyring, active := genstoretest.MintFirstAtomic(t, keyPaths, testPassphrase)
	keyring.Zero()
	keyPaths = genstoretest.BindActive(t, keyPaths, active)
	ks := keystore.NewFileKeyStore()
	if err := keystoretest.Unlock(ks, keyPaths, testPassphrase); err != nil {
		t.Fatalf("InitializeMasterKey: %v", err)
	}

	deps := &stubDeps{keyPaths: keyPaths}
	var reloadCount atomic.Int64
	ir := productruntime.New(productruntime.Config{
		KeyStore: ks,
		KeyPaths: keyPaths,
	})
	// The reload's build, reduced to the selection and the policy in
	// service: reload, when given, decides whether it fails. A failure keeps
	// the generation bound, so the reload keeps the view in service.
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*productruntime.Loaded, error) {
		reloadCount.Add(1)
		if !deps.mutationActive.Load() {
			deps.reloadOutsideMutation.Store(true)
		}
		selection, err := genstore.AuthenticateStoreRootSelection(keyPaths, kr)
		if err != nil {
			return nil, err
		}
		policy, set := ir.PolicyState()
		loaded := &productruntime.Loaded{
			Selection: &selection, PolicyVerified: true, Policy: policy, ASASet: set,
			Contents: keystore.Contents{Selection: &selection},
		}
		if reload != nil {
			if _, err := reload(nil, nil); err != nil {
				return loaded, err
			}
		}
		return loaded, nil
	}, productruntime.ReloadEffects{})
	ir.SetUnlocked()

	svc := Service{Deps: deps, Runtime: ir}
	return svc, ir, &reloadCount, deps
}

// putInstalledTemplateForServiceTest installs a valid generic template for
// keyType, which names it as test.<family>.v1, with a record in state that
// pins no fingerprint. An enable checks the template as the reload after it
// would, so the template must load.
func putInstalledTemplateForServiceTest(t *testing.T, ir *productruntime.Runtime, keyType string, state keytypestate.State) {
	t.Helper()
	family := strings.TrimSuffix(strings.TrimPrefix(keyType, "test."), ".v1")
	yaml := fmt.Sprintf(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: %s
version: 1
display_name: "Service Test"
valid_rekey_target: false
max_opcode_cost: 20000
teal: |
  #pragma version 8
  int 0
`, family)
	err := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
		if _, err := templatestore.SaveTemplateActive(
			genstoretest.Active(t, ir.KeyPaths()),
			[]byte(yaml),
			keyType,
			templatespec.TemplateTypeGeneric,
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
	svc, _, reloadCount := setupServiceWithReloadCounter(t)

	result := svc.ActivateKeyType(adminproto.ActivateKeyTypeRequest{
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

	result := svc.ActivateKeyType(adminproto.ActivateKeyTypeRequest{
		KeyType: "falcon1024.v1",
	})
	if result.Success {
		t.Fatal("ActivateKeyType(unqualified) succeeded, want failure")
	}
	if result.KeyType != "falcon1024.v1" {
		t.Fatalf("KeyType = %q, want falcon1024.v1", result.KeyType)
	}
	if _, ok, err := keytypestate.Get(ir.KeyPaths(), "aplane.falcon1024.v1"); err != nil {
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

	if result := svc.ActivateKeyType(adminproto.ActivateKeyTypeRequest{
		KeyType: "aplane.ed25519.v1",
	}); !result.Success {
		t.Fatalf("setup ActivateKeyType failed: code=%q error=%q", result.Code, result.Error)
	}
	reloadCount.Store(0)

	result := svc.DeactivateKeyType(adminproto.DeactivateKeyTypeRequest{
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

	if result := svc.ActivateKeyType(adminproto.ActivateKeyTypeRequest{
		KeyType: "aplane.ed25519.v1",
	}); !result.Success {
		t.Fatalf("setup ActivateKeyType failed: code=%q error=%q", result.Code, result.Error)
	}

	result := svc.DeactivateKeyType(adminproto.DeactivateKeyTypeRequest{
		KeyType: "falcon1024.v1",
	})
	if result.KeyType != "falcon1024.v1" {
		t.Fatalf("KeyType = %q, want falcon1024.v1", result.KeyType)
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

	result := svc.ActivateKeyType(adminproto.ActivateKeyTypeRequest{KeyType: "aplane.ed25519.v1"})
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
	keyType := "aplane.falcon1024.v1"
	if err := keytypestate.Put(ir.KeyPaths(), keytypestate.Record{
		KeyType: keyType,
		Source:  keytypestate.SourceCompiled,
		State:   keytypestate.StateEnabled,
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	result := svc.DeactivateKeyType(adminproto.DeactivateKeyTypeRequest{KeyType: keyType})
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

			result := svc.ActivateKeyType(adminproto.ActivateKeyTypeRequest{KeyType: keyType})
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

// A failed install or enable undoes what it wrote where it wrote it, though the
// reload that failed left the key paths bound to another generation, or a lock
// left them bound to none.
func TestARollbackUndoesTheGenerationTheWriteWentTo(t *testing.T) {
	const family = "templateadmin-rollback-paths"
	const keyType = "test." + family + ".v1"
	yaml := []byte(`schema_version: 1
derivation_version: 3
template_type: generic
template_mode: generated
publisher: test
family: ` + family + `
version: 1
display_name: "Rollback Paths"
valid_rekey_target: false
max_opcode_cost: 20000
teal: |
  #pragma version 8
  int 0
`)
	operations := map[string]struct {
		prepare func(t *testing.T, ir *productruntime.Runtime)
		run     func(svc Service) (success bool, code, message string)
		left    bool // the disabled template an enable starts from stays
	}{
		"install": {
			prepare: func(t *testing.T, ir *productruntime.Runtime) {
				if err := fsutil.MkdirAllPrivate(ir.KeyPaths().TemplateLibraryDir()); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(ir.KeyPaths().TemplateLibraryDir(), "rollback.yaml"), yaml, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			run: func(svc Service) (bool, string, string) {
				result := svc.InstallLibraryTemplate(adminproto.InstallLibraryTemplateRequest{KeyType: keyType, TemplateType: string(templatespec.TemplateTypeGeneric)})
				return result.Success, result.Code, result.Error
			},
		},
		"import": {
			run: func(svc Service) (bool, string, string) {
				result := svc.ImportInstalledTemplate(adminproto.ImportInstalledTemplateRequest{TemplateYAML: yaml})
				return result.Success, result.Code, result.Error
			},
		},
		"enable": {
			prepare: func(t *testing.T, ir *productruntime.Runtime) {
				putInstalledTemplateForServiceTest(t, ir, keyType, keytypestate.StateDisabled)
			},
			run: func(svc Service) (bool, string, string) {
				result := svc.ActivateKeyType(adminproto.ActivateKeyTypeRequest{KeyType: keyType})
				return result.Success, result.Code, result.Error
			},
			left: true,
		},
	}
	failures := map[string]error{
		protocol.ResultCodeReloadFailed:     errors.New("reload failed"),
		protocol.ResultCodeActivationFailed: nil, // the reload succeeds without the template
	}
	for name, op := range operations {
		for code, reloadErr := range failures {
			for _, moved := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s, %s, moved %v", name, code, moved), func(t *testing.T) {
					var deps *stubDeps
					var rebound storepaths.Paths
					svc, ir, reloadCount, stub := setupServiceWithReload(t, func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
						deps.keyPaths = rebound
						return nil, reloadErr
					})
					deps = stub
					written := genstoretest.Active(t, ir.KeyPaths())
					rebound = storepaths.NewPaths(svc.Deps.KeyPaths().Root())
					if moved {
						rebound = genstoretest.BindActive(t, rebound, rebound.GenerationPaths("gen-1800000000-0a0b0c0d"))
					}
					if op.prepare != nil {
						op.prepare(t, ir)
					}

					success, gotCode, message := op.run(svc)
					if success || gotCode != code || strings.Contains(message, "rollback failed") {
						t.Fatalf("success %v, code %q, error %q; want %s with the rollback done", success, gotCode, message, code)
					}
					if reloadCount.Load() != 1 {
						t.Fatalf("reloads = %d, want 1", reloadCount.Load())
					}
					if templatestore.TemplateExistsActive(written, keyType, templatespec.TemplateTypeGeneric) != op.left {
						t.Fatalf("template in the generation written = %v, want %v", !op.left, op.left)
					}
					rec, ok, err := keytypestate.GetActive(written, keyType)
					if err != nil || ok != op.left || (ok && rec.State != keytypestate.StateDisabled) {
						t.Fatalf("state in the generation written = %+v, %v, %v", rec, ok, err)
					}
				})
			}
		}
	}
}

func TestDeactivateInstalledTemplateReloadFailureLeavesDisabledState(t *testing.T) {
	svc, ir, reloadCount, deps := setupServiceWithReload(t, func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, errors.New("reload failed")
	})
	keyType := "test.templateadmin-disable-reload.v1"
	putInstalledTemplateForServiceTest(t, ir, keyType, keytypestate.StateEnabled)

	result := svc.DeactivateKeyType(adminproto.DeactivateKeyTypeRequest{KeyType: keyType})
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

	result := svc.RemoveInstalledTemplate(adminproto.RemoveInstalledTemplateRequest{KeyType: keyType})
	if result.Success || result.Code != protocol.ResultCodeReloadFailed || !result.Removed {
		t.Fatalf("RemoveInstalledTemplate() = %+v, want reload_failed with removed=true", result)
	}
	if _, ok, err := keytypestate.Get(ir.KeyPaths(), keyType); err != nil {
		t.Fatalf("Get() error = %v", err)
	} else if ok {
		t.Fatal("template state restored after reload failure, want removal retained")
	}
	active, err := genstore.Resolve(ir.KeyPaths())
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if _, err := os.Stat(active.DeletedKeyTypeTemplate(keyType)); err != nil {
		t.Fatalf("archived template stat error = %v", err)
	}
	assertReloadInsideMutation(t, reloadCount, deps)
}

// Both admin install paths run template admission, so a template declaring a
// LogicSig argument the network refuses never reaches the store: not as imported
// YAML, and not as a library file.
func TestInstallRefusesTemplateWithAnArgumentTheNetworkRefuses(t *testing.T) {
	const keyType = "test.admin-install-oversized.v1"
	const want = "runtime_arg blob is 5000 bytes: a LogicSig argument is at most 4096"
	yaml := []byte(`schema_version: 1
derivation_version: 3
template_type: generic
template_mode: generated
publisher: test
family: admin-install-oversized
version: 1
display_name: "Admin Install Oversized"
valid_rekey_target: false
max_opcode_cost: 20000
runtime_args:
  - name: blob
    type: bytes
    max_size: 5000
teal: |
  arg 0
  len
  return
`)
	svc, ir, reloadCount := setupServiceWithReloadCounter(t)

	imported := svc.ImportInstalledTemplate(adminproto.ImportInstalledTemplateRequest{TemplateYAML: yaml})
	if imported.Success || imported.Code != protocol.ResultCodeInvalidTemplate || !strings.Contains(imported.Error, want) {
		t.Fatalf("ImportInstalledTemplate() = %+v, want invalid template: %s", imported, want)
	}

	if err := fsutil.MkdirAllPrivate(ir.KeyPaths().TemplateLibraryDir()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ir.KeyPaths().TemplateLibraryDir(), "oversized.yaml"), yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	installed := svc.InstallLibraryTemplate(adminproto.InstallLibraryTemplateRequest{
		KeyType: keyType, TemplateType: string(templatespec.TemplateTypeGeneric),
	})
	if installed.Success || installed.Code != protocol.ResultCodeInstallFailed || !strings.Contains(installed.Error, "not found in library") {
		t.Fatalf("InstallLibraryTemplate() = %+v, want the library entry refused", installed)
	}
	// The listing says why.
	listed := svc.ListLibraryTemplates()
	found := false
	for _, item := range listed.Templates {
		if item.FileName == "oversized.yaml" {
			found = true
			if !strings.Contains(item.Invalid, want) || item.Installed {
				t.Fatalf("library entry = %+v, want invalid: %s", item, want)
			}
		}
	}
	if !found {
		t.Fatalf("ListLibraryTemplates() = %+v, want an entry for oversized.yaml", listed)
	}

	if templatestore.TemplateExistsActive(genstoretest.Active(t, ir.KeyPaths()), keyType, templatespec.TemplateTypeGeneric) {
		t.Fatal("a refused install left a template in the store")
	}
	if got := reloadCount.Load(); got != 0 {
		t.Fatalf("reloadCount = %d, want 0: nothing was installed", got)
	}
}

// The library lists a template whose descriptions are YAML block scalars
// without the line break each one ends with, as /keytypes lists the key type
// once it is installed.
func TestLibraryListingDropsTheBlockScalarLineBreak(t *testing.T) {
	svc, ir, _ := setupServiceWithReloadCounter(t)
	if err := fsutil.MkdirAllPrivate(ir.KeyPaths().TemplateLibraryDir()); err != nil {
		t.Fatal(err)
	}
	yaml := []byte(`schema_version: 1
derivation_version: 3
template_type: generic
template_mode: generated
publisher: test
family: admin-block-description
version: 1
display_name: "Admin Block Description"
description: |
  Pays one recipient
valid_rekey_target: false
max_opcode_cost: 20000
parameters:
  - name: limit
    label: "Limit"
    description: >
      A limit for
      the operator
    type: uint64
runtime_args:
  - name: secret
    label: "Secret"
    description: |
      The secret
    type: bytes
    max_size: 32
teal: |
  #pragma version 8
  int 1
  return
`)
	if err := os.WriteFile(filepath.Join(ir.KeyPaths().TemplateLibraryDir(), "block.yaml"), yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	listed := svc.ListLibraryTemplates()
	for _, item := range listed.Templates {
		if item.FileName != "block.yaml" {
			continue
		}
		if item.Invalid != "" || item.Description != "Pays one recipient" {
			t.Fatalf("library entry = %+v", item)
		}
		if len(item.Parameters) != 1 || item.Parameters[0].Description != "A limit for the operator" {
			t.Fatalf("parameters = %+v", item.Parameters)
		}
		if len(item.RuntimeArgs) != 1 || item.RuntimeArgs[0].Description != "The secret" {
			t.Fatalf("runtime arguments = %+v", item.RuntimeArgs)
		}
		return
	}
	t.Fatalf("ListLibraryTemplates() = %+v, want an entry for block.yaml", listed)
}
