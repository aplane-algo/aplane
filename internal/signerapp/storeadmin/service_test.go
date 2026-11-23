// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeadmin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/clientreg"
)

type auditEvent struct {
	kind                     string
	reason                   string
	keysMigrated             int
	templatesMigrated        int
	policySidecarsMigrated   int
	sourceTokenFilesMigrated int
}

type recordingAuditLog struct {
	events []auditEvent
}

func (l *recordingAuditLog) LogStoreInitialized(metadataDir string) {
	l.events = append(l.events, auditEvent{kind: "store_initialized"})
}

func (l *recordingAuditLog) LogStoreInitializeFailed(reason string) {
	l.events = append(l.events, auditEvent{kind: "store_initialize_failed", reason: reason})
}

func (l *recordingAuditLog) LogPassphraseChanged(_ context.Context, keysMigrated, templatesMigrated, policySidecarsMigrated, sourceTokenFilesMigrated int) {
	l.events = append(l.events, auditEvent{
		kind:                     "passphrase_changed",
		keysMigrated:             keysMigrated,
		templatesMigrated:        templatesMigrated,
		policySidecarsMigrated:   policySidecarsMigrated,
		sourceTokenFilesMigrated: sourceTokenFilesMigrated,
	})
}

func (l *recordingAuditLog) LogPassphraseChangeFailed(_ context.Context, reason string) {
	l.events = append(l.events, auditEvent{kind: "passphrase_change_failed", reason: reason})
}

func TestInitializeStoreRejectsNilRuntime(t *testing.T) {
	result := Service{}.InitializeStore(adminproto.InitializeStoreRequest{
		Passphrase: []byte("passphrase"),
	})
	if result.Code != protocol.ErrCodeNoRuntimeBound {
		t.Fatalf("Code = %q, want %q", result.Code, protocol.ErrCodeNoRuntimeBound)
	}
}

func TestInitializeStoreRejectsEmptyPassphraseAndAudits(t *testing.T) {
	audit := &recordingAuditLog{}
	ir := testIdentityRuntime()

	result := Service{Runtime: ir, AuditLog: audit}.InitializeStore(adminproto.InitializeStoreRequest{})
	if result.Code != protocol.ErrCodeInvalidPassphrase {
		t.Fatalf("Code = %q, want %q", result.Code, protocol.ErrCodeInvalidPassphrase)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %#v, want one event", audit.events)
	}
	if got := audit.events[0]; got.kind != "store_initialize_failed" || got.reason != "passphrase is required" {
		t.Fatalf("audit event = %#v, want product store initialize failure", got)
	}
}

type initializeTestDeps struct {
	dataDir string
	paths   storepaths.Paths
	cfg     serverconfig.ServerConfig
	mu      sync.Mutex
}

func (d *initializeTestDeps) DataDir() string                    { return d.dataDir }
func (d *initializeTestDeps) Config() *serverconfig.ServerConfig { return &d.cfg }
func (d *initializeTestDeps) KeyPaths() storepaths.Paths         { return d.paths }
func (d *initializeTestDeps) Logf(string, ...interface{})        {}
func (d *initializeTestDeps) WithStoreMutation(fn func() error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fn()
}

func TestInitializeStoreReleasesMutationLockBeforeUnlock(t *testing.T) {
	clientreg.RegisterClient()
	dataDir := t.TempDir()
	deps := &initializeTestDeps{
		dataDir: dataDir,
		paths:   storepaths.NewPaths(dataDir),
	}
	ir := testIdentityRuntime()
	unlockCalled := false
	service := Service{
		Deps:    deps,
		Runtime: ir,
		UnlockIdentity: func(_ []byte) (bool, int, string, string) {
			unlockCalled = true
			if err := deps.WithStoreMutation(func() error {
				return nil
			}); err != nil {
				return false, 0, err.Error(), ""
			}
			return true, 0, "", ""
		},
	}
	done := make(chan adminproto.InitializeStoreResult, 1)
	go func() {
		done <- service.InitializeStore(adminproto.InitializeStoreRequest{
			Passphrase: []byte("initialize-passphrase"),
		})
	}()

	select {
	case result := <-done:
		if !result.Success {
			t.Fatalf("InitializeStore() result = %#v", result)
		}
		if !unlockCalled {
			t.Fatal("InitializeStore() did not invoke unlock")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("InitializeStore() deadlocked by re-entering the store mutation lock")
	}
}

func TestChangeStorePassphraseRejectsInvalidInputsAndAudits(t *testing.T) {
	tests := []struct {
		name string
		req  adminproto.ChangeStorePassphraseRequest
		want string
	}{
		{
			name: "missing current",
			req: adminproto.ChangeStorePassphraseRequest{
				NewPassphrase: []byte("new-passphrase"),
			},
			want: "current and new passphrases are required",
		},
		{
			name: "missing new",
			req: adminproto.ChangeStorePassphraseRequest{
				CurrentPassphrase: []byte("current-passphrase"),
			},
			want: "current and new passphrases are required",
		},
		{
			name: "same passphrase",
			req: adminproto.ChangeStorePassphraseRequest{
				CurrentPassphrase: []byte("same-passphrase"),
				NewPassphrase:     []byte("same-passphrase"),
			},
			want: "new passphrase must be different from current passphrase",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			audit := &recordingAuditLog{}
			ir := testIdentityRuntime()

			result := Service{Runtime: ir, AuditLog: audit}.ChangeStorePassphrase(context.Background(), tt.req)
			if result.Code != "invalid_passphrase" {
				t.Fatalf("Code = %q, want invalid_passphrase", result.Code)
			}
			if result.Error != tt.want {
				t.Fatalf("Error = %q, want %q", result.Error, tt.want)
			}
			if len(audit.events) != 1 {
				t.Fatalf("audit events = %#v, want one event", audit.events)
			}
			if got := audit.events[0]; got.kind != "passphrase_change_failed" || got.reason != tt.want {
				t.Fatalf("audit event = %#v, want product passphrase change failure", got)
			}
		})
	}
}

// A current passphrase that does not open the store is invalid_passphrase. A
// store whose selected generation is damaged fails the change under its own
// code, so the operator is not told a right passphrase is wrong.
func TestChangeStorePassphraseReportsADamagedStoreApartFromAWrongPassphrase(t *testing.T) {
	dataDir := t.TempDir()
	deps := &initializeTestDeps{dataDir: dataDir, paths: storepaths.NewPaths(dataDir)}
	current := []byte("current-passphrase")
	if _, err := storeinit.Initialize(append([]byte(nil), current...), storeinit.Options{
		ValidateCandidate: func(storeinit.FirstGenerationCandidate) error { return nil },
		DataDir:           dataDir,
		Paths:             deps.paths,
	}); err != nil {
		t.Fatal(err)
	}
	active, kr, err := genstore.ResolveStoreRoot(deps.paths, current)
	if err != nil {
		t.Fatal(err)
	}
	kr.Zero()
	if err := os.RemoveAll(active.Dir()); err != nil {
		t.Fatal(err)
	}
	service := Service{Deps: deps, Runtime: testIdentityRuntime()}
	change := func(currentPassphrase []byte) adminproto.ChangeStorePassphraseResult {
		return service.ChangeStorePassphrase(context.Background(), adminproto.ChangeStorePassphraseRequest{
			CurrentPassphrase: currentPassphrase,
			NewPassphrase:     []byte("new-passphrase"),
		})
	}

	if result := change([]byte("wrong-passphrase")); result.Success || result.Code != protocol.ErrCodeInvalidPassphrase {
		t.Fatalf("change with a wrong passphrase = %#v, want invalid_passphrase", result)
	}
	result := change(current)
	if result.Success || result.Code != protocol.ResultCodePassphraseChangeFailed || !strings.Contains(result.Error, "selected generation") {
		t.Fatalf("change on a damaged store = %#v, want passphrase_change_failed naming the selected generation", result)
	}
}

func TestPassphraseCommandConfigFromUnlock(t *testing.T) {
	if got := passphraseCommandConfigFromUnlock(nil); got != nil {
		t.Fatalf("nil unlock config produced %#v, want nil", got)
	}
	if got := passphraseCommandConfigFromUnlock(&unlockconfig.UnlockConfig{}); got != nil {
		t.Fatalf("empty unlock config produced %#v, want nil", got)
	}

	got := passphraseCommandConfigFromUnlock(&unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"/bin/helper", "read"},
		PassphraseCommandEnv:  map[string]string{"TOKEN": "abc"},
	})
	if got == nil {
		t.Fatal("passphrase command config = nil, want config")
		return
	}
	if len(got.Argv) != 2 || got.Argv[0] != "/bin/helper" || got.Argv[1] != "read" {
		t.Fatalf("Argv = %#v, want helper argv", got.Argv)
	}
	if got.Env["TOKEN"] != "abc" {
		t.Fatalf("Env = %#v, want TOKEN", got.Env)
	}
}

func testIdentityRuntime() *productruntime.Runtime {
	return productruntime.New(productruntime.Config{
		ApprovalWait: serverconfig.DefaultApprovalWait,
	})
}

// ChangeStorePassphrase must forward all four distinct migration counts
// (keys, templates, policy sidecars, and source token files) to
// LogPassphraseChanged on both normal completion and a post-commit reload
// failure (where RootCommitted is already true).
func TestChangeStorePassphraseAuditsAllFourMigrationCounts(t *testing.T) {
	clientreg.RegisterClient()
	witnessID := witness.DeriveID(witness.Ed25519V1, make([]byte, 32))
	keyDoc, err := policytest.Document(noderole.RoleCosigner, witnessID, `{}`)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name        string
		reloadFails bool
	}{
		{name: "success", reloadFails: false},
		{name: "root committed with reload failure", reloadFails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			deps := &initializeTestDeps{dataDir: dataDir, paths: storepaths.NewPaths(dataDir)}
			current := []byte("current-passphrase")
			if _, err := storeinit.Initialize(append([]byte(nil), current...), storeinit.Options{
				ValidateCandidate: func(storeinit.FirstGenerationCandidate) error { return nil },
				DataDir:           dataDir,
				Paths:             deps.paths,
				Role:              noderole.RoleCosigner,
			}); err != nil {
				t.Fatal(err)
			}
			active, kr, err := genstore.ResolveStoreRoot(deps.paths, current)
			if err != nil {
				t.Fatal(err)
			}
			defer kr.Zero()
			// Mint a successor with four distinct non-zero migration counts:
			// 3 keys, 4 templates, 2 policy sidecars (default + key), and 1 source token file.
			_, err = genstore.Mint(deps.paths, genstore.MintRequest{
				SkipCandidateValidation: true,
				GenerationID:            "gen-1785200001-00000002",
				Parent:                  active.GenerationID(),
				Integrity:               kr,
				Operation:               "test-seed",
				OperationID:             "test-seed-1",
				CreatedAt:               time.Now().UTC(),
				Apply: func(staged storepaths.GenPaths) error {
					for _, keyName := range []string{"DELETED1", "DELETED2", "DELETED3"} {
						sealed, err := kr.Seal([]byte("archived-key"), crypto.AccountKeyContext(keyName))
						if err != nil {
							return err
						}
						if err := os.WriteFile(filepath.Join(staged.DeletedKeysDir(), keyName+".key"), sealed, 0o600); err != nil {
							return err
						}
					}
					for _, tplName := range []string{"archived1.v1", "archived2.v1", "archived3.v1", "archived4.v1"} {
						sealed, err := kr.Seal([]byte("archived-template"), crypto.KeyTypeTemplateContext(tplName))
						if err != nil {
							return err
						}
						if err := os.WriteFile(staged.DeletedKeyTypeTemplate(tplName), sealed, 0o600); err != nil {
							return err
						}
					}
					if err := policy.WriteKeyPolicy(staged, noderole.RoleCosigner, witnessID, []byte(keyDoc), kr, time.Now().UTC()); err != nil {
						return err
					}
					return sourcetokens.WriteFile(staged, &sourcetokens.File{
						Selector: policy.DefaultKey,
						Tokens: map[string]sourcetokens.Token{
							"screen": {Value: []byte("tok-value-1"), SetAt: time.Now().UTC().Truncate(time.Second)},
						},
					}, kr)
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			rtCfg := productruntime.Config{
				KeyPaths:     deps.paths,
				NodeRole:     noderole.RoleCosigner,
				ApprovalWait: serverconfig.DefaultApprovalWait,
			}
			if !tc.reloadFails {
				rtCfg.KeyStore = keystore.NewFileKeyStore()
			}
			ir := productruntime.New(rtCfg)
			if !tc.reloadFails {
				ir.SetBuildFunc(func(kr *crypto.Keyring) (*productruntime.Loaded, error) {
					sel, err := genstore.AuthenticateStoreRootSelection(deps.paths, kr)
					if err != nil {
						return nil, err
					}
					return &productruntime.Loaded{
						Selection: &sel,
						Contents:  keystore.Contents{Selection: &sel},
					}, nil
				}, productruntime.ReloadEffects{})
			}
			audit := &recordingAuditLog{}
			svc := Service{Deps: deps, Runtime: ir, AuditLog: audit}
			result := svc.ChangeStorePassphrase(context.Background(), adminproto.ChangeStorePassphraseRequest{
				CurrentPassphrase: current,
				NewPassphrase:     []byte("rotated-passphrase"),
			})
			if !result.RootCommitted {
				t.Fatalf("result = %+v, want RootCommitted=true", result)
			}
			if tc.reloadFails && result.Success {
				t.Fatalf("result = %+v, want reload failure after root commit", result)
			}
			if !tc.reloadFails && !result.Success {
				t.Fatalf("result = %+v, want success", result)
			}
			if result.KeysMigrated != 3 || result.TemplatesMigrated != 4 ||
				result.PolicySidecarsMigrated != 2 || result.SourceTokenFilesMigrated != 1 {
				t.Fatalf("result counts = keys %d templates %d policy %d tokens %d, want 3, 4, 2, 1",
					result.KeysMigrated, result.TemplatesMigrated,
					result.PolicySidecarsMigrated, result.SourceTokenFilesMigrated)
			}
			if len(audit.events) != 1 || audit.events[0].kind != "passphrase_changed" {
				t.Fatalf("audit events = %+v, want one passphrase_changed", audit.events)
			}
			got := audit.events[0]
			if got.keysMigrated != 3 ||
				got.templatesMigrated != 4 ||
				got.policySidecarsMigrated != 2 ||
				got.sourceTokenFilesMigrated != 1 {
				t.Fatalf("audited migration counts = %+v, want keys=3 templates=4 policy=2 tokens=1", got)
			}
		})
	}
}
