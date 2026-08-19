// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package identity

import (
	"context"
	"errors"
	"github.com/aplane-algo/aplane/internal/productmode"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/policy"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
)

func TestValidateProductIdentityLayout(t *testing.T) {
	t.Run("missing identities", func(t *testing.T) {
		if err := ValidateProductIdentityLayout(t.TempDir(), productmode.IdentityID); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing default", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, "identities"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := ValidateProductIdentityLayout(root, productmode.IdentityID); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("real default", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "identities", productmode.IdentityID), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := ValidateProductIdentityLayout(root, productmode.IdentityID); err != nil {
			t.Fatal(err)
		}
	})

	for _, entryType := range []string{"directory", "file", "hidden", "symlink"} {
		entryType := entryType
		t.Run("reject extra "+entryType, func(t *testing.T) {
			root := t.TempDir()
			identitiesDir := filepath.Join(root, "identities")
			if err := os.MkdirAll(filepath.Join(identitiesDir, productmode.IdentityID), 0o700); err != nil {
				t.Fatal(err)
			}
			name := "alice"
			switch entryType {
			case "directory":
				if err := os.Mkdir(filepath.Join(identitiesDir, name), 0o700); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(filepath.Join(identitiesDir, name), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "hidden":
				name = ".stale"
				if err := os.Mkdir(filepath.Join(identitiesDir, name), 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(t.TempDir(), filepath.Join(identitiesDir, name)); err != nil {
					t.Fatal(err)
				}
			}
			err := ValidateProductIdentityLayout(root, productmode.IdentityID)
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("ValidateProductIdentityLayout() error = %v, want unexpected entry %q", err, name)
			}
		})
	}

	t.Run("reject symlinked default", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, "identities"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), filepath.Join(root, "identities", productmode.IdentityID)); err != nil {
			t.Fatal(err)
		}
		err := ValidateProductIdentityLayout(root, productmode.IdentityID)
		if err == nil || !strings.Contains(err.Error(), "real directory") {
			t.Fatalf("ValidateProductIdentityLayout() error = %v, want real-directory rejection", err)
		}
	})
}

func TestRuntimePolicySnapshotStoresDefensiveCopies(t *testing.T) {
	ir := New(Config{
		Authenticator: auth.NewTokenAuthenticator("tok"),
	})
	rejectForeignRekey := false
	maxFee := uint64(7000)
	enabled := true
	onNoRoute := string(policy.TransferOnNoRouteReject)
	stored := &policy.StoredConfig{StoredPolicyCore: policy.StoredPolicyCore{RejectForeignRekey: &rejectForeignRekey, MaxFeeMicroAlgos: &maxFee, TransferPolicy: &policy.StoredTransferPolicy{
		SchemaVersion: 1,
		Enabled:       &enabled,
		OnNoRoute:     &onNoRoute,
		Routes: []policy.StoredTransferRoute{
			{
				ID:           "ops_algo",
				Networks:     []string{"mainnet"},
				Sources:      []string{"*"},
				Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
				Destinations: []string{"*"},
			},
		},
		RoutesSet: true,
	}},
	}
	effective := policy.DefaultConfig()
	effective.RejectForeignRekey = false
	effective.MaxFeeMicroAlgos = maxFee

	ir.SetPolicyState(stored, effective)

	gotStored, gotEffective := ir.PolicySnapshot()
	if gotStored == nil || gotEffective == nil {
		t.Fatalf("PolicySnapshot() = (%v, %v), want both snapshots", gotStored, gotEffective)
	}
	if gotStored.RejectForeignRekey == nil || *gotStored.RejectForeignRekey {
		t.Fatalf("stored RejectForeignRekey = %#v, want false", gotStored.RejectForeignRekey)
	}
	if gotEffective.MaxFeeMicroAlgos != maxFee {
		t.Fatalf("effective MaxFeeMicroAlgos = %d, want %d", gotEffective.MaxFeeMicroAlgos, maxFee)
	}

	*gotStored.RejectForeignRekey = true
	gotStored.TransferPolicy.Routes[0].ID = "mutated"
	gotEffective.MaxFeeMicroAlgos = 1

	gotStored, gotEffective = ir.PolicySnapshot()
	if gotStored.RejectForeignRekey == nil || *gotStored.RejectForeignRekey {
		t.Fatalf("stored snapshot was mutated through returned copy: %#v", gotStored.RejectForeignRekey)
	}
	if gotStored.TransferPolicy.Routes[0].ID != "ops_algo" {
		t.Fatalf("stored route ID = %q, want ops_algo", gotStored.TransferPolicy.Routes[0].ID)
	}
	if gotEffective.MaxFeeMicroAlgos != maxFee {
		t.Fatalf("effective snapshot was mutated through returned copy: %d", gotEffective.MaxFeeMicroAlgos)
	}

	ir.SetPolicy(policy.DefaultConfig())
	gotStored, gotEffective = ir.PolicySnapshot()
	if gotStored != nil {
		t.Fatalf("stored snapshot after SetPolicy = %#v, want nil", gotStored)
	}
	if gotEffective == nil {
		t.Fatal("effective policy after SetPolicy = nil, want policy")
	}
}

func TestKeysetRevisionIncrementsOnSnapshotPublish(t *testing.T) {
	ir := New(Config{
		Authenticator: auth.NewTokenAuthenticator("tok"),
	})

	if got := ir.KeysetRevision(); got != 0 {
		t.Fatalf("initial KeysetRevision() = %d, want 0", got)
	}

	ir.PublishSnapshot(
		map[string]string{"ADDR1": "keys/ADDR1.key"},
		map[string]string{"ADDR1": "ed25519"},
	)
	if got := ir.KeysetRevision(); got != 1 {
		t.Fatalf("KeysetRevision() after first publish = %d, want 1", got)
	}

	ir.PublishSnapshot(
		map[string]string{"ADDR1": "keys/ADDR1.key"},
		map[string]string{"ADDR1": "ed25519"},
	)
	if got := ir.KeysetRevision(); got != 2 {
		t.Fatalf("KeysetRevision() after second publish = %d, want 2", got)
	}

	ir.SetUnlocked()
	ir.Lock()
	if got := ir.KeysetRevision(); got != 3 {
		t.Fatalf("KeysetRevision() after lock clears snapshot = %d, want 3", got)
	}
}

func TestKeyIndexSnapshotMaterializesConsistentCopy(t *testing.T) {
	ir := New(Config{
		Authenticator: auth.NewTokenAuthenticator("tok"),
	})
	ir.PublishSnapshot(
		map[string]string{"ADDR1": "keys/ADDR1.key"},
		map[string]string{"ADDR1": "ed25519"},
	)
	ir.keysLock.Lock()
	ir.keyMetadata["ADDR1"] = KeyPublicMetadata{
		Category:     "governance",
		PublicKeyHex: "abcd",
		Parameters:   map[string]string{"purpose": "rekey"},
		LogicSigResources: &lsigresource.Profile{
			ProgramBytes: 10,
			Default:      &lsigresource.PathProfile{ArgumentBytes: 20, MaxOpcodeCost: 30},
		},
	}
	ir.keysLock.Unlock()

	snapshot := ir.KeyIndexSnapshot()
	if snapshot.Revision != 1 {
		t.Fatalf("snapshot revision = %d, want 1", snapshot.Revision)
	}
	if got := snapshot.KeyFiles["ADDR1"]; got != "keys/ADDR1.key" {
		t.Fatalf("snapshot key file = %q, want keys/ADDR1.key", got)
	}
	if got := snapshot.KeyTypes["ADDR1"]; got != "ed25519" {
		t.Fatalf("snapshot key type = %q, want ed25519", got)
	}
	if got := snapshot.KeyMetadata["ADDR1"].Parameters["purpose"]; got != "rekey" {
		t.Fatalf("snapshot key metadata purpose = %q, want rekey", got)
	}

	snapshot.KeyFiles["ADDR1"] = "mutated.key"
	snapshot.KeyTypes["ADDR1"] = "mutated"
	metadata := snapshot.KeyMetadata["ADDR1"]
	metadata.Category = "mutated"
	metadata.Parameters["purpose"] = "mutated"
	metadata.LogicSigResources.Default.ArgumentBytes = 999
	snapshot.KeyMetadata["ADDR1"] = metadata
	if got := ir.keyMetadata["ADDR1"].Category; got != "governance" {
		t.Fatalf("runtime metadata category = %q after caller mutation, want governance", got)
	}
	if got := ir.keyMetadata["ADDR1"].Parameters["purpose"]; got != "rekey" {
		t.Fatalf("runtime metadata purpose = %q after caller mutation, want rekey", got)
	}
	if got := ir.keyMetadata["ADDR1"].LogicSigResources.Default.ArgumentBytes; got != 20 {
		t.Fatalf("runtime LogicSig argument bytes = %d after caller mutation, want 20", got)
	}
	ir.PublishSnapshot(
		map[string]string{"ADDR2": "keys/ADDR2.key"},
		map[string]string{"ADDR2": "aplane.falcon1024.v1"},
	)

	if got := snapshot.KeyFiles["ADDR1"]; got != "mutated.key" {
		t.Fatalf("snapshot key file after later publish = %q, want retained caller mutation", got)
	}
	current := ir.KeyIndexSnapshot()
	if current.Revision != 2 {
		t.Fatalf("current revision = %d, want 2", current.Revision)
	}
	if _, ok := current.KeyFiles["ADDR1"]; ok {
		t.Fatal("current snapshot retained ADDR1 after replacement publish")
	}
	if got := current.KeyFiles["ADDR2"]; got != "keys/ADDR2.key" {
		t.Fatalf("current key file = %q, want keys/ADDR2.key", got)
	}
}

func TestWatcherReloadUsesMutationLock(t *testing.T) {
	ir := New(Config{
		Authenticator: auth.NewTokenAuthenticator("tok"),
	})
	ir.SetUnlocked()

	reloaded := make(chan struct{}, 1)
	ir.SetReloadFunc(func(passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		reloaded <- struct{}{}
		return nil, nil
	})

	var mutationMu sync.Mutex
	ir.SetReloadMutationLock(func() sync.Locker {
		return &mutationMu
	})

	var reloadFn func() error
	started := make(chan struct{})
	ir.EnsureKeyWatcher(func(dirs []string, ctx context.Context, fn func() error) error {
		reloadFn = fn
		close(started)
		return nil
	})

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("watcher did not start")
	}
	if reloadFn == nil {
		t.Fatal("watcher reload callback not captured")
	}

	mutationMu.Lock()
	done := make(chan error, 1)
	go func() {
		done <- reloadFn()
	}()

	select {
	case err := <-done:
		t.Fatalf("watcher reload completed while mutation lock held: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-reloaded:
		t.Fatal("reload ran while mutation lock held")
	default:
	}

	mutationMu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("watcher reload error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("watcher reload did not finish after mutation lock release")
	}
	select {
	case <-reloaded:
	case <-time.After(time.Second):
		t.Fatal("reload function was not called after mutation lock release")
	}
}

func TestStoredConfigApply(t *testing.T) {
	userAutoApprove := true
	lockOnDisconnect := false
	cfg := &StoredConfig{
		UserAutoApprove:   &userAutoApprove,
		LockOnDisconnect:  &lockOnDisconnect,
		PassphraseTimeout: "45m",
		ApprovalWait:      "10m",
	}

	effective, err := cfg.Apply(ConfigDefaults{
		UserAutoApprove:  false,
		LockOnDisconnect: true,
		SessionTimeout:   15 * time.Minute,
		ApprovalWait:     5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !effective.UserAutoApprove {
		t.Fatal("user_auto_approve override not applied")
	}
	if effective.LockOnDisconnect {
		t.Fatal("lock_on_disconnect override not applied")
	}
	if effective.SessionTimeout != 45*time.Minute {
		t.Fatalf("session timeout = %s, want %s", effective.SessionTimeout, 45*time.Minute)
	}
	if effective.ApprovalWait != 10*time.Minute {
		t.Fatalf("approval wait = %s, want %s", effective.ApprovalWait, 10*time.Minute)
	}
}

func TestStoredConfigApplyRejectsMode(t *testing.T) {
	effective, err := (&StoredConfig{}).Apply(ConfigDefaults{})
	if err != nil {
		t.Fatalf("Apply(default) error = %v", err)
	}
	if effective.UserAutoApprove || effective.LockOnDisconnect || effective.SessionTimeout != 0 || effective.ApprovalWait != 0 {
		t.Fatalf("default effective config = %#v, want zero-valued overlays", effective)
	}

	if _, err := (&StoredConfig{Mode: "sentry"}).Apply(ConfigDefaults{}); err == nil {
		t.Fatal("Apply(mode) error = nil")
	} else if !strings.Contains(err.Error(), "identity config mode is unsupported") {
		t.Fatalf("Apply(mode) error = %q, want unsupported mode", err.Error())
	}
}

func TestNodeFailStateIsFirstErrorSticky(t *testing.T) {
	state := &NodeFailState{}
	first := errors.New("first role conflict")
	second := errors.New("second role conflict")

	state.Fail(first)
	state.Fail(second)

	err := state.Err()
	if !errors.Is(err, ErrNodeFailClosed) {
		t.Fatalf("Err() = %v, want ErrNodeFailClosed", err)
	}
	if !errors.Is(err, first) {
		t.Fatalf("Err() = %v, want first cause", err)
	}
	if errors.Is(err, second) {
		t.Fatalf("Err() = %v, should keep first cause", err)
	}
}

func TestNodeFailStateConcurrentPublicationAndReads(t *testing.T) {
	state := &NodeFailState{}
	first := errors.New("first role conflict")
	start := make(chan struct{})
	done := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		state.Fail(first)
		close(done)
	}()
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for {
				err := state.Err()
				if err != nil && !errors.Is(err, ErrNodeFailClosed) {
					t.Errorf("Err() exposed non-fail-closed state: %v", err)
					return
				}
				select {
				case <-done:
					return
				default:
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state.Fail(errors.New("later role conflict"))
			if err := state.Err(); !errors.Is(err, first) {
				t.Errorf("Err() = %v, want sticky first cause", err)
			}
		}()
	}
	wg.Wait()
}

func TestStoredConfigApplyUserAutoApprove(t *testing.T) {
	userAutoApprove := false
	cfg := &StoredConfig{
		UserAutoApprove: &userAutoApprove,
	}

	effective, err := cfg.Apply(ConfigDefaults{
		UserAutoApprove:  true,
		LockOnDisconnect: true,
		SessionTimeout:   15 * time.Minute,
		ApprovalWait:     5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if effective.UserAutoApprove {
		t.Fatal("user_auto_approve override not applied")
	}
}

func TestSaveAndLoadStoredConfig(t *testing.T) {
	root := t.TempDir()
	if err := SaveStoredSetting(root, "user_auto_approve", true); err != nil {
		t.Fatalf("SaveStoredSetting() error = %v", err)
	}
	if err := SaveStoredSetting(root, "lock_on_disconnect", false); err != nil {
		t.Fatalf("SaveStoredSetting() error = %v", err)
	}
	if err := SaveStoredSetting(root, "approval_wait", "10m"); err != nil {
		t.Fatalf("SaveStoredSetting() error = %v", err)
	}

	cfg, err := LoadStoredConfig(root)
	if err != nil {
		t.Fatalf("LoadStoredConfig() error = %v", err)
	}
	if cfg.UserAutoApprove == nil || !*cfg.UserAutoApprove {
		t.Fatal("user_auto_approve not persisted")
	}
	if cfg.LockOnDisconnect == nil || *cfg.LockOnDisconnect {
		t.Fatal("lock_on_disconnect not persisted")
	}
	if cfg.ApprovalWait != "10m" {
		t.Fatalf("approval_wait = %q, want %q", cfg.ApprovalWait, "10m")
	}
}

func TestLoadStoredConfigTreatsEmptyDocumentsAsEmptyConfig(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "empty", data: ""},
		{name: "whitespace", data: " \n\t\n"},
		{name: "comments only", data: "# all settings inherit defaults\n# user_auto_approve: true\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			path := ConfigPath(root)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatal(err)
			}

			cfg, err := LoadStoredConfig(root)
			if err != nil {
				t.Fatalf("LoadStoredConfig() error = %v", err)
			}
			if cfg.UserAutoApprove != nil || cfg.LockOnDisconnect != nil ||
				cfg.PassphraseTimeout != "" || cfg.ApprovalWait != "" || cfg.Mode != "" {
				t.Fatalf("LoadStoredConfig() = %#v, want empty config", cfg)
			}
		})
	}
}

func TestLoadStoredConfigRejectsDecommissionedField(t *testing.T) {
	root := t.TempDir()
	path := ConfigPath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("decommissioned: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadStoredConfig(root); err == nil || !strings.Contains(err.Error(), "decommissioned") {
		t.Fatalf("LoadStoredConfig() error = %v, want unknown decommissioned field", err)
	}
}

func TestLoadAuthorizedKeysRejectsMalformedFile(t *testing.T) {
	root := t.TempDir()
	ir := New(Config{
		Authenticator: auth.NewTokenAuthenticator("tok"),
		KeyPaths:      utilkeys.NewPaths(root),
	})

	path := ir.AuthorizedKeysPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not-a-valid-authorized-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ir.LoadAuthorizedKeys(); err == nil {
		t.Fatal("LoadAuthorizedKeys() succeeded on malformed file, want error")
	}
}
