// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package identity

import (
	"context"
	"errors"
	"github.com/aplane-algo/aplane/internal/crypto"
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
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
)

func TestValidateProductIdentityLayout(t *testing.T) {
	t.Run("missing identities", func(t *testing.T) {
		if err := ValidateProductIdentityLayout(t.TempDir(), auth.DefaultIdentityID); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing default", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, "identities"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := ValidateProductIdentityLayout(root, auth.DefaultIdentityID); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("real default", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "identities", auth.DefaultIdentityID), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := ValidateProductIdentityLayout(root, auth.DefaultIdentityID); err != nil {
			t.Fatal(err)
		}
	})

	for _, entryType := range []string{"directory", "file", "hidden", "symlink"} {
		entryType := entryType
		t.Run("reject extra "+entryType, func(t *testing.T) {
			root := t.TempDir()
			identitiesDir := filepath.Join(root, "identities")
			if err := os.MkdirAll(filepath.Join(identitiesDir, auth.DefaultIdentityID), 0o700); err != nil {
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
			err := ValidateProductIdentityLayout(root, auth.DefaultIdentityID)
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
		if err := os.Symlink(t.TempDir(), filepath.Join(root, "identities", auth.DefaultIdentityID)); err != nil {
			t.Fatal(err)
		}
		err := ValidateProductIdentityLayout(root, auth.DefaultIdentityID)
		if err == nil || !strings.Contains(err.Error(), "real directory") {
			t.Fatalf("ValidateProductIdentityLayout() error = %v, want real-directory rejection", err)
		}
	})
}

func TestRuntimePolicySnapshotStoresDefensiveCopies(t *testing.T) {
	ir := New(Config{
		ID:            "test",
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
		ID:            "test",
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
		ID:            "test",
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

func TestDecommission(t *testing.T) {
	root := t.TempDir()
	ir := New(Config{
		ID:            "test",
		Authenticator: auth.NewTokenAuthenticator("tok"),
		PersistDecommission: func(identityID string) error {
			return SaveStoredSetting(root, identityID, "decommissioned", true)
		},
	})
	ir.SetUnlocked()

	if ir.IsDecommissioned() {
		t.Fatal("should not be decommissioned initially")
	}

	if err := ir.Decommission(); err != nil {
		t.Fatalf("Decommission() error = %v", err)
	}

	if !ir.IsDecommissioned() {
		t.Fatal("should be decommissioned after Decommission()")
	}
	if ir.IsUnlocked() {
		t.Fatal("should be locked after decommission")
	}

	// TryUnlock rejected
	ok, _, errMsg := ir.TryUnlock([]byte("any"), nil)
	if ok {
		t.Fatal("TryUnlock should fail on decommissioned identity")
	}
	if errMsg != ErrDecommissioned.Error() {
		t.Fatalf("TryUnlock errMsg = %q, want %q", errMsg, ErrDecommissioned.Error())
	}

	// Reload rejected
	if _, err := ir.Reload(); err != ErrDecommissioned {
		t.Fatalf("Reload error = %v, want ErrDecommissioned", err)
	}

	// ReloadWithPassphrase rejected
	if _, err := ir.ReloadWithPassphrase([]byte("x")); err != ErrDecommissioned {
		t.Fatalf("ReloadWithPassphrase error = %v, want ErrDecommissioned", err)
	}

	// RequestSigningApproval rejected
	_, err := ir.RequestSigningApproval("r", "a", "s", "d", 0, 0, nil, 0)
	if err != ErrDecommissioned {
		t.Fatalf("RequestSigningApproval error = %v, want ErrDecommissioned", err)
	}

	// RequestTokenProvisioning rejected
	_, err = ir.RequestTokenProvisioning("r", "id", "fp", "addr", 0)
	if err != ErrDecommissioned {
		t.Fatalf("RequestTokenProvisioning error = %v, want ErrDecommissioned", err)
	}

	// SnapshotKeySession returns nil
	if s := ir.SnapshotKeySession(); s != nil {
		t.Fatal("SnapshotKeySession should return nil for decommissioned identity")
	}

	// KeySnapshot returns nil maps
	keys, keyTypes := ir.KeySnapshot()
	if keys != nil || keyTypes != nil {
		t.Fatal("KeySnapshot should return nil maps for decommissioned identity")
	}

	// WithKeyring rejected
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err != ErrDecommissioned {
		t.Fatalf("WithKeyring error = %v, want ErrDecommissioned", err)
	}

	storedCfg, err := LoadStoredConfig(root, "test")
	if err != nil {
		t.Fatalf("LoadStoredConfig() error = %v", err)
	}
	if !storedCfg.IsDecommissioned() {
		t.Fatal("decommissioned state was not persisted")
	}
}

func TestDecommissionNotifiesLockedAfterLifecycleUnlock(t *testing.T) {
	notifyErr := make(chan error, 1)
	var ir *Runtime
	ir = New(Config{
		ID:            "test",
		Authenticator: auth.NewTokenAuthenticator("tok"),
		OnLocked: func() {
			release, err := ir.BeginOperation()
			if release != nil {
				release()
			}
			notifyErr <- err
		},
	})
	ir.SetUnlocked()

	decommissionDone := make(chan error, 1)
	go func() {
		decommissionDone <- ir.Decommission()
	}()

	select {
	case err := <-decommissionDone:
		if err != nil {
			t.Fatalf("Decommission() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Decommission() did not return; locked notification may be running under lifecycleMu")
	}

	select {
	case err := <-notifyErr:
		if err != ErrDecommissioned {
			t.Fatalf("BeginOperation() from locked notification error = %v, want ErrDecommissioned", err)
		}
	case <-time.After(time.Second):
		t.Fatal("locked notification did not run")
	}
}

func TestDecommissionPersistErrorLeavesRuntimeActive(t *testing.T) {
	injected := errors.New("persist failed")
	ir := New(Config{
		ID:            "test",
		Authenticator: auth.NewTokenAuthenticator("tok"),
		PersistDecommission: func(identityID string) error {
			if identityID != "test" {
				t.Fatalf("PersistDecommission identityID = %q, want test", identityID)
			}
			return injected
		},
	})
	ir.SetUnlocked()

	delivered := make(chan struct{})
	c := signerapproval.New(
		func() bool { return true },
		func(req *signerapproval.SignRequest) bool {
			if req.ID != "req-1" {
				t.Errorf("approval request ID = %q, want req-1", req.ID)
			}
			close(delivered)
			return true
		},
		nil,
		nil,
	)
	ir.SetApprovalCoordinator(c)

	type approvalResult struct {
		approved bool
		err      error
	}
	result := make(chan approvalResult, 1)
	go func() {
		approved, err := ir.RequestSigningApproval("req-1", "addr", "sender", "desc", 0, 0, nil, time.Minute)
		result <- approvalResult{approved: approved, err: err}
	}()

	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("approval request was not delivered")
	}
	if got := ir.PendingSignCount(); got != 1 {
		t.Fatalf("PendingSignCount() before decommission = %d, want 1", got)
	}

	if err := ir.Decommission(); !errors.Is(err, injected) {
		t.Fatalf("Decommission() error = %v, want %v", err, injected)
	}
	if ir.IsDecommissioned() {
		t.Fatal("runtime decommissioned despite persistence failure")
	}
	if !ir.IsUnlocked() {
		t.Fatal("runtime locked despite persistence failure")
	}
	if got := ir.PendingSignCount(); got != 1 {
		t.Fatalf("PendingSignCount() after failed decommission = %d, want 1", got)
	}
	select {
	case got := <-result:
		t.Fatalf("approval completed after failed decommission: %#v", got)
	default:
	}

	ir.HandleSignApprovalResponse(&signerapproval.SignResponse{
		ID:       "req-1",
		Approved: false,
		Reason:   "test cleanup",
	})
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("cleanup approval response error = %v", got.err)
		}
		if got.approved {
			t.Fatal("cleanup approval response approved = true, want false")
		}
	case <-time.After(time.Second):
		t.Fatal("pending approval did not finish after cleanup response")
	}
	if got := ir.PendingSignCount(); got != 0 {
		t.Fatalf("PendingSignCount() after cleanup = %d, want 0", got)
	}
}

func TestDecommissionFailsPendingApprovals(t *testing.T) {
	ir := New(Config{
		ID:            "test",
		Authenticator: auth.NewTokenAuthenticator("tok"),
	})
	delivered := make(chan struct{})
	c := signerapproval.New(
		func() bool { return true },
		func(req *signerapproval.SignRequest) bool {
			close(delivered)
			return true
		},
		nil,
		nil,
	)
	ir.SetApprovalCoordinator(c)

	type approvalResult struct {
		approved bool
		err      error
	}
	result := make(chan approvalResult, 1)
	go func() {
		approved, err := ir.RequestSigningApproval("req-1", "addr", "sender", "desc", 0, 0, nil, time.Minute)
		result <- approvalResult{approved: approved, err: err}
	}()

	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("approval request was not delivered")
	}

	if err := ir.Decommission(); err != nil {
		t.Fatalf("Decommission() error = %v", err)
	}

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("RequestSigningApproval() error = %v, want nil rejection", got.err)
		}
		if got.approved {
			t.Fatal("RequestSigningApproval() approved = true, want false")
		}
	case <-time.After(time.Second):
		t.Fatal("pending approval was not failed by decommission")
	}
	if ir.PendingSignCount() != 0 {
		t.Fatalf("PendingSignCount() = %d, want 0", ir.PendingSignCount())
	}
}

func TestDecommissionWaitsForActiveOperation(t *testing.T) {
	ir := New(Config{
		ID:            "test",
		Authenticator: auth.NewTokenAuthenticator("tok"),
	})

	release, err := ir.BeginOperation()
	if err != nil {
		t.Fatalf("BeginOperation() error = %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- ir.Decommission()
	}()

	select {
	case err := <-done:
		t.Fatalf("Decommission() completed before active operation release: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	release()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Decommission() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Decommission() did not complete after active operation release")
	}

	if _, err := ir.BeginOperation(); err != ErrDecommissioned {
		t.Fatalf("BeginOperation() after decommission error = %v, want ErrDecommissioned", err)
	}
}

func TestDecommissionWaitingBlocksNewOperation(t *testing.T) {
	ir := New(Config{
		ID:            "test",
		Authenticator: auth.NewTokenAuthenticator("tok"),
	})

	release, err := ir.BeginOperation()
	if err != nil {
		t.Fatalf("BeginOperation() error = %v", err)
	}

	decommissionDone := make(chan error, 1)
	go func() {
		decommissionDone <- ir.Decommission()
	}()

	deadline := time.After(time.Second)
	for {
		if ir.lifecycleMu.TryRLock() {
			ir.lifecycleMu.RUnlock()
			select {
			case err := <-decommissionDone:
				t.Fatalf("Decommission() completed before active operation release: %v", err)
			case <-deadline:
				t.Fatal("Decommission() did not start waiting for the lifecycle write lock")
			default:
				time.Sleep(time.Millisecond)
				continue
			}
		}
		break
	}

	beginDone := make(chan error, 1)
	go func() {
		release, err := ir.BeginOperation()
		if release != nil {
			release()
		}
		beginDone <- err
	}()

	select {
	case err := <-beginDone:
		t.Fatalf("BeginOperation() completed while Decommission was waiting: %v", err)
	default:
	}

	release()

	select {
	case err := <-decommissionDone:
		if err != nil {
			t.Fatalf("Decommission() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Decommission() did not complete after active operation release")
	}

	select {
	case err := <-beginDone:
		if err != ErrDecommissioned {
			t.Fatalf("BeginOperation() after queued decommission error = %v, want ErrDecommissioned", err)
		}
	case <-time.After(time.Second):
		t.Fatal("BeginOperation() did not unblock after decommission")
	}
}

func TestDecommissionStopsKeyWatcher(t *testing.T) {
	ir := New(Config{
		ID:            "test",
		Authenticator: auth.NewTokenAuthenticator("tok"),
	})

	watcherStarted := make(chan struct{})
	watcherStopped := make(chan struct{})
	ir.EnsureKeyWatcher(func(_ []string, ctx context.Context, _ func() error) error {
		close(watcherStarted)
		go func() {
			<-ctx.Done()
			close(watcherStopped)
		}()
		return nil
	})

	select {
	case <-watcherStarted:
	case <-time.After(time.Second):
		t.Fatal("watcher did not start")
	}

	if err := ir.Decommission(); err != nil {
		t.Fatalf("Decommission() error = %v", err)
	}

	select {
	case <-watcherStopped:
	case <-time.After(time.Second):
		t.Fatal("watcher did not stop after decommission")
	}

	restarted := make(chan struct{})
	ir.EnsureKeyWatcher(func(_ []string, _ context.Context, _ func() error) error {
		close(restarted)
		return nil
	})
	select {
	case <-restarted:
		t.Fatal("watcher restarted after decommission")
	default:
	}
}

func TestWatcherReloadUsesMutationLock(t *testing.T) {
	ir := New(Config{
		ID:            "test",
		Authenticator: auth.NewTokenAuthenticator("tok"),
	})
	ir.SetUnlocked()

	reloaded := make(chan struct{}, 1)
	ir.SetReloadFunc(func(identityID string, passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
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
	if err := SaveStoredSetting(root, "default", "user_auto_approve", true); err != nil {
		t.Fatalf("SaveStoredSetting() error = %v", err)
	}
	if err := SaveStoredSetting(root, "default", "lock_on_disconnect", false); err != nil {
		t.Fatalf("SaveStoredSetting() error = %v", err)
	}
	if err := SaveStoredSetting(root, "default", "approval_wait", "10m"); err != nil {
		t.Fatalf("SaveStoredSetting() error = %v", err)
	}

	cfg, err := LoadStoredConfig(root, "default")
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

func TestStoredConfigIsDecommissioned(t *testing.T) {
	root := t.TempDir()
	if err := SaveStoredSetting(root, "default", "decommissioned", true); err != nil {
		t.Fatalf("SaveStoredSetting() error = %v", err)
	}

	cfg, err := LoadStoredConfig(root, "default")
	if err != nil {
		t.Fatalf("LoadStoredConfig() error = %v", err)
	}
	if !cfg.IsDecommissioned() {
		t.Fatal("IsDecommissioned() = false, want true")
	}
}

func TestLoadAuthorizedKeysRejectsMalformedFile(t *testing.T) {
	root := t.TempDir()
	ir := New(Config{
		ID:            "default",
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
