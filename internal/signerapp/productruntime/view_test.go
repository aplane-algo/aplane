// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keyclass"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatepolicy"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

// viewTokens is a token index holding token for the default selector.
func viewTokens(t *testing.T, token string) *sourcetokens.Index {
	t.Helper()
	file, err := sourcetokens.SetToken(nil, sourcetokens.DefaultSelector, "screening", []byte(token), time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Zero()
	return sourcetokens.NewIndex([]*sourcetokens.File{file})
}

// viewKeys is a key scan of selection holding one key.
func viewKeys(selection storepaths.GenPaths) keystore.Contents {
	return keystore.Contents{Selection: &selection, Keys: map[string]apkeys.KeyScanInfo{
		"ADDR": {KeyFile: "keys/ADDR.key", KeyType: "ed25519"},
	}}
}

// viewInService is an unlocked runtime serving a published view: one key,
// a token and policy p0, bound to the generation the store selects.
func viewInService(t *testing.T) (ir *Runtime, bound storepaths.GenPaths, p0 *policyruntime.NodePolicy) {
	t.Helper()
	ir, _, _, _ = unlockedRuntimeForTest(t)
	bound, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	p0 = &policyruntime.NodePolicy{}
	ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
		return &Loaded{Selection: &bound, PolicyVerified: true, Policy: p0, Tokens: viewTokens(t, "tok-0"), Contents: viewKeys(bound)}, nil
	}, ReloadEffects{})
	epoch := ir.stageTables.Epoch()
	if _, err := ir.FollowCommit(genstore.Committed); err != nil {
		t.Fatal(err)
	}
	if ir.KeyCount() != 1 || ir.NodePolicy() != p0 {
		t.Fatalf("setup: %d key(s), policy %p; want the published view", ir.KeyCount(), ir.NodePolicy())
	}
	// The stage tables holding the old inventory close before the new one
	// is published.
	if ir.stageTables.Epoch() == epoch {
		t.Fatal("the publish left the stage tables open")
	}
	return ir, bound, p0
}

// The failure rule, decided by facts, for a reload on a signer with a view
// in service. A role conflict fails the node closed; a store in doubt, a root
// that moved off the bound generation or does not authenticate, and a
// content defect enter recovery's view: bound to what the build found the
// root selecting, or to nothing, with the policy the build verified or none,
// and no keys and no token index. Anything else keeps the view in service.
// The build's own token index is zeroed whatever happens to it.
func TestTheFailureRuleDecidesWhatAFailedBuildLeaves(t *testing.T) {
	transient := errors.New("injected read failure")
	defect := fmt.Errorf("%w: 1 malformed key file(s)", signertemplates.ErrGenerationValidation)
	conflict := fmt.Errorf("key snapshot rejected: %w", keyclass.ErrNodeRoleConflict)
	for _, tc := range []struct {
		name      string
		uncertain bool // an uncertain commit, not one that landed
		moved     bool // the build finds the root selecting another generation
		noRoot    bool // the root does not authenticate
		verified  bool // the build verified a policy
		err       error
		want      string // state, binding, policy, keys, token, fail closed, told
	}{
		{name: "role conflict", err: conflict, verified: true,
			want: "recovery bound=bound policy=new keys=0 token=none failClosed=true told=true"},
		{name: "store in doubt, the build succeeds", uncertain: true, moved: true, verified: true,
			want: "recovery bound=moved policy=new keys=0 token=none failClosed=false told=true"},
		{name: "store in doubt, the build fails", uncertain: true, err: transient,
			want: "recovery bound=bound policy=none keys=0 token=none failClosed=false told=true"},
		{name: "root moved", moved: true, err: transient,
			want: "recovery bound=moved policy=none keys=0 token=none failClosed=false told=true"},
		{name: "root does not authenticate", noRoot: true, err: transient,
			want: "recovery bound=none policy=none keys=0 token=none failClosed=false told=true"},
		{name: "content defect", err: defect, verified: true,
			want: "recovery bound=bound policy=new keys=0 token=none failClosed=false told=true"},
		{name: "anything else", err: transient, verified: true,
			want: "unlocked bound=bound policy=kept keys=1 token=tok-0 failClosed=false told=false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ir, bound, p0 := viewInService(t)
			moved := ir.KeyPaths().GenerationPaths("gen-1800000000-0a0b0c0d")
			p1 := &policyruntime.NodePolicy{}
			built := viewTokens(t, "tok-built")
			failClosed, told := false, false
			ir.SetReloadRecoveryHook(func(error) { told = true })
			ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
				loaded := &Loaded{Tokens: built}
				switch {
				case tc.noRoot:
				case tc.moved:
					loaded.Selection = &moved
				default:
					loaded.Selection = &bound
				}
				if tc.verified {
					loaded.PolicyVerified, loaded.Policy = true, p1
				}
				if tc.err == nil {
					loaded.Contents = viewKeys(*loaded.Selection)
				}
				return loaded, tc.err
			}, ReloadEffects{NodeFailClosed: func(error) { failClosed = true }})

			outcome := genstore.Committed
			if tc.uncertain {
				outcome = genstore.Uncertain
			}
			epoch := ir.stageTables.Epoch()
			_, err := ir.FollowCommit(outcome)
			if !tc.uncertain && !errors.Is(err, tc.err) {
				t.Fatalf("FollowCommit() = %v, want %v", err, tc.err)
			}

			binding := "none"
			if active, err := ir.ActivePaths(); err == nil {
				binding = map[string]string{bound.GenerationID(): "bound", moved.GenerationID(): "moved"}[active.GenerationID()]
			}
			policy := map[*policyruntime.NodePolicy]string{nil: "none", p0: "kept", p1: "new"}[ir.NodePolicy()]
			token, ok := ir.sourceTokens.TokenFor(sourcetokens.DefaultSelector, "screening")
			if !ok {
				token = "none"
			}
			got := fmt.Sprintf("%v bound=%s policy=%s keys=%d token=%s failClosed=%v told=%v",
				ir.GetState(), binding, policy, ir.KeyCount(), token, failClosed, told)
			if got != tc.want {
				t.Fatalf("\n got: %s\nwant: %s", got, tc.want)
			}
			if value, _ := built.TokenFor(sourcetokens.DefaultSelector, "screening"); value == "tok-built" {
				t.Fatal("the build's token index was not zeroed")
			}
			// The stage tables close on any install, so none serves the
			// old inventory; a kept view installs nothing.
			if moved := ir.stageTables.Epoch() != epoch; moved != ir.IsRecovery() {
				t.Fatalf("stage tables invalidated = %v in state %v; want them closed exactly when recovery's view was installed", moved, ir.GetState())
			}
			_, loadErr := ir.SnapshotKeySession().GetKeyWithContext(context.Background(), "ADDR")
			if inRecovery := ir.IsRecovery(); inRecovery != errors.Is(loadErr, keystore.ErrStoreLocked) {
				t.Fatalf("a key load in state %v = %v; want locked exactly in recovery", ir.GetState(), loadErr)
			}
		})
	}
}

// recordingRegistry is a provider registry that holds nothing and records
// every batch registered in it.
type recordingRegistry struct {
	mu      sync.Mutex
	batches [][]string
}

func (r *recordingRegistry) Get(string) lsigprovider.LSigProvider { return nil }
func (r *recordingRegistry) Unregister(string) bool               { return false }
func (r *recordingRegistry) RegisterBatchIfAbsent(batch []lsigprovider.LSigProvider) ([]bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	keyTypes := make([]string, len(batch))
	registered := make([]bool, len(batch))
	for i, p := range batch {
		keyTypes[i], registered[i] = p.KeyType(), true
	}
	r.batches = append(r.batches, keyTypes)
	return registered, nil
}

func (r *recordingRegistry) registered() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.batches
}

// viewProvider keeps the provider contract and nothing else: the contract
// check reads its identity only.
type viewProvider struct {
	lsigprovider.LSigProvider
	keyType string
}

func (p viewProvider) KeyType() string       { return p.keyType }
func (p viewProvider) RoutingFamily() string { return p.keyType }
func (p viewProvider) Version() int          { return 1 }
func (p viewProvider) Category() string      { return lsigprovider.CategoryGenericLsig }

// preparedTemplate writes an enabled generic template record into the bound
// generation and prepares it with a registrar that gives a viewProvider.
func preparedTemplate(t *testing.T, ir *Runtime, bound storepaths.GenPaths, keyType string) signertemplates.PreparedTemplates {
	t.Helper()
	var prepared signertemplates.PreparedTemplates
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		if _, err := templatestore.SaveTemplateActive(bound, []byte("ignored"), keyType, templatestore.TemplateTypeGeneric, kr); err != nil {
			return err
		}
		if err := keytypestate.PutActive(bound, keytypestate.Record{KeyType: keyType, Source: keytypestate.SourceYAMLGeneric, State: keytypestate.StateEnabled}); err != nil {
			return err
		}
		manager := &signertemplates.Manager{
			Paths: ir.KeyPaths(), ActivePaths: bound, Registry: ir.ProviderRegistry(),
			Registrars: []signertemplates.TemplateRegistrar{{
				Name: "generic", Source: keytypestate.SourceYAMLGeneric, TemplateType: templatestore.TemplateTypeGeneric,
				Prepare: func(keyType string, _ []byte) (templatepolicy.PreparedTemplateRegistration, error) {
					return templatepolicy.PreparedTemplateRegistration{Fingerprint: "fp-" + keyType, Provider: viewProvider{keyType: keyType}}, nil
				},
			}},
		}
		var err error
		prepared, err = manager.PrepareKeystoreTemplates(kr)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return prepared
}

// No provider is registered by a build that is not published, whether the
// view in service is kept or recovery's view is published; the publish of
// the whole view registers the batch once.
func TestOnlyAPublishedBuildRegistersItsProviders(t *testing.T) {
	ir, bound, _ := viewInService(t)
	registry := &recordingRegistry{}
	ir.providers = registry
	const keyType = "view-template"
	prepared := preparedTemplate(t, ir, bound, keyType)

	for _, err := range []error{
		errors.New("injected read failure"),                                 // kept
		fmt.Errorf("%w: injected", signertemplates.ErrGenerationValidation), // recovery
	} {
		ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
			return &Loaded{Selection: &bound, Templates: prepared}, err
		}, ReloadEffects{})
		_, _ = ir.FollowCommit(genstore.Committed)
		if got := registry.registered(); len(got) != 0 {
			t.Fatalf("a build that failed with %v registered %v", err, got)
		}
	}
	// A build that succeeds in recovery publishes recovery's view, and
	// registers nothing either.
	ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
		return &Loaded{Selection: &bound, Templates: prepared, Contents: viewKeys(bound)}, nil
	}, ReloadEffects{})
	if _, err := ir.FollowCommit(genstore.Committed); err != nil || !ir.IsRecovery() || ir.KeyCount() != 0 {
		t.Fatalf("FollowCommit() in recovery = %v, state %v, %d key(s); want recovery's view", err, ir.GetState(), ir.KeyCount())
	}
	if got := registry.registered(); len(got) != 0 {
		t.Fatalf("a build published as recovery's view registered %v", got)
	}

	if _, err := ir.Reconcile(func(*crypto.Keyring) error { return nil }, true); err != nil || !ir.IsUnlocked() {
		t.Fatalf("Reconcile() = %v, state %v; want unlocked", err, ir.GetState())
	}
	if got := registry.registered(); len(got) != 1 || len(got[0]) != 1 || got[0][0] != keyType {
		t.Fatalf("the published build registered %v, want one batch of %s", got, keyType)
	}
}

// A lock that lands while a build runs returns only once the build's token
// index is zeroed: the build holds the passphrase lock for reading, which
// the lock's cleanup takes for writing, and the reload publishes or discards
// what it built before it lets go.
func TestALockDuringABuildReturnsOnlyAfterTheBuildIsZeroed(t *testing.T) {
	ir, bound, _ := viewInService(t)
	built := viewTokens(t, "tok-built")
	building, release := make(chan struct{}), make(chan struct{})
	ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
		close(building)
		<-release
		return &Loaded{Selection: &bound, Tokens: built}, errors.New("injected read failure")
	}, ReloadEffects{})
	reloaded := make(chan struct{})
	go func() {
		defer close(reloaded)
		_, _ = ir.FollowCommit(genstore.Committed)
	}()
	<-building
	locked := make(chan struct{})
	go func() {
		defer close(locked)
		ir.Lock()
	}()
	select {
	case <-locked:
		t.Fatal("the lock returned while the build still ran")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-locked
	if value, _ := built.TokenFor(sourcetokens.DefaultSelector, "screening"); value == "tok-built" {
		t.Fatal("the lock returned with the build's token index still in memory")
	}
	<-reloaded
}

// A reload that a lock overtook publishes, and its publish is then cleared
// by the lock's cleanup; it sends no keys-changed notification and does not
// wake the stage table worker, since the lock has told its sessions the
// signer is locked.
func TestAReloadALockOvertookSendsNoNotification(t *testing.T) {
	ir, bound, _ := viewInService(t)
	for len(ir.StageWork()) > 0 {
		<-ir.StageWork()
	}
	notified := 0
	var lockDone sync.WaitGroup
	ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
		lockDone.Add(1)
		go func() {
			defer lockDone.Done()
			ir.Lock()
		}()
		for ir.GetState() != signerruntime.SignerStateLocked {
			time.Sleep(time.Millisecond)
		}
		return &Loaded{Selection: &bound, Contents: viewKeys(bound)}, nil
	}, ReloadEffects{NotifyKeysChanged: func(int) { notified++ }})
	if _, err := ir.FollowCommit(genstore.Committed); err != nil {
		t.Fatal(err)
	}
	lockDone.Wait()
	if notified != 0 {
		t.Fatalf("the overtaken reload sent %d keys-changed notification(s)", notified)
	}
	if len(ir.StageWork()) != 0 {
		t.Fatal("the overtaken reload woke the stage table worker")
	}
	if ir.KeyCount() != 0 {
		t.Fatalf("%d key(s) after the lock, want its cleanup to clear the publish", ir.KeyCount())
	}
}

// A reconcile runs its step, builds, publishes and promotes. A step that
// fails leaves the store in doubt for the explicit reconcile, which enters
// recovery's view; the rescan after a restore, which begins in recovery,
// stays in recovery's view as it was. A lock that overtakes either keeps the
// signer locked, and the reconcile answers that the state changed.
func TestAReconcileEndsAsItsStepAndALockDecide(t *testing.T) {
	stepFailed := errors.New("injected reconcile failure")
	t.Run("an explicit reconcile whose step fails enters recovery", func(t *testing.T) {
		ir, bound, _ := viewInService(t)
		told := false
		ir.SetReloadRecoveryHook(func(cause error) { told = errors.Is(cause, stepFailed) })
		ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
			return &Loaded{Selection: &bound, Contents: viewKeys(bound)}, nil
		}, ReloadEffects{})
		if _, err := ir.Reconcile(func(*crypto.Keyring) error { return stepFailed }, true); !errors.Is(err, stepFailed) {
			t.Fatalf("Reconcile() = %v, want the step's failure", err)
		}
		if !ir.IsRecovery() || ir.KeyCount() != 0 || !told {
			t.Fatalf("state %v, %d key(s), told %v; want recovery's view, the hook told the step's failure", ir.GetState(), ir.KeyCount(), told)
		}
	})
	t.Run("a rescan whose step fails stays in recovery", func(t *testing.T) {
		ir, bound, _ := viewInService(t)
		ir.EnterRecovery(nil)
		built := false
		ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
			built = true
			return &Loaded{Selection: &bound, Contents: viewKeys(bound)}, nil
		}, ReloadEffects{})
		if _, err := ir.Reconcile(func(*crypto.Keyring) error { return stepFailed }, false); !errors.Is(err, stepFailed) || built || !ir.IsRecovery() {
			t.Fatalf("Reconcile() = %v, built %v, state %v; want the step's failure, no build and recovery", err, built, ir.GetState())
		}
	})
	for _, fromRecovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("a lock overtakes, from recovery %v", fromRecovery), func(t *testing.T) {
			ir, bound, _ := viewInService(t)
			if fromRecovery {
				ir.EnterRecovery(nil)
			}
			var lockDone sync.WaitGroup
			ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
				lockDone.Add(1)
				go func() {
					defer lockDone.Done()
					ir.Lock()
				}()
				for ir.GetState() != signerruntime.SignerStateLocked {
					time.Sleep(time.Millisecond)
				}
				return &Loaded{Selection: &bound, Contents: viewKeys(bound)}, nil
			}, ReloadEffects{})
			_, err := ir.Reconcile(func(*crypto.Keyring) error { return nil }, true)
			lockDone.Wait()
			if !errors.Is(err, ErrReconcileStateChanged) || ir.GetState() != signerruntime.SignerStateLocked {
				t.Fatalf("Reconcile() = %v, state %v; want ErrReconcileStateChanged and the lock standing", err, ir.GetState())
			}
		})
	}
}

// A store in doubt on a signer a lock has already moved out of service
// builds nothing and installs nothing: the lock stands. The test holds the
// passphrase lock for reading, as the reload does, so the lock's state moves
// at once and its cleanup waits, with the keyring still open: the window in
// which only the refusal keeps the reload from building and installing
// recovery's view on a locked signer.
func TestAStoreInDoubtOnALockedSignerBuildsNothing(t *testing.T) {
	ir, bound, _ := viewInService(t)
	built := false
	ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
		built = true
		return &Loaded{Selection: &bound}, nil
	}, ReloadEffects{})
	ir.passphraseLock.RLock()
	locked := make(chan struct{})
	go func() {
		defer close(locked)
		ir.Lock()
	}()
	for ir.GetState() != signerruntime.SignerStateLocked {
		time.Sleep(time.Millisecond)
	}
	end := ir.reloadViewLocked(reloadMode{inDoubt: true, cause: errCommitUncertain})
	ir.passphraseLock.RUnlock()
	<-locked
	if built || end.recovery || !errors.Is(end.err, ErrNeitherUnlockedNorRecovery) {
		t.Fatalf("built %v, recovery %v, err %v; want no build, no recovery and the locked refusal", built, end.recovery, end.err)
	}
}

// A runtime with no build wired fails every build closed: a commit that
// landed, or one in doubt, enters recovery with nothing bound.
func TestARuntimeWithNoBuildFailsClosed(t *testing.T) {
	for _, outcome := range []genstore.MintOutcome{genstore.Committed, genstore.Uncertain} {
		ir, _, _ := viewInService(t)
		ir.SetBuildFunc(nil, ReloadEffects{})
		_, _ = ir.FollowCommit(outcome)
		if _, err := ir.ActivePaths(); !ir.IsRecovery() || err == nil {
			t.Fatalf("%v with no build: state %v, binding error %v; want recovery bound to nothing", outcome, ir.GetState(), err)
		}
	}
}

// A watcher reload that finds the store root selecting another generation,
// and then fails, enters recovery bound to that generation: the view in
// service is the superseded one's. A watcher reload once kept the view after
// any failure that was not a content defect.
func TestAWatcherReloadThatFindsTheRootMovedEntersRecoveryBoundToIt(t *testing.T) {
	ir, _, _ := viewInService(t)
	moved := ir.KeyPaths().GenerationPaths("gen-1800000000-0a0b0c0d")
	ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
		return &Loaded{Selection: &moved}, errors.New("injected read failure")
	}, ReloadEffects{})
	reloaded, err := ir.reloadFromWatcher()
	if !reloaded || !errors.Is(err, ErrEnteredRecovery) {
		t.Fatalf("reloadFromWatcher() = %v, %v; want a reload that entered recovery", reloaded, err)
	}
	if active, err := ir.ActivePaths(); !ir.IsRecovery() || err != nil || active.GenerationID() != moved.GenerationID() {
		t.Fatalf("state %v bound to %v (%v), want recovery bound to %s", ir.GetState(), active.GenerationID(), err, moved.GenerationID())
	}
}

// A lock that lands while a reload's build runs, a build that then finds a
// content defect, leaves the signer locked: the entry into recovery is
// refused, recovery's view is not installed, the hook is not told, and the
// error carries no ErrEnteredRecovery, so a caller answers as for a failed
// refresh, not recovery_blocked.
func TestALockDuringAFailingBuildEntersNoRecovery(t *testing.T) {
	ir, bound, _ := viewInService(t)
	told := false
	ir.SetReloadRecoveryHook(func(error) { told = true })
	var lockDone sync.WaitGroup
	ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
		lockDone.Add(1)
		go func() {
			defer lockDone.Done()
			ir.Lock()
		}()
		for ir.GetState() != signerruntime.SignerStateLocked {
			time.Sleep(time.Millisecond)
		}
		return &Loaded{Selection: &bound}, fmt.Errorf("%w: injected", signertemplates.ErrGenerationValidation)
	}, ReloadEffects{})
	_, err := ir.Reload()
	lockDone.Wait()
	if !errors.Is(err, signertemplates.ErrGenerationValidation) || errors.Is(err, ErrEnteredRecovery) {
		t.Fatalf("Reload() = %v, want the defect without ErrEnteredRecovery", err)
	}
	if ir.GetState() != signerruntime.SignerStateLocked || told {
		t.Fatalf("state %v, hook told %v; want the lock standing and the hook not told", ir.GetState(), told)
	}
}

// An unlock from locked whose build fails for a transient reason installs
// nothing: no keyring, no key maps, no token index, and no provider. The
// keyring the attempt opened and its token index are zeroed.
func TestAnUnlockWhoseBuildFailsInstallsNothing(t *testing.T) {
	ir, bound, _ := viewInService(t)
	registry := &recordingRegistry{}
	ir.providers = registry
	prepared := preparedTemplate(t, ir, bound, "unlock-template")
	ir.Lock()
	built := viewTokens(t, "tok-built")
	var opened *crypto.Keyring
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*Loaded, error) {
		opened = kr
		return &Loaded{Selection: &bound, Templates: prepared, Tokens: built, Contents: viewKeys(bound)}, errors.New("injected read failure")
	}, ReloadEffects{})

	if _, err := ir.Unlock([]byte(secondUnlockPassphrase), func(*crypto.Keyring) error { return nil }, nil); err == nil {
		t.Fatal("Unlock() succeeded though its build failed")
	}
	if ir.GetState() != signerruntime.SignerStateLocked || ir.KeyCount() != 0 {
		t.Fatalf("state %v with %d key(s), want locked with none", ir.GetState(), ir.KeyCount())
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err == nil {
		t.Fatal("the failed unlock installed a keyring")
	}
	if got := registry.registered(); len(got) != 0 {
		t.Fatalf("the failed unlock registered %v", got)
	}
	if value, _ := built.TokenFor(sourcetokens.DefaultSelector, "screening"); value == "tok-built" {
		t.Fatal("the build's token index was not zeroed")
	}
	if opened == nil || opened.CurrentTerm() != 0 {
		t.Fatal("the keyring the attempt opened was not zeroed")
	}
}

// An unlock begun in recovery whose build fails for a transient reason
// leaves recovery its own keyring and binding, for the reconcile, restore and
// rollback it needs, and zeroes the keyring the attempt opened.
func TestAnUnlockInRecoveryWhoseBuildFailsKeepsRecoverysKeyring(t *testing.T) {
	ir, bound, _ := viewInService(t)
	ir.EnterRecovery(nil)
	var recoverys *crypto.Keyring
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error { recoverys = kr; return nil }); err != nil {
		t.Fatal(err)
	}
	var opened *crypto.Keyring
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*Loaded, error) {
		opened = kr
		return &Loaded{Selection: &bound}, errors.New("injected read failure")
	}, ReloadEffects{})

	if _, err := ir.Unlock([]byte(secondUnlockPassphrase), func(*crypto.Keyring) error { return nil }, nil); err == nil {
		t.Fatal("Unlock() succeeded though its build failed")
	}
	if !ir.IsRecovery() {
		t.Fatalf("state %v, want recovery", ir.GetState())
	}
	var current *crypto.Keyring
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error { current = kr; return nil }); err != nil || current != recoverys {
		t.Fatalf("recovery's keyring after the failed unlock = %p (%v), want its own %p", current, err, recoverys)
	}
	if active, err := ir.ActivePaths(); err != nil || active.GenerationID() != bound.GenerationID() {
		t.Fatalf("binding after the failed unlock = %v, %v; want %s", active.GenerationID(), err, bound.GenerationID())
	}
	if opened == nil || opened == recoverys || opened.CurrentTerm() != 0 {
		t.Fatal("the keyring the attempt opened was not zeroed")
	}
}

// An unlock that loses to a lock landing during its build publishes, and
// its fence then locks and clears: no keyring, key maps or token index from
// the attempt remain. Its policy and the providers it registered remain, as
// a policy does after any lock.
func TestAnUnlockThatLosesToALockLeavesNothingButItsPolicy(t *testing.T) {
	ir, bound, _ := viewInService(t)
	registry := &recordingRegistry{}
	ir.providers = registry
	prepared := preparedTemplate(t, ir, bound, "loser-template")
	ir.Lock()
	policy := &policyruntime.NodePolicy{}
	var lockDone sync.WaitGroup
	ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
		lockDone.Add(1)
		go func() {
			defer lockDone.Done()
			ir.Lock()
		}()
		// The lock lands whole: its cleanup has nothing to wait for, since
		// the build holds no passphrase lock.
		lockDone.Wait()
		return &Loaded{Selection: &bound, PolicyVerified: true, Policy: policy, Templates: prepared,
			Tokens: viewTokens(t, "tok-loser"), Contents: viewKeys(bound)}, nil
	}, ReloadEffects{})

	if _, err := ir.Unlock([]byte(secondUnlockPassphrase), func(*crypto.Keyring) error { return nil }, nil); !errors.Is(err, signerruntime.ErrLockedDuringUnlock) {
		t.Fatalf("Unlock() = %v, want %v", err, signerruntime.ErrLockedDuringUnlock)
	}
	if ir.GetState() != signerruntime.SignerStateLocked || ir.KeyCount() != 0 {
		t.Fatalf("state %v with %d key(s), want locked with none", ir.GetState(), ir.KeyCount())
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err == nil {
		t.Fatal("the losing unlock left a keyring")
	}
	if _, ok := ir.sourceTokens.TokenFor(sourcetokens.DefaultSelector, "screening"); ok {
		t.Fatal("the losing unlock left a token index")
	}
	if ir.NodePolicy() != policy {
		t.Fatal("the losing unlock's policy is gone; a lock leaves the policy")
	}
	if got := registry.registered(); len(got) != 1 {
		t.Fatalf("the losing unlock registered %v, want its one batch", got)
	}
}

// An in-doubt recovery entry (uncertain commit or explicit reconcile whose
// store step failed) must cancel active key uses and withdraw pending
// approvals when the state moves to recovery, before the recovery build runs.
func TestInDoubtRecoveryCancelsKeyUsesAndApprovalsBeforeItsBuild(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(ir *Runtime)
	}{
		{
			name: "uncertain commit",
			run: func(ir *Runtime) {
				_, _ = ir.FollowCommit(genstore.Uncertain)
			},
		},
		{
			name: "explicit reconcile failing step",
			run: func(ir *Runtime) {
				_, _ = ir.Reconcile(func(*crypto.Keyring) error { return errors.New("step failed") }, true)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ir, bound, _ := viewInService(t)
			shown := make(chan struct{}, 1)
			ir.SetApprovalCoordinator(signerapproval.New(
				func() bool { return true },
				func(*signerapproval.SignRequest) bool { shown <- struct{}{}; return true },
				func(*signerapproval.SignRequestCanceled) bool { return true },
			))
			useCtx, releaseUse := ir.KeyUseContext(context.Background())
			defer releaseUse()
			if useCtx.Err() != nil {
				t.Fatalf("setup: key use already canceled: %v", useCtx.Err())
			}

			reqCtx, finishReq := ir.BeginSigningRequest(context.Background(), "sign-in-doubt")
			defer finishReq()
			approvalErrCh := make(chan error, 1)
			go func() {
				_, err := ir.RequestSigningApprovalPrompt(reqCtx, signerapproval.Prompt{
					RequestID: "sign-in-doubt", Address: "A", TxnSender: "A", Description: "d",
				}, time.Minute)
				approvalErrCh <- err
			}()
			<-shown

			buildEntered := make(chan struct{})
			releaseBuild := make(chan struct{})
			ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
				close(buildEntered)
				<-releaseBuild
				return &Loaded{Selection: &bound}, nil
			}, ReloadEffects{})

			done := make(chan struct{})
			go func() {
				defer close(done)
				tc.run(ir)
			}()

			select {
			case <-buildEntered:
			case <-time.After(3 * time.Second):
				t.Fatal("in-doubt build did not start")
			}

			// While the build is still blocked, both the held key use and the
			// pending approval must already be ended.
			select {
			case <-useCtx.Done():
			case <-time.After(time.Second):
				close(releaseBuild)
				t.Fatal("key use stayed live while in-doubt build ran")
			}
			select {
			case err := <-approvalErrCh:
				if !errors.Is(err, signerapproval.ErrSessionEnded) {
					close(releaseBuild)
					t.Fatalf("approval error = %v, want ErrSessionEnded", err)
				}
			case <-time.After(time.Second):
				close(releaseBuild)
				t.Fatal("pending approval stayed up while in-doubt build ran")
			}

			close(releaseBuild)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("in-doubt recovery did not finish")
			}
			if !ir.IsRecovery() {
				t.Fatalf("state = %v, want recovery", ir.GetState())
			}
		})
	}
}

// A lock that lands during an in-doubt build stands: afterReload must not
// invoke the recovery hook, and the signer ends locked with no keyring, no
// keys, and no source token index.
func TestLockDuringInDoubtBuildSuppressesRecoveryHookAndLeavesSignerLocked(t *testing.T) {
	ir, bound, _ := viewInService(t)
	told := false
	ir.SetReloadRecoveryHook(func(error) { told = true })

	var lockDone sync.WaitGroup
	ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
		lockDone.Add(1)
		go func() {
			defer lockDone.Done()
			ir.Lock()
		}()
		for ir.GetState() != signerruntime.SignerStateLocked {
			time.Sleep(time.Millisecond)
		}
		return &Loaded{
			Selection:      &bound,
			PolicyVerified: true,
			Policy:         &policyruntime.NodePolicy{},
			Tokens:         viewTokens(t, "tok-indoubt"),
			Contents:       viewKeys(bound),
		}, nil
	}, ReloadEffects{})

	_, _ = ir.FollowCommit(genstore.Uncertain)
	lockDone.Wait()

	if told {
		t.Fatal("recovery hook fired even though a lock overtook the in-doubt build")
	}
	if ir.GetState() != signerruntime.SignerStateLocked || ir.KeyCount() != 0 {
		t.Fatalf("state %v with %d key(s), want locked with 0", ir.GetState(), ir.KeyCount())
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err == nil {
		t.Fatal("locked signer still holds a keyring")
	}
	if _, ok := ir.sourceTokens.TokenFor(sourcetokens.DefaultSelector, "screening"); ok {
		t.Fatal("locked signer still holds a source token index")
	}
}

// A lock that overtakes Reconcile during its store step — whether the step
// succeeds or fails, and whether the reconcile began unlocked or in recovery
// — must return ErrReconcileStateChanged with the signer locked.
func TestReconcileOvertakenByLockDuringStepReturnsStateChanged(t *testing.T) {
	for _, startRecovery := range []bool{false, true} {
		for _, stepErr := range []error{nil, errors.New("step failed after lock")} {
			for _, explicit := range []bool{true, false} {
				if !startRecovery && !explicit {
					continue
				}
				name := fmt.Sprintf("fromRecovery=%v/stepErr=%v/explicit=%v", startRecovery, stepErr != nil, explicit)
				t.Run(name, func(t *testing.T) {
					ir, _, _ := viewInService(t)
					if startRecovery {
						ir.EnterRecovery(nil)
					}
					var lockDone sync.WaitGroup
					_, err := ir.Reconcile(func(*crypto.Keyring) error {
						lockDone.Add(1)
						go func() {
							defer lockDone.Done()
							ir.Lock()
						}()
						for ir.GetState() != signerruntime.SignerStateLocked {
							time.Sleep(time.Millisecond)
						}
						return stepErr
					}, explicit)
					lockDone.Wait()

					if !errors.Is(err, ErrReconcileStateChanged) {
						t.Fatalf("Reconcile() error = %v, want %v", err, ErrReconcileStateChanged)
					}
					if ir.GetState() != signerruntime.SignerStateLocked {
						t.Fatalf("state = %v, want locked", ir.GetState())
					}
				})
			}
		}
	}
}

// On a failing reconcile build, Reconcile maps to ErrReconcileStateChanged
// only when a lock overtook the reconcile; an ordinary build failure stays a
// credential-reload error with the signer in recovery.
func TestReconcileBuildFailureMapsOnlyLockedToStateChanged(t *testing.T) {
	t.Run("lock during failing build returns ErrReconcileStateChanged", func(t *testing.T) {
		ir, bound, _ := viewInService(t)
		var lockDone sync.WaitGroup
		ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
			lockDone.Add(1)
			go func() {
				defer lockDone.Done()
				ir.Lock()
			}()
			for ir.GetState() != signerruntime.SignerStateLocked {
				time.Sleep(time.Millisecond)
			}
			return &Loaded{Selection: &bound}, errors.New("build failed after lock")
		}, ReloadEffects{})

		_, err := ir.Reconcile(func(*crypto.Keyring) error { return nil }, true)
		lockDone.Wait()
		if !errors.Is(err, ErrReconcileStateChanged) {
			t.Fatalf("Reconcile() error = %v, want %v", err, ErrReconcileStateChanged)
		}
		if ir.GetState() != signerruntime.SignerStateLocked {
			t.Fatalf("state = %v, want locked", ir.GetState())
		}
	})

	t.Run("ordinary failing build stays recovery error", func(t *testing.T) {
		ir, bound, _ := viewInService(t)
		buildErr := errors.New("injected build failure")
		ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
			return &Loaded{Selection: &bound}, buildErr
		}, ReloadEffects{})

		_, err := ir.Reconcile(func(*crypto.Keyring) error { return nil }, true)
		if err == nil || errors.Is(err, ErrReconcileStateChanged) || !errors.Is(err, buildErr) {
			t.Fatalf("Reconcile() error = %v, want wrapped %v (not ErrReconcileStateChanged)", err, buildErr)
		}
		if !ir.IsRecovery() {
			t.Fatalf("state = %v, want recovery", ir.GetState())
		}
	})
}
