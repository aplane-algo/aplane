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
	if _, err := ir.FollowCommit(genstore.Committed); err != nil {
		t.Fatal(err)
	}
	if ir.KeyCount() != 1 || ir.NodePolicy() != p0 {
		t.Fatalf("setup: %d key(s), policy %p; want the published view", ir.KeyCount(), ir.NodePolicy())
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
