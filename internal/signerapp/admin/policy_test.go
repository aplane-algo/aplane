// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"errors"
	"fmt"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/asasetstore"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig/clientreg"
)

const (
	adminPolicyPassphrase = "admin-policy-test-passphrase"
	adminPolicyKeyA       = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
	adminPolicyKeyB       = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// setupPolicyAdmin returns an unlocked admin service over an initialized
// store whose runtime reload reloads policy from the selected generation.
func setupPolicyAdmin(t *testing.T, role noderole.Role) (Service, *productruntime.Runtime) {
	t.Helper()
	svc, ir, _ := setupUnpublishedPolicyAdmin(t, role)
	ir.SetUnlocked()
	return svc, ir
}

// policyReload is the runtime reload setupUnpublishedPolicyAdmin installs.
type policyReload = func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error)

// setupUnpublishedPolicyAdmin is setupPolicyAdmin with the keyring open and
// policy loaded but the runtime not yet published unlocked, as an unlock in
// flight leaves it. It also returns the reload it installed.
func setupUnpublishedPolicyAdmin(t *testing.T, role noderole.Role) (Service, *productruntime.Runtime, policyReload) {
	t.Helper()
	clientreg.RegisterClient()
	root := t.TempDir()
	paths := storepaths.NewPaths(root)
	if _, err := storeinit.Initialize([]byte(adminPolicyPassphrase), storeinit.Options{ValidateCandidate: storevalidate.FirstGeneration, DataDir: root, Paths: paths, Role: role}); err != nil {
		t.Fatal(err)
	}
	cfg := serverconfig.DefaultServerConfig()
	deps := &fakeDeps{dataDir: root, config: &cfg, keyPaths: paths}
	ir := productruntime.New(productruntime.Config{
		KeyStore: keystore.NewAtomicFileKeyStoreForPaths(paths),
		KeyPaths: paths,
		NodeRole: role,
	})
	if err := ir.KeyStore().Unlock([]byte(adminPolicyPassphrase)); err != nil {
		t.Fatal(err)
	}
	reload := func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return &signertemplates.ReloadReport{}, ir.KeyStore().WithKeyring(func(kr *crypto.Keyring) error {
			active, err := genstore.ResolveStoreRootWithKeyring(paths, kr)
			if err != nil {
				return err
			}
			np, err := policyruntime.Load(role, &cfg, active, kr)
			if err != nil {
				return err
			}
			set, err := asasetstore.Load(active, kr)
			if err != nil {
				return err
			}
			ir.SetVerifiedPolicyState(np, set, nil)
			return nil
		})
	}
	ir.SetReloadFunc(reload)
	if _, err := reload(nil, nil); err != nil {
		t.Fatal(err)
	}
	return Service{Deps: deps, Runtime: ir, ASAChain: builtinNetworksChain{}}, ir, reload
}

func signerPolicyDoc(maxFee string) string {
	return policytest.MustDocument(noderole.RoleSigner, policy.DefaultKey, fmt.Sprintf(`{"max_fee_microalgos":%q}`, maxFee))
}

func cosignerPolicyDoc(key string) string {
	return policytest.MustDocument(noderole.RoleCosigner, key, "")
}

// runtimePolicy returns the policy the runtime enforces for selector.
func runtimePolicy(ir *productruntime.Runtime, selector string) *policy.Config {
	return ir.NodePolicy().PolicyFor(selector)
}

func currentGeneration(t *testing.T, svc Service, ir *productruntime.Runtime) string {
	t.Helper()
	var id string
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		active, err := genstore.ResolveStoreRootWithKeyring(svc.Deps.KeyPaths(), kr)
		id = active.GenerationID()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSignerPolicyApplyMintsGenerationAndReloads(t *testing.T) {
	svc, ir := setupPolicyAdmin(t, noderole.RoleSigner)
	view := svc.GetPolicy()
	embedded := policytest.EmbeddedDefault(t, noderole.RoleSigner)
	if !view.Success || view.NodeRole != "signer" || len(view.Documents) != 1 ||
		view.Documents[0].Key != policy.DefaultKey || view.Documents[0].Size != len(embedded) ||
		svc.GetPolicyDocumentAt(adminproto.GetPolicyDocumentRequest{Key: policy.DefaultKey}).Document != embedded {
		t.Fatalf("GetPolicy() = %+v", view)
	}
	before := currentGeneration(t, svc, ir)

	result := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: signerPolicyDoc("2000")}},
		ExpectedPolicySetSHA256: view.PolicySetSHA256,
		ExpectedSnapshotSHA256:  svc.GetPolicyContext().SnapshotSHA256,
	})
	if !result.Success || result.Policy == nil || result.Policy.GenerationID == "" {
		t.Fatalf("ApplyPolicy() = %+v", result)
	}
	if after := currentGeneration(t, svc, ir); after == before || after != result.Policy.GenerationID {
		t.Fatalf("generation %s -> %s, result %s", before, after, result.Policy.GenerationID)
	}
	// The audit evidence is the commit's own.
	if !result.Changed || result.GenerationID != result.Policy.GenerationID ||
		result.BasePolicySetSHA256 != view.PolicySetSHA256 || result.PolicySetSHA256 != result.Policy.PolicySetSHA256 {
		t.Fatalf("apply evidence = %+v", result)
	}
	if got := runtimePolicy(ir, ""); got == nil || got.MaxFeeMicroAlgos != 2000 {
		t.Fatalf("runtime policy after apply = %#v", got)
	}
	if again := svc.GetPolicy(); svc.GetPolicyDocumentAt(adminproto.GetPolicyDocumentRequest{Key: policy.DefaultKey}).Document != signerPolicyDoc("2000") || again.PolicySetSHA256 == view.PolicySetSHA256 {
		t.Fatalf("GetPolicy() after apply = %+v", again)
	}

	unchanged := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: signerPolicyDoc("2000")}},
		ExpectedPolicySetSHA256: result.Policy.PolicySetSHA256,
		ExpectedSnapshotSHA256:  svc.GetPolicyContext().SnapshotSHA256,
	})
	if !unchanged.Success || unchanged.Policy.GenerationID != "" || currentGeneration(t, svc, ir) != result.Policy.GenerationID {
		t.Fatalf("identical apply = %+v, want no new generation", unchanged)
	}
	if unchanged.Changed || unchanged.GenerationID != "" || unchanged.BasePolicySetSHA256 != unchanged.PolicySetSHA256 || unchanged.PolicySetSHA256 == "" {
		t.Fatalf("no-op evidence = %+v", unchanged)
	}
}

// Concurrent applies against one snapshot: one commits and carries its own
// generation; the rest are refused and carry none, never another's.
func TestConcurrentPolicyAppliesCarryTheirOwnEvidence(t *testing.T) {
	svc, ir := setupPolicyAdmin(t, noderole.RoleSigner)
	view := svc.GetPolicy()
	snapshot := svc.GetPolicyContext().SnapshotSHA256
	results := make([]adminproto.ApplyPolicyResult, 6)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
				Documents:               []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: signerPolicyDoc(fmt.Sprintf("%d", 2000+i))}},
				ExpectedPolicySetSHA256: view.PolicySetSHA256,
				ExpectedSnapshotSHA256:  snapshot,
			})
		}(i)
	}
	wg.Wait()
	winners := 0
	for i, r := range results {
		if r.Success {
			winners++
			if r.GenerationID != currentGeneration(t, svc, ir) || svc.GetPolicy().PolicySetSHA256 != r.PolicySetSHA256 ||
				svc.GetPolicyDocumentAt(adminproto.GetPolicyDocumentRequest{Key: policy.DefaultKey}).Document != signerPolicyDoc(fmt.Sprintf("%d", 2000+i)) {
				t.Fatalf("the winner's evidence is not its own commit: %+v", r)
			}
			continue
		}
		if r.Code != "policy_snapshot_changed" || r.GenerationID != "" || r.Changed {
			t.Fatalf("a refused apply = %+v", r)
		}
	}
	if winners != 1 {
		t.Fatalf("%d applies committed against one snapshot", winners)
	}
}

func TestPolicyApplyRejectsStaleInvalidAndMalformedRequests(t *testing.T) {
	svc, ir := setupPolicyAdmin(t, noderole.RoleSigner)
	view := svc.GetPolicy()
	snapshot := svc.GetPolicyContext().SnapshotSHA256
	before := currentGeneration(t, svc, ir)
	for _, tc := range []struct {
		name string
		req  adminproto.ApplyPolicyRequest
		code string
	}{
		{"no concurrency base", adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: signerPolicyDoc("1")}}}, "expected_policy_set_sha256_required"},
		{"stale base", adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: signerPolicyDoc("1")}}, ExpectedPolicySetSHA256: strings.Repeat("0", 64), ExpectedSnapshotSHA256: snapshot}, "policy_snapshot_changed"},
		{"no reviewed snapshot", adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: signerPolicyDoc("1")}}, ExpectedPolicySetSHA256: view.PolicySetSHA256}, "expected_snapshot_sha256_required"},
		{"stale snapshot", adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: signerPolicyDoc("1")}}, ExpectedPolicySetSHA256: view.PolicySetSHA256, ExpectedSnapshotSHA256: strings.Repeat("0", 64)}, "policy_snapshot_changed"},
		{"invalid document", adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: policytest.Signer(t, policy.DefaultKey, `{"max_fee_microalgos":1}`)}}, ExpectedPolicySetSHA256: view.PolicySetSHA256, ExpectedSnapshotSHA256: snapshot}, "policy_validation_failed"},
		{"witness key on a signer node", adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: adminPolicyKeyA, Document: policytest.Signer(t, adminPolicyKeyA, "")}}, ExpectedPolicySetSHA256: view.PolicySetSHA256, ExpectedSnapshotSHA256: snapshot}, "policy_validation_failed"},
		{"unkeyed document", adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Document: signerPolicyDoc("1")}}, ExpectedPolicySetSHA256: view.PolicySetSHA256, ExpectedSnapshotSHA256: snapshot}, "invalid_policy_request"},
		{"default removal", adminproto.ApplyPolicyRequest{Remove: []string{policy.DefaultKey}, ExpectedPolicySetSHA256: view.PolicySetSHA256, ExpectedSnapshotSHA256: snapshot}, "invalid_policy_request"},
		{"removal of a key on the default", adminproto.ApplyPolicyRequest{Remove: []string{adminPolicyKeyA}, ExpectedPolicySetSHA256: view.PolicySetSHA256, ExpectedSnapshotSHA256: snapshot}, "invalid_policy_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.ApplyPolicy(tc.req)
			if result.Success || result.Code != tc.code {
				t.Fatalf("ApplyPolicy() = %+v, want code %s", result, tc.code)
			}
			if tc.code == "policy_validation_failed" && len(result.Errors) != 1 {
				t.Fatalf("problems = %+v, want one", result.Errors)
			}
		})
	}
	if currentGeneration(t, svc, ir) != before || svc.GetPolicy().PolicySetSHA256 != view.PolicySetSHA256 {
		t.Fatal("a rejected apply changed the store")
	}
}

func TestCosignerPolicyApplyAddsReplacesAndRemovesPerKey(t *testing.T) {
	svc, ir := setupPolicyAdmin(t, noderole.RoleCosigner)
	ir.PublishSnapshot(map[string]string{adminPolicyKeyA: "keys/" + adminPolicyKeyA + ".cos"}, map[string]string{})
	view := svc.GetPolicy()
	if !view.Success || view.NodeRole != "cosigner" || len(view.Documents) != 1 || view.Documents[0].Key != policy.DefaultKey ||
		len(view.Keys) != 1 || view.Keys[0].Status != adminproto.PolicyKeyDefault {
		t.Fatalf("initial GetPolicy() = %+v", view)
	}
	if got := runtimePolicy(ir, adminPolicyKeyA); got == nil || got.VerdictForType("pay") != policy.TransactionTypeReject {
		t.Fatalf("a key without its own policy must follow the deny-all cosigner default: %+v", got)
	}

	check := svc.CheckPolicy(adminproto.CheckPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: adminPolicyKeyB, Document: cosignerPolicyDoc(adminPolicyKeyB)}}})
	if !check.Success || !check.Valid || len(check.Warnings) != 1 || check.Warnings[0].Key != adminPolicyKeyB {
		t.Fatalf("CheckPolicy() = %+v, want valid with a key-not-held warning", check)
	}

	result := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents: []adminproto.PolicyDocument{
			{Key: adminPolicyKeyA, Document: cosignerPolicyDoc(adminPolicyKeyA)},
			{Key: adminPolicyKeyB, Document: cosignerPolicyDoc(adminPolicyKeyB)},
		},
		ExpectedPolicySetSHA256: view.PolicySetSHA256,
		ExpectedSnapshotSHA256:  svc.GetPolicyContext().SnapshotSHA256,
	})
	if !result.Success {
		t.Fatalf("ApplyPolicy(add) = %+v", result)
	}
	status := map[string]string{}
	for _, st := range result.Policy.Keys {
		status[st.Key] = st.Status
	}
	if status[adminPolicyKeyA] != adminproto.PolicyKeyOwn || status[adminPolicyKeyB] != adminproto.PolicyKeyNotHeld {
		t.Fatalf("key status = %v", status)
	}
	if np := ir.NodePolicy(); len(np.Keys) != 2 || np.PolicyFor(adminPolicyKeyA).VerdictForType("pay") != policy.TransactionTypeAllow {
		t.Fatalf("runtime key policies = %+v, want 2 with A's own document in force", np.Keys)
	}

	removed := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{Remove: []string{adminPolicyKeyB},
		ExpectedPolicySetSHA256: result.Policy.PolicySetSHA256, ExpectedSnapshotSHA256: svc.GetPolicyContext().SnapshotSHA256})
	if !removed.Success || len(removed.Policy.Documents) != 2 || removed.Policy.Documents[1].Key != adminPolicyKeyA {
		t.Fatalf("ApplyPolicy(remove) = %+v", removed)
	}
	if ir.NodePolicy().HasOwn(adminPolicyKeyB) {
		t.Fatal("removed policy is still enforced")
	}
	if doc := svc.GetPolicyDocumentAt(adminproto.GetPolicyDocumentRequest{Key: adminPolicyKeyA}); !doc.Success || doc.Document != cosignerPolicyDoc(adminPolicyKeyA) {
		t.Fatalf("GetPolicyDocument(A) = %+v", doc)
	}
	for _, key := range []string{adminPolicyKeyB, ""} {
		if doc := svc.GetPolicyDocumentAt(adminproto.GetPolicyDocumentRequest{Key: key}); doc.Success || doc.Code != "policy_document_not_found" {
			t.Fatalf("GetPolicyDocument(%q) = %+v, want policy_document_not_found", key, doc)
		}
	}

	for _, tc := range []struct {
		name string
		req  adminproto.ApplyPolicyRequest
	}{
		{"remove absent", adminproto.ApplyPolicyRequest{Remove: []string{adminPolicyKeyB}}},
		{"unkeyed document", adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Document: cosignerPolicyDoc(adminPolicyKeyA)}}}},
		{"replace and remove", adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: adminPolicyKeyA, Document: cosignerPolicyDoc(adminPolicyKeyA)}}, Remove: []string{adminPolicyKeyA}}},
		{"empty change", adminproto.ApplyPolicyRequest{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.req.ExpectedPolicySetSHA256 = removed.Policy.PolicySetSHA256
			tc.req.ExpectedSnapshotSHA256 = svc.GetPolicyContext().SnapshotSHA256
			if got := svc.ApplyPolicy(tc.req); got.Success || got.Code != "invalid_policy_request" {
				t.Fatalf("ApplyPolicy() = %+v, want invalid_policy_request", got)
			}
		})
	}

	mismatch := svc.CheckPolicy(adminproto.CheckPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: adminPolicyKeyB, Document: cosignerPolicyDoc(adminPolicyKeyA)}}})
	if !mismatch.Success || mismatch.Valid || len(mismatch.Errors) != 1 || mismatch.Errors[0].Key != adminPolicyKeyB || mismatch.Errors[0].Pointer != "/key" {
		t.Fatalf("CheckPolicy(key mismatch) = %+v", mismatch)
	}
}

func TestPolicyRequestsFailClosedWithoutLoadedPolicy(t *testing.T) {
	svc, ir := setupPolicyAdmin(t, noderole.RoleSigner)
	ir.SetVerifiedPolicyState(nil, nil, nil)
	if view := svc.GetPolicy(); view.Success || view.Code != "policy_unavailable" {
		t.Fatalf("GetPolicy() = %+v", view)
	}
	if check := svc.CheckPolicy(adminproto.CheckPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: signerPolicyDoc("1")}}}); check.Success || check.Code != "policy_unavailable" {
		t.Fatalf("CheckPolicy() = %+v", check)
	}
}

// recordingMutationDeps reports whether the runtime was already in recovery
// when the store mutation lock was released.
type recordingMutationDeps struct {
	Deps
	ir                *productruntime.Runtime
	recoveryAtRelease bool
}

func (d *recordingMutationDeps) WithStoreMutation(fn func() error) error {
	return d.Deps.WithStoreMutation(func() error {
		err := fn()
		d.recoveryAtRelease = d.ir.IsRecovery()
		return err
	})
}

// A policy commit whose reload fails must enter recovery before the mutation
// lock is released: until then the runtime may still serve the superseded
// generation, and a key write taking the lock would land in it.
func TestPolicyApplyEntersRecoveryBeforeReleasingTheLock(t *testing.T) {
	svc, ir := setupPolicyAdmin(t, noderole.RoleSigner)
	view := svc.GetPolicy()
	ir.SetReloadFunc(func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, fmt.Errorf("reload failed")
	})
	deps := &recordingMutationDeps{Deps: svc.Deps, ir: ir}
	svc.Deps = deps

	result := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: signerPolicyDoc("2000")}},
		ExpectedPolicySetSHA256: view.PolicySetSHA256,
		ExpectedSnapshotSHA256:  svc.GetPolicyContext().SnapshotSHA256,
	})
	if result.Success || !result.CommitUncertain || result.Code != "policy_reload_failed" {
		t.Fatalf("ApplyPolicy() = %+v, want an uncertain reload failure", result)
	}
	if result.GenerationID == "" || result.GenerationID != currentGeneration(t, svc, ir) || result.BasePolicySetSHA256 != view.PolicySetSHA256 {
		t.Fatalf("a reload failure lost its commit evidence: %+v", result)
	}
	if !deps.recoveryAtRelease {
		t.Fatal("runtime entered recovery only after the store mutation lock was released")
	}
	if !ir.IsRecovery() {
		t.Fatal("runtime is not in recovery after a failed post-commit reload")
	}

	// Recovery admits only the operations that resolve the store; a further
	// apply must not mint another generation on top of it.
	stuck := currentGeneration(t, svc, ir)
	again := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: signerPolicyDoc("3000")}},
		ExpectedPolicySetSHA256: view.PolicySetSHA256,
		ExpectedSnapshotSHA256:  svc.GetPolicyContext().SnapshotSHA256,
	})
	if again.Success || again.Code != protocol.ResultCodeRecoveryBlocked || again.CommitUncertain {
		t.Fatalf("ApplyPolicy() in recovery = %+v, want recovery_blocked", again)
	}
	if after := currentGeneration(t, svc, ir); after != stuck {
		t.Fatalf("apply in recovery moved the generation %s -> %s", stuck, after)
	}
}

// A policy commit whose durability is unknown may already be the visible
// root. The runtime must rebind to it before the lock is released, as restore
// does, so the keystore never trails the store while recovery blocks signing.
func TestPolicyApplyUncertainCommitReloadsAndEntersRecovery(t *testing.T) {
	svc, ir := setupPolicyAdmin(t, noderole.RoleSigner)
	view := svc.GetPolicy()
	before := currentGeneration(t, svc, ir)

	identityDir := svc.Deps.KeyPaths().ProductDir()
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == identityDir {
			return errors.New("simulated identity-directory sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()
	result := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: signerPolicyDoc("2000")}},
		ExpectedPolicySetSHA256: view.PolicySetSHA256,
		ExpectedSnapshotSHA256:  svc.GetPolicyContext().SnapshotSHA256,
	})
	fsutil.TestHook = nil

	if result.Success || !result.CommitUncertain || result.Code != "policy_commit_uncertain" {
		t.Fatalf("ApplyPolicy(durability unknown) = %+v", result)
	}
	if result.GenerationID == "" || result.GenerationID != currentGeneration(t, svc, ir) || result.Changed {
		t.Fatalf("an uncertain commit lost its generation: %+v", result)
	}
	if !ir.IsRecovery() {
		t.Fatal("runtime is not in recovery after an uncertain policy commit")
	}
	if after := currentGeneration(t, svc, ir); after == before {
		t.Fatalf("uncertain commit did not publish a new root (still %s)", before)
	}
	if got := svc.GetPolicyDocumentAt(adminproto.GetPolicyDocumentRequest{Key: policy.DefaultKey}).Document; got != signerPolicyDoc("2000") {
		t.Fatalf("runtime policy after uncertain commit = %q, want the committed document", got)
	}
}

// An unlock on another connection opens the keyring before it publishes the
// runtime unlocked, and runs outside the store mutation lock. A policy apply
// in between once committed, met a locked signer when its reload failed, on
// which SetRecovery does nothing, and the unlock then published unlocked over
// a generation the runtime had not followed. The apply is refused instead:
// it needs an unlocked signer, checked under the lock.
func TestPolicyApplyDuringAnUnlockInFlightIsRefused(t *testing.T) {
	svc, ir, _ := setupUnpublishedPolicyAdmin(t, noderole.RoleSigner)
	view := svc.GetPolicy()
	snapshot := svc.GetPolicyContext().SnapshotSHA256
	before := currentGeneration(t, svc, ir)
	if ir.IsUnlocked() || ir.IsRecovery() {
		t.Fatalf("setup: state = %s, want locked with the keyring open", ir.GetState())
	}
	ir.SetReloadFunc(func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, fmt.Errorf("reload failed")
	})

	result := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: signerPolicyDoc("2000")}},
		ExpectedPolicySetSHA256: view.PolicySetSHA256,
		ExpectedSnapshotSHA256:  snapshot,
	})
	ir.SetUnlocked() // the unlock in flight publishes

	if after := currentGeneration(t, svc, ir); after != before && ir.IsUnlocked() {
		t.Fatalf("the signer ended unlocked over generation %s, which its reload did not follow (apply answered %s)", after, result.Code)
	}
	const want = "identity is locked; unlock the signer before applying policy"
	if result.Success || result.Code != "identity_locked" || result.Error != want || result.CommitUncertain || result.GenerationID != "" {
		t.Fatalf("ApplyPolicy() during an unlock = %+v, want identity_locked: %s", result, want)
	}
	if after := currentGeneration(t, svc, ir); after != before {
		t.Fatalf("an apply during an unlock committed %s -> %s", before, after)
	}
}

// secondUnlockInFlight starts an unlock of the unlocked signer, as a second
// admin connection does, and holds it in its reload (the one with a
// passphrase) until release is called. The unlock has read the session
// generations by then, and it holds passphraseLock, so a mutation's reload
// waits for it. It returns the unlock's outcome once it ends.
func secondUnlockInFlight(t *testing.T, ir *productruntime.Runtime, reload policyReload) (release func(), outcome func() string) {
	t.Helper()
	entered, held := make(chan struct{}), make(chan struct{})
	ir.SetReloadFunc(func(passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		if passphrase != nil {
			close(entered)
			<-held
		}
		return reload(passphrase, session)
	})
	done := make(chan string, 1)
	go func() {
		ok, _, msg := ir.TryUnlock([]byte(adminPolicyPassphrase), nil)
		if ok {
			msg = "published unlocked"
		}
		done <- msg
	}()
	<-entered
	return func() { close(held) }, func() string { return <-done }
}

// awaitRecovery waits for a mutation running beside the test to enter
// recovery.
func awaitRecovery(t *testing.T, ir *productruntime.Runtime) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ir.IsRecovery() {
		if time.Now().After(deadline) {
			t.Fatalf("the mutation never entered recovery; state %s", ir.GetState())
		}
		time.Sleep(time.Millisecond)
	}
}

// A second unlock of the unlocked signer runs its passphrase checks and
// reload outside the store mutation lock. An uncertain policy commit meanwhile
// enters recovery; the unlock, still in flight, once published unlocked over
// it when its reload returned. It now publishes nothing, the signer stays in
// recovery as the apply's answer says, and the unlock answers that it found
// recovery.
func TestUncertainPolicyCommitDuringASecondUnlockEntersRecovery(t *testing.T) {
	svc, ir, reload := setupUnpublishedPolicyAdmin(t, noderole.RoleSigner)
	ir.SetUnlocked()
	view := svc.GetPolicy()
	snapshot := svc.GetPolicyContext().SnapshotSHA256
	release, unlockOutcome := secondUnlockInFlight(t, ir, reload)

	identityDir := svc.Deps.KeyPaths().ProductDir()
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == identityDir {
			return errors.New("simulated identity-directory sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()
	applied := make(chan adminproto.ApplyPolicyResult, 1)
	go func() {
		applied <- svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
			Documents:               []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: signerPolicyDoc("2000")}},
			ExpectedPolicySetSHA256: view.PolicySetSHA256,
			ExpectedSnapshotSHA256:  snapshot,
		})
	}()
	awaitRecovery(t, ir)
	release()
	result := <-applied
	fsutil.TestHook = nil

	if result.Success || !result.CommitUncertain || result.Code != "policy_commit_uncertain" {
		t.Fatalf("ApplyPolicy(durability unknown) = %+v", result)
	}
	if got := unlockOutcome(); got != signerruntime.RecoveryDuringUnlockMessage {
		t.Fatalf("the second unlock = %q, want %q", got, signerruntime.RecoveryDuringUnlockMessage)
	}
	if !ir.IsRecovery() {
		t.Fatalf("state after an uncertain commit during a second unlock = %s, want recovery", ir.GetState())
	}
}
