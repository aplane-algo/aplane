// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig"
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
	lsig.RegisterClient()
	root := t.TempDir()
	paths := storepaths.NewPaths(root)
	if _, err := storeinit.Initialize([]byte(adminPolicyPassphrase), storeinit.Options{DataDir: root, Paths: paths, Role: role}); err != nil {
		t.Fatal(err)
	}
	cfg := serverconfig.DefaultServerConfig()
	deps := &fakeDeps{dataDir: root, config: &cfg, keyPaths: paths}
	ir := productruntime.New(productruntime.Config{
		KeyStore:      keystore.NewAtomicFileKeyStoreForPaths(paths),
		KeyPaths:      paths,
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		NodeRole:      role,
	})
	if err := ir.KeyStore().Unlock([]byte(adminPolicyPassphrase)); err != nil {
		t.Fatal(err)
	}
	ir.SetUnlocked()
	reload := func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return &signertemplates.ReloadReport{}, ir.KeyStore().WithKeyring(func(kr *crypto.Keyring) error {
			active, err := genstore.ResolveStoreRootWithKeyring(paths, kr)
			if err != nil {
				return err
			}
			np, err := policyruntime.Load(role, root, &cfg, active, kr)
			if err != nil {
				return err
			}
			ir.SetNodePolicy(np)
			return nil
		})
	}
	ir.SetReloadFunc(reload)
	if _, err := reload(nil, nil); err != nil {
		t.Fatal(err)
	}
	return Service{Deps: deps, Runtime: ir}, ir
}

func signerPolicyDoc(maxFee string) string {
	return fmt.Sprintf(`{"format":"aplane.signer-policy.v1","max_fee_microalgos":%q}`, maxFee)
}

func cosignerPolicyDoc(key string) string {
	return fmt.Sprintf(`{"format":"aplane.cosigner-policy.v1","key":%q,"transfer_policy":{"routes":[]}}`, key)
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
	if !view.Success || view.NodeRole != "signer" || len(view.Documents) != 1 ||
		view.Documents[0].Size != len(policy.InitialSignerPolicy) ||
		svc.GetPolicyDocument("").Document != string(policy.InitialSignerPolicy) {
		t.Fatalf("GetPolicy() = %+v", view)
	}
	before := currentGeneration(t, svc, ir)

	result := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Document: signerPolicyDoc("2000")}},
		ExpectedPolicySetSHA256: view.PolicySetSHA256,
	})
	if !result.Success || result.Policy == nil || result.Policy.GenerationID == "" {
		t.Fatalf("ApplyPolicy() = %+v", result)
	}
	if after := currentGeneration(t, svc, ir); after == before || after != result.Policy.GenerationID {
		t.Fatalf("generation %s -> %s, result %s", before, after, result.Policy.GenerationID)
	}
	if got := ir.Policy(); got == nil || got.MaxFeeMicroAlgos != 2000 {
		t.Fatalf("runtime policy after apply = %#v", got)
	}
	if again := svc.GetPolicy(); svc.GetPolicyDocument("").Document != signerPolicyDoc("2000") || again.PolicySetSHA256 == view.PolicySetSHA256 {
		t.Fatalf("GetPolicy() after apply = %+v", again)
	}

	unchanged := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Document: signerPolicyDoc("2000")}},
		ExpectedPolicySetSHA256: result.Policy.PolicySetSHA256,
	})
	if !unchanged.Success || unchanged.Policy.GenerationID != "" || currentGeneration(t, svc, ir) != result.Policy.GenerationID {
		t.Fatalf("identical apply = %+v, want no new generation", unchanged)
	}
}

func TestPolicyApplyRejectsStaleInvalidAndMalformedRequests(t *testing.T) {
	svc, ir := setupPolicyAdmin(t, noderole.RoleSigner)
	view := svc.GetPolicy()
	before := currentGeneration(t, svc, ir)
	for _, tc := range []struct {
		name string
		req  adminproto.ApplyPolicyRequest
		code string
	}{
		{"no concurrency base", adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Document: signerPolicyDoc("1")}}}, "expected_policy_set_sha256_required"},
		{"stale base", adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Document: signerPolicyDoc("1")}}, ExpectedPolicySetSHA256: strings.Repeat("0", 64)}, "policy_snapshot_changed"},
		{"invalid document", adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Document: `{"format":"aplane.signer-policy.v1","max_fee_microalgos":1}`}}, ExpectedPolicySetSHA256: view.PolicySetSHA256}, "policy_validation_failed"},
		{"keyed signer document", adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: adminPolicyKeyA, Document: signerPolicyDoc("1")}}, ExpectedPolicySetSHA256: view.PolicySetSHA256}, "invalid_policy_request"},
		{"signer removal", adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Document: signerPolicyDoc("1")}}, Remove: []string{adminPolicyKeyA}, ExpectedPolicySetSHA256: view.PolicySetSHA256}, "invalid_policy_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.ApplyPolicy(tc.req)
			if result.Success || result.Code != tc.code {
				t.Fatalf("ApplyPolicy() = %+v, want code %s", result, tc.code)
			}
			if tc.code == "policy_validation_failed" && (len(result.Errors) != 1 || result.Errors[0].Pointer != "/max_fee_microalgos") {
				t.Fatalf("problems = %+v, want one at /max_fee_microalgos", result.Errors)
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
	if !view.Success || view.NodeRole != "cosigner" || len(view.Documents) != 0 ||
		len(view.Keys) != 1 || view.Keys[0].Status != adminproto.PolicyKeyNoPolicy {
		t.Fatalf("initial GetPolicy() = %+v", view)
	}

	check := svc.CheckPolicy(adminproto.CheckPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: adminPolicyKeyB, Document: cosignerPolicyDoc(adminPolicyKeyB)}}})
	if !check.Success || !check.Valid || len(check.Warnings) != 2 {
		t.Fatalf("CheckPolicy() = %+v, want valid with no-policy and key-not-held warnings", check)
	}

	result := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents: []adminproto.PolicyDocument{
			{Key: adminPolicyKeyA, Document: cosignerPolicyDoc(adminPolicyKeyA)},
			{Key: adminPolicyKeyB, Document: cosignerPolicyDoc(adminPolicyKeyB)},
		},
		ExpectedPolicySetSHA256: view.PolicySetSHA256,
	})
	if !result.Success {
		t.Fatalf("ApplyPolicy(add) = %+v", result)
	}
	status := map[string]string{}
	for _, st := range result.Policy.Keys {
		status[st.Key] = st.Status
	}
	if status[adminPolicyKeyA] != adminproto.PolicyKeyActive || status[adminPolicyKeyB] != adminproto.PolicyKeyNotHeld {
		t.Fatalf("key status = %v", status)
	}
	if policies := ir.CosignerPolicies(); len(policies) != 2 {
		t.Fatalf("runtime cosigner policies = %d, want 2", len(policies))
	}

	removed := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{Remove: []string{adminPolicyKeyB}, ExpectedPolicySetSHA256: result.Policy.PolicySetSHA256})
	if !removed.Success || len(removed.Policy.Documents) != 1 || removed.Policy.Documents[0].Key != adminPolicyKeyA {
		t.Fatalf("ApplyPolicy(remove) = %+v", removed)
	}
	if _, ok := ir.CosignerPolicies()[adminPolicyKeyB]; ok {
		t.Fatal("removed policy is still enforced")
	}
	if doc := svc.GetPolicyDocument(adminPolicyKeyA); !doc.Success || doc.Document != cosignerPolicyDoc(adminPolicyKeyA) {
		t.Fatalf("GetPolicyDocument(A) = %+v", doc)
	}
	for _, key := range []string{adminPolicyKeyB, ""} {
		if doc := svc.GetPolicyDocument(key); doc.Success || doc.Code != "policy_document_not_found" {
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
	ir.SetNodePolicy(nil)
	if view := svc.GetPolicy(); view.Success || view.Code != "policy_unavailable" {
		t.Fatalf("GetPolicy() = %+v", view)
	}
	if check := svc.CheckPolicy(adminproto.CheckPolicyRequest{Documents: []adminproto.PolicyDocument{{Document: signerPolicyDoc("1")}}}); check.Success || check.Code != "policy_unavailable" {
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
		Documents:               []adminproto.PolicyDocument{{Document: signerPolicyDoc("2000")}},
		ExpectedPolicySetSHA256: view.PolicySetSHA256,
	})
	if result.Success || !result.CommitUncertain || result.Code != "policy_reload_failed" {
		t.Fatalf("ApplyPolicy() = %+v, want an uncertain reload failure", result)
	}
	if !deps.recoveryAtRelease {
		t.Fatal("runtime entered recovery only after the store mutation lock was released")
	}
	if !ir.IsRecovery() {
		t.Fatal("runtime is not in recovery after a failed post-commit reload")
	}
}
