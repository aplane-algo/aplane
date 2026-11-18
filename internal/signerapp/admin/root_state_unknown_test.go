// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"errors"
	"os"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// hideRootAfterCommit makes the next store root commit land and then fail
// with the root unreadable, which leaves its state unknown: the commit's
// directory sync moves the new root aside and fails. The returned function
// puts the root back.
func hideRootAfterCommit(t *testing.T, paths storepaths.Paths) func() {
	t.Helper()
	root, aside := paths.StoreRootPath(), paths.StoreRootPath()+".aside"
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op != fsutil.OpDirSync || path != paths.ProductDir() {
			return nil
		}
		fsutil.TestHook = nil
		if err := os.Rename(root, aside); err != nil {
			t.Error(err)
		}
		return errors.New("simulated identity-directory sync failure")
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	return func() {
		fsutil.TestHook = nil
		if err := os.Rename(aside, root); err != nil {
			t.Fatal(err)
		}
	}
}

// A policy commit whose root cannot be read back may have landed, so the
// signer enters recovery as for an unconfirmed commit, instead of reporting
// a failure before commit and signing on from the old generation.
func TestPolicyApplyWithAnUnreadableRootEntersRecovery(t *testing.T) {
	svc, ir := setupPolicyAdmin(t, noderole.RoleSigner)
	view := svc.GetPolicy()
	restoreRoot := hideRootAfterCommit(t, svc.Deps.KeyPaths())
	result := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: signerPolicyDoc("2000")}},
		ExpectedPolicySetSHA256: view.PolicySetSHA256,
		ExpectedSnapshotSHA256:  svc.GetPolicyContext().SnapshotSHA256,
	})
	restoreRoot()

	if result.Success || !result.CommitUncertain || result.Code != "policy_commit_uncertain" {
		t.Fatalf("ApplyPolicy(root state unknown) = %+v", result)
	}
	if !ir.IsRecovery() {
		t.Fatal("runtime is not in recovery after a policy commit of unknown state")
	}
	if got := currentGeneration(t, svc, ir); result.GenerationID == "" || got != result.GenerationID {
		t.Fatalf("root selects %s, result names %q; want the commit that landed", got, result.GenerationID)
	}
}

// An ASA set commit whose root cannot be read back enters recovery the same
// way.
func TestAddASAWithAnUnreadableRootEntersRecovery(t *testing.T) {
	svc, ir, _ := setupASAAdmin(t)
	restoreRoot := hideRootAfterCommit(t, svc.Deps.KeyPaths())
	added := confirmASA9(t, svc)
	restoreRoot()

	if added.Success || !added.CommitUncertain || added.Code != "asa_commit_uncertain" {
		t.Fatalf("AddASA(root state unknown) = %+v", added)
	}
	if !ir.IsRecovery() {
		t.Fatal("runtime is not in recovery after an ASA set commit of unknown state")
	}
	if got := currentGeneration(t, svc, ir); added.GenerationID == "" || got != added.GenerationID {
		t.Fatalf("root selects %s, result names %q; want the commit that landed", got, added.GenerationID)
	}
}
