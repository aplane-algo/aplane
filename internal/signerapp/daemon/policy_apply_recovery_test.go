// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
)

// An uncertain policy commit must block signing before the runtime reloads:
// signing does not take the store mutation lock, so a request reaching the
// execution gate during the reload would sign against the generation being
// replaced.
func TestUncertainPolicyCommitBlocksExecutionBeforeReload(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	app := server.adminServices().adminApp()
	view := app.GetPolicy()
	var reloaded, executionAllowed bool
	ir.SetReloadFunc(func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		reloaded = true
		// This is the production execution gate a concurrent signing request uses.
		release, err := server.newSigningServiceWithAudit(ir, nil).BeforeExecute()
		executionAllowed = err == nil
		if release != nil {
			release()
		}
		return &signertemplates.ReloadReport{}, nil
	})
	identityDir := server.keyPaths.ProductDir()
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == identityDir {
			return errors.New("simulated directory sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()
	result := app.ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: policytest.Signer(t, policy.DefaultKey, `{"max_fee_microalgos":"4321"}`)}},
		ExpectedPolicySetSHA256: view.PolicySetSHA256,
	})
	if !result.CommitUncertain || !reloaded {
		t.Fatalf("missing uncertain reload: %+v, reload=%v", result, reloaded)
	}
	if executionAllowed {
		t.Fatal("production signing execution gate allowed signing during uncertain-commit reload")
	}
}
