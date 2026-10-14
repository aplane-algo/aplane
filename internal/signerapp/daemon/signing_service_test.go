// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

// A signing service resolves every key against the policy snapshot captured
// when it was built: a later reload or setting change never reaches it.
func TestNewSigningServiceForRuntimeCapturesPolicyAndUserAutoApproveSnapshot(t *testing.T) {
	userAutoApprove := false
	signer := &Signer{
		config: &serverconfig.ServerConfig{},
	}
	ir := productruntime.New(productruntime.Config{
		UserAutoApprove: &userAutoApprove,
	})
	initialPolicy := policy.DefaultConfig()
	initialPolicy.AlwaysReviewWarnings = true
	ir.SetPolicy(initialPolicy)

	svc := signer.newSigningServiceWithAudit(ir, nil)

	later := policy.DefaultConfig()
	later.AutoApproveSelfNoOpTransfer = true
	ir.SetPolicy(later)
	ir.Config().SetUserAutoApprove(true)

	if svc.PolicyFor == nil {
		t.Fatal("captured resolver = nil, want snapshot")
	}
	first, second := svc.PolicyFor("KEY-A"), svc.PolicyFor("KEY-B")
	if first == nil || !first.AlwaysReviewWarnings || first.AutoApproveSelfNoOpTransfer {
		t.Fatalf("captured policy = %+v, want the snapshot taken at construction", first)
	}
	if second != first {
		t.Fatal("two resolutions on one service returned different snapshots")
	}
	if svc.Approval == nil || svc.Approval.UserAutoApprove == nil {
		t.Fatal("captured approval service/user_auto_approve = nil")
	}
	if *svc.Approval.UserAutoApprove {
		t.Fatal("captured user_auto_approve observed later runtime mutation")
	}
}
