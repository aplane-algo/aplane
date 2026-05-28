// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

func TestNewSigningServiceForIdentityCapturesPolicyAndUserAutoApproveSnapshot(t *testing.T) {
	userAutoApprove := false
	signer := &Signer{
		registry: identity.NewRegistry(),
		config:   &apconfig.ServerConfig{},
	}
	ir := identity.New(identity.Config{
		ID:              auth.DefaultIdentityID,
		Authenticator:   auth.NewTokenAuthenticator("test-token"),
		UserAutoApprove: &userAutoApprove,
	})
	initialPolicy := &policy.Config{
		AlwaysReviewWarnings: true,
	}
	ir.SetPolicy(initialPolicy)

	svc := signer.newSigningServiceForIdentityWithAudit(ir, nil)

	ir.SetPolicy(&policy.Config{
		RejectForeignRekey:          true,
		AutoApproveSelfNoOpTransfer: true,
	})
	ir.Config().SetUserAutoApprove(true)

	if svc.Policy == nil {
		t.Fatal("captured policy = nil, want snapshot")
	}
	if !svc.Policy.AlwaysReviewWarnings {
		t.Fatal("captured policy lost initial AlwaysReviewWarnings setting")
	}
	if svc.Policy.RejectForeignRekey {
		t.Fatal("captured policy observed later RejectForeignRekey mutation")
	}
	if svc.Policy.AutoApproveSelfNoOpTransfer {
		t.Fatal("captured policy observed later AutoApproveSelfNoOpTransfer mutation")
	}
	if svc.Approval == nil || svc.Approval.UserAutoApprove == nil {
		t.Fatal("captured approval service/user_auto_approve = nil")
	}
	if *svc.Approval.UserAutoApprove {
		t.Fatal("captured user_auto_approve observed later runtime mutation")
	}
}
