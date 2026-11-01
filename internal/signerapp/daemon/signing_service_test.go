// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/policycontext"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
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

// contextWithAsset9 is a signer's context mapping private-dev, with asset 9
// confirmed under unit and decimals.
func contextWithAsset9(t *testing.T, unit string, decimals uint64) (*policycontext.Context, types.Digest) {
	t.Helper()
	const hash = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	genesis, err := asaset.ParseGenesisHash(hash)
	if err != nil {
		t.Fatal(err)
	}
	set, err := asaset.New([]asaset.Entry{{
		Identity: asaset.Identity{Genesis: genesis, AssetID: 9}, UnitName: unit, Decimals: decimals,
		Creator: types.Address{1}.String(), ConfirmedAt: time.Unix(1_700_000_000, 0), NetworkAtConfirmation: "private-dev",
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := policyruntime.NewContext(noderole.RoleSigner, &serverconfig.ServerConfig{GenesisHashNetworks: map[string]string{hash: "private-dev"}}, set)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, types.Digest(genesis)
}

// A request shows amounts from the context it captured: an approval queued
// before the ASA set changes keeps the prompt and the limit messages it was
// built with.
func TestSigningServiceShowsAmountsFromTheCapturedContext(t *testing.T) {
	cfg := &serverconfig.ServerConfig{GenesisHashNetworks: map[string]string{"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=": "private-dev"}}
	doc := policytest.MustDocument(noderole.RoleSigner, policy.DefaultKey, `{"limits": {"private-dev": {"asa:9": {"reject_above": "100"}}},
		"transfer_policy": {"routes": [{"id": "r", "networks": ["private-dev"], "sources": ["*"], "assets": ["asa:9"], "destinations": ["*"],
			"limits": {"private-dev": {"asa:9": {"review_above": "120"}}}}]}}`)
	install := func(ir *productruntime.Runtime, unit string, decimals uint64) types.Digest {
		ctx, genesis := contextWithAsset9(t, unit, decimals)
		np, err := policyruntime.Compile(noderole.RoleSigner, cfg, []policy.StoredDocument{{Key: policy.DefaultKey, Bytes: []byte(doc)}}, ctx)
		if err != nil {
			t.Fatal(err)
		}
		ir.SetNodePolicy(np)
		return genesis
	}
	ir := productruntime.New(productruntime.Config{NodeRole: noderole.RoleSigner})
	genesis := install(ir, "XYZ", 2)
	svc := (&Signer{config: cfg}).newSigningServiceWithAudit(ir, nil)
	install(ir, "NEW", 6)

	txn := types.Transaction{Type: types.AssetTransferTx, Header: types.Header{GenesisHash: genesis},
		AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: 9, AssetAmount: 150}}
	// Group prompts are built by the service, single-transaction prompts by
	// its approval service; both show the captured context.
	for name, describe := range map[string]signersigning.GenerateTxnDescriptionFromTxnFunc{
		"group":              svc.GenerateTxnDescriptionFromTxn,
		"single transaction": svc.Approval.GenerateTxnDescriptionFromTxn,
	} {
		if got := describe(txn); !strings.Contains(got, "ASA Transfer: 1.5 XYZ (150 base units), asset #9, private-dev") {
			t.Fatalf("the %s prompt after an ASA set change:\n%s", name, got)
		}
	}
	violations := policy.CheckTxnPolicyLints(txn, svc.PolicyFor("ANY"), nil)
	if msg := policy.JoinLintViolations(violations); !strings.Contains(msg, "1.5 XYZ (150 base units) of asset #9 exceeds") || !strings.Contains(msg, "1 XYZ (100 base units)") {
		t.Fatalf("the limit message after an ASA set change: %s", msg)
	}
	routed := policy.CheckTxnTransferRoutingReviewPolicyLints(txn, svc.PolicyFor("ANY"))
	if msg := policy.JoinLintViolations(routed); !strings.Contains(msg, "1.5 XYZ (150 base units) of asset #9 exceeds review threshold 1.2 XYZ (120 base units) on private-dev") {
		t.Fatalf("the route limit message after an ASA set change: %s", msg)
	}
}
