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
	"github.com/aplane-algo/aplane/internal/signerapp/externalcheck"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
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
	ir.SetVerifiedPolicyState(&policyruntime.NodePolicy{Role: ir.NodeRole(), Default: initialPolicy}, nil, nil)

	svc := signer.newSigningServiceWithAudit(ir, nil)

	later := policy.DefaultConfig()
	later.AutoApproveSelfNoOpTransfer = true
	ir.SetVerifiedPolicyState(&policyruntime.NodePolicy{Role: ir.NodeRole(), Default: later}, nil, nil)
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
	if svc.Approval == nil {
		t.Fatal("captured approval service = nil")
	}
	if svc.Approval.UserAutoApprove {
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
		ir.SetVerifiedPolicyState(np, nil, nil)
		return genesis
	}
	ir := productruntime.New(productruntime.Config{NodeRole: noderole.RoleSigner})
	genesis := install(ir, "XYZ", 2)
	svc := (&Signer{config: cfg}).newSigningServiceWithAudit(ir, nil)
	install(ir, "NEW", 6)

	txn := types.Transaction{Type: types.AssetTransferTx, Header: types.Header{GenesisHash: genesis},
		AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: 9, AssetAmount: 150}}
	// Every prompt's review is described by the service, in the captured
	// context.
	if got := svc.GenerateTxnDescriptionFromTxn(txn).Text(); !strings.Contains(got, "ASA Transfer: 1.5 XYZ (150 base units), asset #9, private-dev") {
		t.Fatalf("the prompt after an ASA set change:\n%s", got)
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

// A request signs only in the session it began in. A recovery and a
// reconcile while it waits (for an approval, say) leave the signer unlocked
// again, but in a new session, and the request is refused before it signs
// rather than signed on a plan made before them. A lock and an unlock do the
// same; a request begun afterwards signs.
func TestSigningServiceRefusesAfterTheSessionItBeganInEnds(t *testing.T) {
	for _, tc := range []struct {
		name      string
		roundTrip func(ir *productruntime.Runtime)
	}{
		{"recovery and reconcile", func(ir *productruntime.Runtime) {
			ir.EnterRecovery(nil)
			if !ir.PromoteRecoveryToUnlocked() {
				t.Fatal("reconcile did not promote the signer")
			}
		}},
		{"lock and unlock", func(ir *productruntime.Runtime) {
			ir.Lock()
			ir.SetUnlocked()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := &Signer{config: &serverconfig.ServerConfig{}}
			ir := productruntime.New(productruntime.Config{})
			ir.SetVerifiedPolicyState(&policyruntime.NodePolicy{Role: ir.NodeRole(), Default: policy.DefaultConfig()}, nil, nil)
			ir.SetUnlocked()

			svc := signer.newSigningServiceWithAudit(ir, nil)
			if !svc.IsUnlocked() {
				t.Fatal("a request begun on an unlocked signer reads locked")
			}
			tc.roundTrip(ir)
			if !ir.IsUnlocked() {
				t.Fatal("the signer is not unlocked after the round trip")
			}
			if svc.IsUnlocked() {
				t.Fatal("a request begun before the round trip still reads as signable")
			}
			if release, err := svc.BeforeExecute(); err == nil {
				release()
				t.Fatal("a request begun before the round trip may still execute")
			}
			if !signer.newSigningServiceWithAudit(ir, nil).IsUnlocked() {
				t.Fatal("a request begun after the round trip cannot sign")
			}
		})
	}
}

// A request that begins while the signer is in recovery has no session to
// sign in, though the reconcile leaves the signer unlocked again: the policy
// snapshot it took may since have been replaced.
func TestSigningServiceBegunInRecoveryIsRefused(t *testing.T) {
	signer := &Signer{config: &serverconfig.ServerConfig{}}
	ir := productruntime.New(productruntime.Config{})
	ir.SetVerifiedPolicyState(&policyruntime.NodePolicy{Role: ir.NodeRole(), Default: policy.DefaultConfig()}, nil, nil)
	ir.SetUnlocked()
	ir.EnterRecovery(nil)

	svc := signer.newSigningServiceWithAudit(ir, nil)
	if !ir.PromoteRecoveryToUnlocked() {
		t.Fatal("reconcile did not promote the signer")
	}
	if svc.IsUnlocked() {
		t.Fatal("a request begun in recovery reads as signable after the reconcile")
	}
	if !signer.newSigningServiceWithAudit(ir, nil).IsUnlocked() {
		t.Fatal("a request begun after the reconcile cannot sign")
	}
}

// The external checks read tokens from the runtime's source token index: the
// index published when the lookup runs, and none once the signer locks.
func TestSigningServiceReadsSourceTokensFromTheRuntimeIndex(t *testing.T) {
	const keyID = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
	signer := &Signer{config: &serverconfig.ServerConfig{}}
	ir := productruntime.New(productruntime.Config{NodeRole: noderole.RoleCosigner})
	ir.SetUnlocked()
	svc := signer.newSigningServiceWithAudit(ir, nil)
	runner, ok := svc.ExternalChecks.(*externalcheck.Runner)
	if !ok || runner.Tokens == nil {
		t.Fatalf("ExternalChecks = %#v, want a runner that reads tokens", svc.ExternalChecks)
	}
	if _, ok := runner.Tokens(keyID, "screening"); ok {
		t.Fatal("a token was found before any was published")
	}
	f, err := sourcetokens.SetToken(nil, keyID, "screening", []byte("token-value"), time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Zero()
	ir.PublishSourceTokens(sourcetokens.NewIndex([]*sourcetokens.File{f}))
	if got, ok := runner.Tokens(keyID, "screening"); !ok || got != "token-value" {
		t.Fatalf("Tokens() = %q, %v; want the token published after the service was built", got, ok)
	}
	ir.Lock()
	if _, ok := runner.Tokens(keyID, "screening"); ok {
		t.Fatal("a token was found after the signer locked")
	}
}
