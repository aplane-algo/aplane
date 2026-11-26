// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/externalcheck"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

// externalGate is a cosigner gate test: a route policy from source to allowed,
// with one screening check on every pay movement, asked of a stub source.
type externalGate struct {
	t       *testing.T
	svc     *Service
	audit   *limitedCosignerAuditLogger
	cfg     *policy.Config
	source  string
	allowed string
	hits    atomic.Int32
	mu      sync.Mutex
	answer  func(w http.ResponseWriter, r *http.Request)
}

func newExternalGate(t *testing.T) *externalGate {
	t.Helper()
	g := &externalGate{t: t, source: types.Address{25}.String(), allowed: types.Address{26}.String(), audit: &limitedCosignerAuditLogger{}}
	g.answer = func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"score": 12}`)) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.hits.Add(1)
		g.mu.Lock()
		answer := g.answer
		g.mu.Unlock()
		answer(w, r)
	}))
	t.Cleanup(srv.Close)
	g.cfg = cosignerRoutePolicy(t, g.source, g.allowed)
	g.cfg.DocumentKey = policy.DefaultKey
	g.cfg.ExternalSources = map[string]policy.ExternalSourceV1{"screening": {BaseURL: srv.URL, TimeoutMS: 5000, MaxResponseBytes: 1024}}
	limit := "30"
	g.cfg.ExternalChecks = []policy.ExternalCheckV1{{
		ID: "screen", Source: "screening", Scope: policy.ExternalScopeMovement, NetworkWildcard: true,
		Path: policy.ExternalTemplateV1{Text: "/screen/{destination}", Parts: []policy.ExternalTemplatePart{
			{Literal: "/screen/"}, {Fact: "destination"}}},
		Require: []policy.ExternalRuleV1{{Pointer: "/score", Op: policy.ExternalOpLe, Number: &limit}},
	}}
	g.svc = &Service{
		Planner: cosignerTestPlanner, PolicyFor: fixedPolicy(g.cfg), HoldsCosignerKey: holdsAllCosignerKeys,
		AuditLog: g.audit, ExternalChecks: &externalcheck.Runner{Fetcher: &externalcheck.Fetcher{}},
	}
	return g
}

func (g *externalGate) setAnswer(answer func(w http.ResponseWriter, r *http.Request)) {
	g.mu.Lock()
	g.answer = answer
	g.mu.Unlock()
}

func (g *externalGate) plan(destination string) *ComponentSignPlan {
	txn := testnetPaymentTransaction(g.t, g.source, destination, 1)
	return mustPrepareComponentSigning(g.t, componentPlanRequest{
		RequestID:     "cmp-cosigner-external",
		ComponentKey:  testFalconComponentSelector(g.t, 0xab),
		Group:         componentTestGroup(g.t, []string{txnutil.EncodeWithPrefixHex(txn)}),
		TargetIndices: []int{0},
	})
}

// A request the policy would sign is signed when its checks pass, and the
// gates record what ran for the audit record.
func TestCosignerSignsWhenExternalChecksPass(t *testing.T) {
	g := newExternalGate(t)
	plan := g.plan(g.allowed)
	if err := g.svc.runCosignerGates(context.Background(), plan); err != nil {
		t.Fatalf("runCosignerGates() error = %#v", err)
	}
	if plan.ExternalChecks == nil || !slices.Equal(plan.ExternalChecks.CheckIDs, []string{"screen"}) || plan.ExternalChecks.Lookups != 1 {
		t.Fatalf("plan.ExternalChecks = %+v, want screen over one lookup", plan.ExternalChecks)
	}
	if got := externalChecksNote(plan.ExternalChecks); got != "; external checks passed: screen (1 lookup)" {
		t.Fatalf("audit note = %q", got)
	}
	if g.hits.Load() != 1 {
		t.Fatalf("%d lookups, want 1", g.hits.Load())
	}
	if externalChecksNote(nil) != "" {
		t.Fatal("a document without checks adds nothing to the audit record")
	}
}

// A refusal tells the requester which check refused which unit and no more.
// What the source answered stays in the cosigner's audit record.
func TestCosignerExternalCheckRefusalKeepsTheAnswerInTheAuditRecord(t *testing.T) {
	g := newExternalGate(t)
	g.setAnswer(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"score": 72}`)) })
	err := g.svc.runCosignerGates(context.Background(), g.plan(g.allowed))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("error = %#v, want forbidden", err)
	}
	want := "cosigner policy rejected request: external check screen refused the pay movement of transaction 0 (external_check:screen)"
	if err.Message != want {
		t.Fatalf("message = %q, want %q", err.Message, want)
	}
	if strings.Contains(err.Message, "72") {
		t.Fatal("the requester was told what the source answered")
	}
	if len(g.audit.limited) != 1 {
		t.Fatalf("%d audit entries, want 1", len(g.audit.limited))
	}
	entry := g.audit.limited[0]
	if entry.policyRule != "external_check:screen" || !strings.Contains(entry.reason, "/score = 72, want le 30") ||
		!strings.Contains(entry.reason, "source screening, GET /screen/"+g.allowed) {
		t.Fatalf("audit entry = %+v", entry)
	}
}

// A lookup that fails refuses the request, under its own rule ID.
func TestCosignerRefusesWhenAnExternalLookupFails(t *testing.T) {
	g := newExternalGate(t)
	g.setAnswer(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	err := g.svc.runCosignerGates(context.Background(), g.plan(g.allowed))
	if err == nil || err.Kind != ErrorForbidden || !strings.Contains(err.Message, "external_check:screen:unavailable") {
		t.Fatalf("error = %#v, want the check unavailable", err)
	}
	if entry := g.audit.limited[0]; !strings.Contains(entry.reason, "status 503") {
		t.Fatalf("audit entry = %+v, want the status", entry)
	}
}

// Nothing is looked up for a request the policy refuses, and the refusal is
// the policy's own.
func TestCosignerMakesNoLookupForARequestThePolicyRefuses(t *testing.T) {
	g := newExternalGate(t)
	err := g.svc.runCosignerGates(context.Background(), g.plan(types.Address{27}.String()))
	if err == nil || !strings.Contains(err.Message, policy.TransferRoutingRouteMissRuleID) {
		t.Fatalf("error = %#v, want the policy's route miss", err)
	}
	if strings.Contains(err.Message, "external_check") {
		t.Fatalf("error = %q names an external check", err.Message)
	}
	if g.hits.Load() != 0 {
		t.Fatalf("%d lookups for a request the policy refused, want none", g.hits.Load())
	}
}

// A node that cannot run checks signs nothing under a document that has any.
func TestCosignerRefusesWhenItCannotRunExternalChecks(t *testing.T) {
	g := newExternalGate(t)
	g.svc.ExternalChecks = nil
	store := &componentKeyStore{}
	txn := testnetPaymentTransaction(t, g.source, g.allowed, 1)
	_, err := g.svc.signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-external",
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		Group:         componentTestGroup(t, []string{txnutil.EncodeWithPrefixHex(txn)}),
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorForbidden || !strings.Contains(err.Message, "external_check:screen:unavailable") {
		t.Fatalf("error = %#v, want the check unavailable", err)
	}
	if store.calls != 0 || g.hits.Load() != 0 {
		t.Fatalf("store calls = %d, lookups = %d; want none of either", store.calls, g.hits.Load())
	}
	// A document without checks needs no runner.
	g.cfg.ExternalChecks = nil
	if err := g.svc.runCosignerGates(context.Background(), g.plan(g.allowed)); err != nil {
		t.Fatalf("runCosignerGates() without checks error = %#v", err)
	}
}

// The step holds a key use for as long as it runs. A lock cancels the key
// use's context: the lookup ends at once, the request is refused as locked,
// and the key use is released, which is what the lock waits for before it
// clears the tokens.
func TestCosignerExternalChecksEndWhenTheNodeLocks(t *testing.T) {
	g := newExternalGate(t)
	arrived := make(chan struct{})
	g.setAnswer(func(_ http.ResponseWriter, r *http.Request) {
		close(arrived)
		<-r.Context().Done()
	})
	var held, released atomic.Int32
	lockCtx, lock := context.WithCancel(context.Background())
	g.svc.KeyUse = func(context.Context) (context.Context, func()) {
		held.Add(1)
		return lockCtx, func() { released.Add(1) }
	}
	done := make(chan *ServiceError, 1)
	go func() { done <- g.svc.runCosignerGates(context.Background(), g.plan(g.allowed)) }()
	<-arrived
	if held.Load() != 1 || released.Load() != 0 {
		t.Fatalf("held = %d, released = %d during the lookup; want 1 and 0", held.Load(), released.Load())
	}
	start := time.Now()
	lock()
	select {
	case err := <-done:
		if err == nil || err.Kind != ErrorLocked {
			t.Fatalf("error = %#v, want locked", err)
		}
		if waited := time.Since(start); waited > time.Second {
			t.Fatalf("the gates returned %s after the lock; a lock must not wait for the source", waited)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the gates did not return after the lock")
	}
	if released.Load() != 1 {
		t.Fatalf("released = %d after the gates returned, want 1", released.Load())
	}
	if len(g.audit.limited) != 0 {
		t.Fatalf("a lock was audited as a refusal: %+v", g.audit.limited)
	}

	// A request that reaches the step on a locked node makes no lookup.
	before := g.hits.Load()
	if err := g.svc.runCosignerGates(context.Background(), g.plan(g.allowed)); err == nil || err.Kind != ErrorLocked {
		t.Fatalf("error = %#v on a locked node, want locked", err)
	}
	if g.hits.Load() != before {
		t.Fatal("a lookup was made on a locked node")
	}
}

// If recovery clears the source token index before key-use context
// cancellation reaches an in-flight external check, a missing token while the
// session is no longer unlocked must answer locked and record no cosigner
// policy rejection. While unlocked, a genuinely unset token still refuses
// under external_check:<id>:token_not_set.
func TestCosignerExternalChecksTokenClearedBySessionEndAnswersLocked(t *testing.T) {
	newTokenGate := func(t *testing.T, unlocked bool) *externalGate {
		t.Helper()
		g := newExternalGate(t)
		src := g.cfg.ExternalSources["screening"]
		src.Token = &policy.ExternalTokenV1{Header: "Authorization", Prefix: "Bearer "}
		g.cfg.ExternalSources["screening"] = src
		g.svc.IsUnlocked = func() bool { return unlocked }
		g.svc.KeyUse = func(ctx context.Context) (context.Context, func()) { return ctx, func() {} }
		g.svc.ExternalChecks = &externalcheck.Runner{
			Fetcher: &externalcheck.Fetcher{},
			Tokens:  func(string, string) (string, bool) { return "", false },
		}
		return g
	}

	t.Run("ended session answers locked without rejection audit", func(t *testing.T) {
		g := newTokenGate(t, false)
		err := g.svc.runCosignerGates(context.Background(), g.plan(g.allowed))
		if err == nil || err.Kind != ErrorLocked {
			t.Fatalf("error = %#v, want locked", err)
		}
		if len(g.audit.limited) != 0 {
			t.Fatalf("ended session was audited as a refusal: %+v", g.audit.limited)
		}
		if g.hits.Load() != 0 {
			t.Fatalf("%d lookups made, want 0", g.hits.Load())
		}
	})

	t.Run("unlocked session still refuses missing token", func(t *testing.T) {
		g := newTokenGate(t, true)
		err := g.svc.runCosignerGates(context.Background(), g.plan(g.allowed))
		if err == nil || err.Kind != ErrorForbidden || !strings.Contains(err.Message, "external_check:screen:token_not_set") {
			t.Fatalf("error = %#v, want token_not_set refusal", err)
		}
		if len(g.audit.limited) != 1 {
			t.Fatalf("audit entries = %d, want 1", len(g.audit.limited))
		}
	})
}

// A canceled request ends its lookups and is reported as canceled.
func TestCosignerExternalChecksEndWhenTheRequestIsCanceled(t *testing.T) {
	g := newExternalGate(t)
	arrived := make(chan struct{})
	g.setAnswer(func(_ http.ResponseWriter, r *http.Request) {
		close(arrived)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *ServiceError, 1)
	go func() { done <- g.svc.runCosignerGates(ctx, g.plan(g.allowed)) }()
	<-arrived
	cancel()
	select {
	case err := <-done:
		if err == nil || err.Kind == ErrorForbidden || !strings.Contains(err.Message, "canceled") {
			t.Fatalf("error = %#v, want a canceled request", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the gates did not return after the cancel")
	}
}

// A Witness Key ID sent with padding is the canonical ID to every step: the
// key lookup and policy selection, the external check's lookup path and its
// witness_key fact, and the audit record. The source never sees the padding.
func TestCosignerExternalChecksUseTheCanonicalWitnessKeyID(t *testing.T) {
	g := newExternalGate(t)
	canonicalID := testFalconComponentSelector(t, 0xab)
	var gotPath atomic.Value
	g.setAnswer(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.EscapedPath())
		_, _ = w.Write([]byte(`{"key": "` + canonicalID + `"}`))
	})
	g.cfg.ExternalChecks = []policy.ExternalCheckV1{{
		ID: "ops-switch", Source: "screening", Scope: policy.ExternalScopeRequest, NetworkWildcard: true,
		Path: policy.ExternalTemplateV1{Text: "/signing/{witness_key}", Parts: []policy.ExternalTemplatePart{
			{Literal: "/signing/"}, {Fact: "witness_key"}}},
		Require: []policy.ExternalRuleV1{{Pointer: "/key", Op: policy.ExternalOpEq, Fact: "witness_key"}},
	}}
	txn := testnetPaymentTransaction(t, g.source, g.allowed, 1)
	plan, planErr := prepareComponentSigning(componentPlanRequest{
		RequestID:     "cmp-cosigner-padded-key",
		ComponentKey:  " " + canonicalID + "\n",
		Group:         componentTestGroup(t, []string{txnutil.EncodeWithPrefixHex(txn)}),
		TargetIndices: []int{0},
	})
	if planErr != nil {
		t.Fatalf("prepareComponentSigning() error = %#v", planErr)
	}
	if plan.ComponentKey != canonicalID {
		t.Fatalf("plan.ComponentKey = %q, want the canonical %q", plan.ComponentKey, canonicalID)
	}
	if err := g.svc.runCosignerGates(context.Background(), plan); err != nil {
		t.Fatalf("runCosignerGates() error = %#v", err)
	}
	if gotPath.Load() != "/signing/"+canonicalID {
		t.Fatalf("lookup path = %q, want /signing/%s", gotPath, canonicalID)
	}

	// A refusal's audit record names the canonical ID too.
	g.cfg.ExternalChecks[0].Require[0] = policy.ExternalRuleV1{Pointer: "/key", Op: policy.ExternalOpNe, Fact: "witness_key"}
	plan, _ = prepareComponentSigning(componentPlanRequest{
		RequestID: "cmp-cosigner-padded-key", ComponentKey: canonicalID + " ",
		Group:         componentTestGroup(t, []string{txnutil.EncodeWithPrefixHex(txn)}),
		TargetIndices: []int{0},
	})
	err := g.svc.runCosignerGates(context.Background(), plan)
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("error = %#v, want the check's refusal", err)
	}
	if len(g.audit.limited) != 1 || g.audit.limited[0].authAddress != canonicalID {
		t.Fatalf("audit entries = %+v, want one naming %s", g.audit.limited, canonicalID)
	}
}

// A component key that is not a Witness Key ID at all is refused as a bad
// request when the plan is built, before any gate runs.
func TestComponentPlanRefusesAMalformedWitnessKeyID(t *testing.T) {
	txn := testnetPaymentTransaction(t, types.Address{25}.String(), types.Address{26}.String(), 1)
	for _, key := range []string{"", "  ", "not-a-witness-key", strings.ToLower(testFalconComponentSelector(t, 0xab))} {
		_, err := prepareComponentSigning(componentPlanRequest{
			RequestID: "cmp-cosigner-bad-key", ComponentKey: key,
			Group:         componentTestGroup(t, []string{txnutil.EncodeWithPrefixHex(txn)}),
			TargetIndices: []int{0},
		})
		if err == nil || err.Kind != ErrorBadRequest {
			t.Fatalf("prepareComponentSigning(%q) error = %#v, want a bad request", key, err)
		}
	}
}

// A multi-target group whose transactions target different networks must be
// refused before policy evaluation or external checks run; otherwise a
// scope:request check scoped to mainnet would inspect only target 0's network
// and skip the lookup, even when policy routes cover both networks.
func TestCosignerRefusesMixedGenesisGroupBeforePolicyOrExternalChecks(t *testing.T) {
	g := newExternalGate(t)
	bothNetworks := cosignerPolicyConfigForSigningTest(t, fmt.Sprintf(`{
  "transfer_policy": {
    "routes": [
      {
        "id": "allow_both_networks",
        "networks": ["testnet", "mainnet"],
        "sources": [%q],
        "assets": ["algo"],
        "destinations": [%q]
      }
    ]
  }
}`, g.source, g.allowed))
	bothNetworks.DocumentKey = g.cfg.DocumentKey
	bothNetworks.ExternalSources = g.cfg.ExternalSources
	bothNetworks.ExternalChecks = []policy.ExternalCheckV1{{
		ID:       "mainnet-only-request",
		Source:   "screening",
		Scope:    policy.ExternalScopeRequest,
		Networks: []string{apconfig.NetworkMainnet},
		Path: policy.ExternalTemplateV1{Text: "/request/{network}", Parts: []policy.ExternalTemplatePart{
			{Literal: "/request/"}, {Fact: "network"},
		}},
		Require: []policy.ExternalRuleV1{{Pointer: "/ok", Op: policy.ExternalOpEq, Bool: boolPtr(true)}},
	}}
	g.cfg = bothNetworks
	g.svc.PolicyFor = fixedPolicy(bothNetworks)

	txn0 := testnetPaymentTransaction(t, g.source, g.allowed, 1)
	txn1 := testnetPaymentTransaction(t, g.source, g.allowed, 2)
	txn1.GenesisHash = verdictGenesis(t, apconfig.AlgorandMainnetGenesisHash)
	txn1.GenesisID = "mainnet-v1.0"
	gid, err := crypto.ComputeGroupID([]types.Transaction{txn0, txn1})
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	txn0.Group = gid
	txn1.Group = gid

	store := &componentKeyStore{}
	_, signErr := g.svc.signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-mixed-genesis",
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		Group:         componentTestGroup(t, []string{txnutil.EncodeWithPrefixHex(txn0), txnutil.EncodeWithPrefixHex(txn1)}),
		TargetIndices: []int{0, 1},
	}, newComponentKeySession(store))
	if signErr == nil || signErr.Kind != ErrorBadRequest || !strings.Contains(signErr.Message, "different genesis hash") {
		t.Fatalf("signComponentWithContext(mixed genesis) error = %#v, want bad request for different genesis hash", signErr)
	}
	if g.hits.Load() != 0 || store.calls != 0 || len(g.audit.limited) != 0 {
		t.Fatalf("hits=%d storeCalls=%d audit=%d, want 0 for all", g.hits.Load(), store.calls, len(g.audit.limited))
	}
}

// A cosigner refuses a target on a network it doesn't know before its policy
// or external checks run: a bad request, as on /sign, not a policy rejection,
// and nothing is audited. A network the node's own mapping adds is known, and
// the request goes on to the policy.
func TestCosignerRefusesAnUnknownNetworkBeforePolicy(t *testing.T) {
	const custom = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	networks, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{custom: "devnet-x"})
	if err != nil {
		t.Fatal(err)
	}
	g := newExternalGate(t)
	g.svc.Planner = &Planner{Snapshot: cosignerTestPlanner.Snapshot, GenesisHashResolver: networks}
	// A node compiles its policies with the mapping it checks networks with.
	g.cfg.GenesisHashResolver = networks
	planOn := func(genesis types.Digest) *ComponentSignPlan {
		txn := testnetPaymentTransaction(t, g.source, g.allowed, 1)
		txn.GenesisHash = genesis
		return mustPrepareComponentSigning(t, componentPlanRequest{
			RequestID:     "cmp-cosigner-unknown-network",
			ComponentKey:  testFalconComponentSelector(t, 0xab),
			Group:         componentTestGroup(t, []string{txnutil.EncodeWithPrefixHex(txn)}),
			TargetIndices: []int{0},
		})
	}

	signErr := g.svc.runCosignerGates(context.Background(), planOn(types.Digest{0xee}))
	if signErr == nil || signErr.Kind != ErrorBadRequest || !strings.Contains(signErr.Message, "unrecognized genesis hash ee00") {
		t.Fatalf("runCosignerGates(unknown network) = %#v, want a bad request naming the genesis hash", signErr)
	}
	if g.hits.Load() != 0 || len(g.audit.limited) != 0 {
		t.Fatalf("hits=%d audit=%d, want neither before policy", g.hits.Load(), len(g.audit.limited))
	}

	// The policy routes testnet only, so the known custom network reaches it
	// and is refused there, audited.
	signErr = g.svc.runCosignerGates(context.Background(), planOn(verdictGenesis(t, custom)))
	if signErr == nil || signErr.Kind != ErrorForbidden || !strings.Contains(signErr.Message, policy.TransferRoutingRouteMissRuleID) {
		t.Fatalf("runCosignerGates(custom network) = %#v, want the policy's route miss", signErr)
	}
	if len(g.audit.limited) != 1 {
		t.Fatalf("audit = %d, want the policy rejection recorded", len(g.audit.limited))
	}
}

// Network parameter validation runs before signer invariants: a group that
// both violates cross-slot network rules (mixed genesis or disjoint windows)
// and breaks a signer invariant (such as a nonparticipating keyreg) must get
// an unaudited bad_request rather than an audited invariant refusal.
func TestCosignerRefusesNetworkParamErrorsBeforeSignerInvariants(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*types.Transaction, *types.Transaction)
		wantText string
	}{
		{
			name: "mixed genesis with nonparticipating keyreg",
			mutate: func(_, txn1 *types.Transaction) {
				txn1.GenesisHash = verdictGenesis(t, apconfig.AlgorandMainnetGenesisHash)
				txn1.GenesisID = "mainnet-v1.0"
			},
			wantText: "different genesis hash",
		},
		{
			name: "disjoint validity windows with nonparticipating keyreg",
			mutate: func(txn0, txn1 *types.Transaction) {
				txn0.FirstValid, txn0.LastValid = 1000, 1100
				txn1.FirstValid, txn1.LastValid = 1200, 1300
			},
			wantText: "validity windows do not overlap",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newExternalGate(t)
			txn0 := testnetPaymentTransaction(t, g.source, g.allowed, 1)
			txn1 := types.Transaction{
				Type: types.KeyRegistrationTx,
				Header: types.Header{
					Sender:      txn0.Sender,
					Fee:         1_000,
					FirstValid:  txn0.FirstValid,
					LastValid:   txn0.LastValid,
					GenesisID:   txn0.GenesisID,
					GenesisHash: txn0.GenesisHash,
				},
				KeyregTxnFields: types.KeyregTxnFields{Nonparticipation: true},
			}
			tc.mutate(&txn0, &txn1)
			gid, err := crypto.ComputeGroupID([]types.Transaction{txn0, txn1})
			if err != nil {
				t.Fatalf("ComputeGroupID() error = %v", err)
			}
			txn0.Group = gid
			txn1.Group = gid

			plan := mustPrepareComponentSigning(t, componentPlanRequest{
				RequestID:     "cmp-cosigner-network-before-invariant",
				ComponentKey:  testFalconComponentSelector(t, 0xab),
				Group:         componentTestGroup(t, []string{txnutil.EncodeWithPrefixHex(txn0), txnutil.EncodeWithPrefixHex(txn1)}),
				TargetIndices: []int{0, 1},
			})
			gateErr := g.svc.runCosignerGates(context.Background(), plan)
			if gateErr == nil || gateErr.Kind != ErrorBadRequest || !strings.Contains(gateErr.Message, tc.wantText) {
				t.Fatalf("runCosignerGates() error = %#v, want bad_request mentioning %q", gateErr, tc.wantText)
			}
			if g.hits.Load() != 0 || len(g.audit.limited) != 0 || len(g.audit.rejected) != 0 {
				t.Fatalf("hits=%d limited=%d rejected=%d, want 0 for all", g.hits.Load(), len(g.audit.limited), len(g.audit.rejected))
			}
		})
	}
}

// A multi-target group whose validity windows do not overlap can never confirm
// on chain and is refused before policy evaluation or external checks.
func TestCosignerRefusesNonOverlappingValidityWindows(t *testing.T) {
	g := newExternalGate(t)
	txn0 := testnetPaymentTransaction(t, g.source, g.allowed, 1)
	txn1 := testnetPaymentTransaction(t, g.source, g.allowed, 2)
	txn0.FirstValid, txn0.LastValid = 1000, 1100
	txn1.FirstValid, txn1.LastValid = 1200, 1300
	gid, err := crypto.ComputeGroupID([]types.Transaction{txn0, txn1})
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	txn0.Group = gid
	txn1.Group = gid

	plan := mustPrepareComponentSigning(t, componentPlanRequest{
		RequestID:     "cmp-cosigner-disjoint-window",
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		Group:         componentTestGroup(t, []string{txnutil.EncodeWithPrefixHex(txn0), txnutil.EncodeWithPrefixHex(txn1)}),
		TargetIndices: []int{0, 1},
	})
	gateErr := g.svc.runCosignerGates(context.Background(), plan)
	if gateErr == nil || gateErr.Kind != ErrorBadRequest || !strings.Contains(gateErr.Message, "validity windows do not overlap") {
		t.Fatalf("runCosignerGates(disjoint window) error = %#v, want bad request for disjoint windows", gateErr)
	}
	if g.hits.Load() != 0 || len(g.audit.limited) != 0 {
		t.Fatalf("hits=%d audit=%d, want 0 for both", g.hits.Load(), len(g.audit.limited))
	}
}

func boolPtr(v bool) *bool { return &v }
