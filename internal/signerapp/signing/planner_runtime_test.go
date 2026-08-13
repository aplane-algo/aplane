// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/witness"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

type stubPlannerDeps struct {
	keyTypes    map[string]string
	keyFiles    map[string]string
	keyMetadata map[string]PlannerKeyMetadata
}

func (d stubPlannerDeps) Snapshot(identityID string) PlannerIdentitySnapshot {
	keyFiles := d.keyFiles
	if keyFiles == nil && d.keyTypes != nil {
		keyFiles = make(map[string]string, len(d.keyTypes))
		for address := range d.keyTypes {
			keyFiles[address] = "keys/" + address + ".key"
		}
	}
	return PlannerIdentitySnapshot{
		KeyFiles:    keyFiles,
		KeyTypes:    d.keyTypes,
		KeyMetadata: d.keyMetadata,
	}
}

type countingSnapshotPlannerDeps struct {
	stubPlannerDeps
	calls int
}

func (d *countingSnapshotPlannerDeps) Snapshot(identityID string) PlannerIdentitySnapshot {
	d.calls++
	return d.stubPlannerDeps.Snapshot(identityID)
}

type captureAuditLog struct {
	entries []captureAuditEntry
}

type captureAuditEntry struct {
	identityID  string
	authAddress string
	txnSender   string
	txnType     string
	details     string
}

func (a *captureAuditLog) LogSignRequest(identityID, authAddress, txnSender, txnType, details string) {
	a.entries = append(a.entries, captureAuditEntry{
		identityID:  identityID,
		authAddress: authAddress,
		txnSender:   txnSender,
		txnType:     txnType,
		details:     details,
	})
}

func TestCalculateLogicSigResourcesV42SeparatesProgramArgumentsAndOpcode(t *testing.T) {
	profile := lsigresource.Profile{
		ProgramBytes: 4_500,
		Default: &lsigresource.PathProfile{
			ArgumentBytes: 1_423,
			MaxOpcodeCost: 39_999,
		},
	}
	snapshot := PlannerIdentitySnapshot{
		KeyMetadata: map[string]PlannerKeyMetadata{
			"LSIG": {LogicSigResources: &profile},
		},
	}
	plan, indices, err := calculateLogicSigResources(
		nil,
		snapshot,
		"default",
		[]signerapi.SignRequest{{AuthAddress: "LSIG"}},
		[]types.Transaction{{}},
		nil,
		map[int]bool{},
		map[int]bool{},
		nil,
		false,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if plan.DummyCount != 1 || plan.GroupSize != 2 {
		t.Fatalf("resource plan = %#v, want one dummy and group size two", plan)
	}
	if plan.TotalArgumentBytes != 1_423 || plan.TotalMaxOpcodeCost != 40_000 {
		t.Fatalf("resource totals = %#v", plan)
	}
	if len(indices) != 1 || indices[0] != 0 {
		t.Fatalf("fee-capable LogicSig indices = %v, want [0]", indices)
	}
}

// LogicSig planning is governed by the compiled v42 contract and therefore
// does not depend on a reachable per-network algod.
func TestCalculateLogicSigResourcesUsesCompiledConsensus(t *testing.T) {
	profile := lsigresource.Profile{
		ProgramBytes: 4_500,
		Default:      &lsigresource.PathProfile{ArgumentBytes: 1_423, MaxOpcodeCost: 39_999},
	}
	snapshot := PlannerIdentitySnapshot{
		KeyMetadata: map[string]PlannerKeyMetadata{"LSIG": {LogicSigResources: &profile}},
	}
	plan, _, err := calculateLogicSigResources(
		nil,
		snapshot,
		"default",
		[]signerapi.SignRequest{{AuthAddress: "LSIG"}},
		[]types.Transaction{{}},
		nil,
		map[int]bool{},
		map[int]bool{},
		nil,
		false,
		false,
	)
	if err != nil {
		t.Fatalf("calculateLogicSigResources() error = %v, want fixed-contract success", err)
	}
	if plan.GroupSize != 2 || plan.DummyCount != 1 {
		t.Fatalf("resource plan = %#v, want compiled v42 group size 2", plan)
	}
}

func TestCalculateLogicSigResourcesAllowsNonLogicSigGroup(t *testing.T) {
	_, _, err := calculateLogicSigResources(
		nil,
		PlannerIdentitySnapshot{},
		"default",
		[]signerapi.SignRequest{{AuthAddress: "ED25519"}},
		[]types.Transaction{{}},
		nil,
		map[int]bool{},
		map[int]bool{},
		nil,
		false,
		false,
	)
	if err != nil {
		t.Fatalf("calculateLogicSigResources() error = %v, want success", err)
	}
}

func TestCalculateLogicSigResourcesRejectsOversizedNonLogicSigGroup(t *testing.T) {
	requests := make([]signerapi.SignRequest, 17)
	txns := make([]types.Transaction, len(requests))
	_, _, err := calculateLogicSigResources(
		nil,
		PlannerIdentitySnapshot{},
		"default",
		requests,
		txns,
		nil,
		map[int]bool{},
		map[int]bool{},
		nil,
		false,
		true,
	)
	if err == nil || !strings.Contains(err.Error(), "maximum is 16") {
		t.Fatalf("calculateLogicSigResources() error = %v, want maximum-group rejection", err)
	}
}

func TestCalculateLogicSigResourcesRejectsOrphanPassthroughLogicSigFields(t *testing.T) {
	encoded := msgpack.Encode(types.SignedTxn{
		Lsig: types.LogicSig{Args: [][]byte{{1}}},
	})
	_, _, err := calculateLogicSigResources(
		nil,
		PlannerIdentitySnapshot{},
		"default",
		[]signerapi.SignRequest{{SignedTxnHex: hex.EncodeToString(encoded)}},
		[]types.Transaction{{}},
		nil,
		map[int]bool{0: true},
		map[int]bool{},
		map[int][]byte{0: encoded},
		true,
		true,
	)
	if err == nil || !strings.Contains(err.Error(), "require a non-empty program") {
		t.Fatalf("calculateLogicSigResources() error = %v, want orphan-field rejection", err)
	}
}

func TestPassthroughLogicSigUsageRequiresReviewedResources(t *testing.T) {
	encoded := msgpack.Encode(types.SignedTxn{
		Lsig: types.LogicSig{
			Logic: []byte{1, 2, 3},
			Args:  [][]byte{{4, 5}},
		},
	})

	t.Run("missing declaration", func(t *testing.T) {
		_, _, err := passthroughLogicSigUsage(encoded, nil, 1)
		if err == nil || !strings.Contains(err.Error(), "requires lsig_resources") {
			t.Fatalf("passthroughLogicSigUsage() error = %v, want declaration rejection", err)
		}
	})

	t.Run("observed sizes must match", func(t *testing.T) {
		_, _, err := passthroughLogicSigUsage(encoded, &signerapi.LogicSigResourceUsage{
			ProgramBytes:  4,
			ArgumentBytes: 2,
			MaxOpcodeCost: 20_000,
		}, 1)
		if err == nil || !strings.Contains(err.Error(), "program_bytes is 4, observed 3") {
			t.Fatalf("passthroughLogicSigUsage() error = %v, want program-size rejection", err)
		}
	})

	t.Run("declaration on non-LogicSig", func(t *testing.T) {
		plain := msgpack.Encode(types.SignedTxn{})
		_, _, err := passthroughLogicSigUsage(plain, &signerapi.LogicSigResourceUsage{
			ProgramBytes:  1,
			MaxOpcodeCost: 1,
		}, 1)
		if err == nil || !strings.Contains(err.Error(), "without LogicSig authorization") {
			t.Fatalf("passthroughLogicSigUsage() error = %v, want orphan-declaration rejection", err)
		}
	})

	t.Run("uses declared opcode ceiling", func(t *testing.T) {
		usage, present, err := passthroughLogicSigUsage(encoded, &signerapi.LogicSigResourceUsage{
			ProgramBytes:  3,
			ArgumentBytes: 2,
			MaxOpcodeCost: 40_000,
		}, 1)
		if err != nil {
			t.Fatalf("passthroughLogicSigUsage() error = %v", err)
		}
		if !present || usage.MaxOpcodeCost != 40_000 {
			t.Fatalf("passthrough usage = %#v, present=%v; want declared opcode ceiling", usage, present)
		}
	})
}

func TestCalculateLogicSigResourcesRejectsUnderprovisionedImmutablePassthrough(t *testing.T) {
	encoded := msgpack.Encode(types.SignedTxn{
		Lsig: types.LogicSig{Logic: []byte{1}},
	})
	_, _, err := calculateLogicSigResources(
		nil,
		PlannerIdentitySnapshot{},
		"default",
		[]signerapi.SignRequest{{
			SignedTxnHex: hex.EncodeToString(encoded),
			LsigResources: &signerapi.LogicSigResourceUsage{
				ProgramBytes:  1,
				MaxOpcodeCost: 40_000,
			},
		}},
		[]types.Transaction{{}},
		nil,
		map[int]bool{0: true},
		map[int]bool{},
		map[int][]byte{0: encoded},
		true,
		true,
	)
	if err == nil || !strings.Contains(err.Error(), "requires 2 additional dummy transaction") {
		t.Fatalf("calculateLogicSigResources() error = %v, want immutable-group dummy rejection", err)
	}
}

func TestVerifySignableKeysRequiresKeyTypeMetadata(t *testing.T) {
	const addr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	requests := []signerapi.SignRequest{{
		AuthAddress: addr,
		TxnBytesHex: "deadbeef",
	}}

	snapshot := PlannerIdentitySnapshot{
		KeyFiles: map[string]string{addr: "keys/" + addr + ".key"},
	}
	count, err := verifySignableKeys(nil, snapshot, "default", requests, map[int]bool{}, map[int]bool{})
	if count != 0 {
		t.Fatalf("verifySignableKeys() count = %d, want 0", count)
	}
	if err == nil {
		t.Fatal("verifySignableKeys() error = nil, want fail-closed metadata error")
		return
	}
	if err.Kind != ErrorInternal {
		t.Fatalf("verifySignableKeys() error kind = %q, want %q", err.Kind, ErrorInternal)
	}
	if got := err.Error(); got == "" || !strings.Contains(got, "missing key type metadata") {
		t.Fatalf("verifySignableKeys() error = %q, want missing key type metadata", got)
	}
}

func TestVerifySignableKeysRequiresKeyFileInSnapshot(t *testing.T) {
	const addr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	requests := []signerapi.SignRequest{{
		AuthAddress: addr,
		TxnBytesHex: "deadbeef",
	}}
	snapshot := PlannerIdentitySnapshot{
		KeyTypes: map[string]string{addr: "ed25519"},
	}

	count, err := verifySignableKeys(nil, snapshot, "default", requests, map[int]bool{}, map[int]bool{})
	if count != 0 {
		t.Fatalf("verifySignableKeys() count = %d, want 0", count)
	}
	if err == nil {
		t.Fatal("verifySignableKeys() error = nil, want missing key failure")
		return
	}
	if err.Kind != ErrorBadRequest {
		t.Fatalf("verifySignableKeys() error kind = %q, want %q", err.Kind, ErrorBadRequest)
	}
	if got := err.Error(); got == "" || !strings.Contains(got, "no key found for address") {
		t.Fatalf("verifySignableKeys() error = %q, want missing key failure", got)
	}
}

func TestVerifySignableKeysRejectsWitnessKeyTypes(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
		want    string
	}{
		{
			name:    "Falcon sentry key",
			keyType: witness.Falcon1024V1,
			want:    sentryComponentSignRejectMessage,
		},
		{
			name:    "falcon sentry key",
			keyType: witness.Falcon1024V1,
			want:    sentryComponentSignRejectMessage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := types.Address{1}.String()
			requests := []signerapi.SignRequest{{
				AuthAddress: addr,
				TxnBytesHex: "deadbeef",
			}}
			snapshot := PlannerIdentitySnapshot{
				KeyFiles: map[string]string{addr: "keys/" + addr + ".key"},
				KeyTypes: map[string]string{addr: tt.keyType},
			}

			count, err := verifySignableKeys(nil, snapshot, "default", requests, map[int]bool{}, map[int]bool{})
			if count != 0 {
				t.Fatalf("verifySignableKeys() count = %d, want 0", count)
			}
			if err == nil {
				t.Fatal("verifySignableKeys() error = nil, want sentry key type rejection")
				return
			}
			if err.Kind != ErrorBadRequest {
				t.Fatalf("error kind = %q, want %q", err.Kind, ErrorBadRequest)
			}
			if !strings.Contains(err.Message, tt.want) {
				t.Fatalf("error message = %q, want %q", err.Message, tt.want)
			}
		})
	}
}

func TestVerifySignableKeysAllowsGuardedAccountPlanning(t *testing.T) {
	addr := types.Address{1}.String()
	requests := []signerapi.SignRequest{{
		AuthAddress: addr,
		TxnBytesHex: "deadbeef",
	}}
	snapshot := PlannerIdentitySnapshot{
		KeyFiles: map[string]string{addr: "keys/" + addr + ".key"},
		KeyTypes: map[string]string{addr: keytypes.GuardedFalcon1024Sentry1024V1},
	}

	count, err := verifySignableKeys(nil, snapshot, "default", requests, map[int]bool{}, map[int]bool{})
	if err != nil {
		t.Fatalf("verifySignableKeys() error = %v, want guarded planning to succeed", err)
	}
	if count != 1 {
		t.Fatalf("verifySignableKeys() count = %d, want 1", count)
	}
}

func TestPlannerUsesSingleIdentitySnapshot(t *testing.T) {
	var genesisHash types.Digest
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{
		base64.StdEncoding.EncodeToString(genesisHash[:]): "snapshot_test",
	})
	if err != nil {
		t.Fatalf("NewGenesisHashNetworkResolver() error = %v", err)
	}

	authAddr := types.Address{1}.String()
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      types.Address{2},
			Fee:         1_000,
			FirstValid:  1,
			LastValid:   10,
			GenesisHash: genesisHash,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: types.Address{3},
			Amount:   1,
		},
	}

	deps := &countingSnapshotPlannerDeps{
		stubPlannerDeps: stubPlannerDeps{
			keyTypes: map[string]string{authAddr: "ed25519"},
		},
	}
	planner := NewPlanner(deps, PlannerOptions{GenesisHashResolver: resolver})

	plan, planErr := planner.PlanGroup("default", signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: authAddr,
			TxnBytesHex: hex.EncodeToString(msgpack.Encode(txn)),
		}},
	})
	if planErr != nil {
		t.Fatalf("PlanGroup() error = %v", planErr)
	}
	if deps.calls != 1 {
		t.Fatalf("Snapshot() calls = %d, want 1", deps.calls)
	}
	if got := plan.AuthKeyTypes[0]; got != "ed25519" {
		t.Fatalf("AuthKeyTypes[0] = %q, want ed25519", got)
	}
	if !plan.KnownAddresses[authAddr] {
		t.Fatalf("KnownAddresses[%q] = false, want true from planning snapshot", authAddr)
	}
}

func TestPlannerAuditsDecodedTxnSender(t *testing.T) {
	var genesisHash types.Digest
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{
		base64.StdEncoding.EncodeToString(genesisHash[:]): "audit_test",
	})
	if err != nil {
		t.Fatalf("NewGenesisHashNetworkResolver() error = %v", err)
	}

	authAddr := types.Address{1}.String()
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      types.Address{2},
			Fee:         1_000,
			FirstValid:  1,
			LastValid:   10,
			GenesisHash: genesisHash,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: types.Address{3},
			Amount:   1,
		},
	}
	audit := &captureAuditLog{}
	deps := stubPlannerDeps{
		keyTypes: map[string]string{authAddr: "ed25519"},
	}
	planner := NewPlanner(deps, PlannerOptions{
		AuditLog:            audit,
		GenesisHashResolver: resolver,
		GenerateTxnDescription: func(txnBytesHex string) string {
			return "decoded transaction"
		},
	})

	_, planErr := planner.PlanGroup("default", signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: authAddr,
			TxnSender:   "caller-spoofed-sender",
			TxnBytesHex: hex.EncodeToString(msgpack.Encode(txn)),
		}},
	})
	if planErr != nil {
		t.Fatalf("PlanGroup() error = %v", planErr)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(audit.entries))
	}
	if got, want := audit.entries[0].txnSender, txn.Sender.String(); got != want {
		t.Fatalf("audit txn sender = %q, want decoded sender %q", got, want)
	}
	if got := audit.entries[0].txnSender; got == "caller-spoofed-sender" {
		t.Fatal("audit used caller-supplied txn sender")
	}
}

func makePlannerTxn(groupID types.Digest) types.Transaction {
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Group: groupID,
		},
	}
}

// groupedPlannerTxns builds n distinct transactions sharing a real group ID
// (computed via ComputeGroupID), so validateGroupConsistency's group-ID
// recomputation accepts them.
func groupedPlannerTxns(t *testing.T, n int) []types.Transaction {
	t.Helper()
	txns := make([]types.Transaction, n)
	for i := range txns {
		txns[i] = types.Transaction{
			Type:   types.PaymentTx,
			Header: types.Header{Sender: types.Address{byte(i + 1)}},
		}
	}
	gid, err := algocrypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	for i := range txns {
		txns[i].Group = gid
	}
	return txns
}

func TestValidateGroupConsistency(t *testing.T) {
	groupA := types.Digest{1, 2, 3}
	groupB := types.Digest{4, 5, 6}
	empty := types.Digest{}

	// Pre-grouped cases must carry a group ID that actually matches the
	// transactions, since validateGroupConsistency now recomputes and verifies
	// it. A fabricated group ID (groupA below) is used only for the negative
	// "members disagree" cases where the recompute is never reached.
	singleGrouped := groupedPlannerTxns(t, 1)
	multiGrouped := groupedPlannerTxns(t, 2)

	tests := []struct {
		name           string
		txns           []types.Transaction
		hasPassthrough bool
		wantGrouped    bool
		wantErr        bool
	}{
		{
			name:        "single ungrouped transaction",
			txns:        []types.Transaction{makePlannerTxn(empty)},
			wantGrouped: false,
		},
		{
			name:        "single pre-grouped transaction",
			txns:        singleGrouped,
			wantGrouped: true,
		},
		{
			name:        "multiple matching pre-grouped transactions",
			txns:        multiGrouped,
			wantGrouped: true,
		},
		{
			name: "pre-grouped with a forged group ID is rejected",
			txns: []types.Transaction{
				makePlannerTxn(groupA),
				makePlannerTxn(groupA),
			},
			wantErr: true,
		},
		{
			name: "multiple ungrouped transactions",
			txns: []types.Transaction{
				makePlannerTxn(empty),
				makePlannerTxn(empty),
			},
			wantGrouped: false,
		},
		{
			name: "mismatched group IDs rejected",
			txns: []types.Transaction{
				makePlannerTxn(groupA),
				makePlannerTxn(groupB),
			},
			wantErr: true,
		},
		{
			name: "mixed grouped and ungrouped rejected",
			txns: []types.Transaction{
				makePlannerTxn(groupA),
				makePlannerTxn(empty),
			},
			wantErr: true,
		},
		{
			name: "passthrough requires pre-grouped",
			txns: []types.Transaction{
				makePlannerTxn(empty),
			},
			hasPassthrough: true,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isPreGrouped, err := validateGroupConsistency(tt.txns, tt.hasPassthrough, nil)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if isPreGrouped != tt.wantGrouped {
				t.Errorf("expected isPreGrouped=%v, got %v", tt.wantGrouped, isPreGrouped)
			}
		})
	}
}

func TestPlanGroupRejectsBoundedFeeCeilingAfterDummyPooling(t *testing.T) {
	var genesisHash types.Digest
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{
		base64.StdEncoding.EncodeToString(genesisHash[:]): "bounded_fee_test",
	})
	if err != nil {
		t.Fatalf("NewGenesisHashNetworkResolver() error = %v", err)
	}

	authAddr := types.Address{1}.String()
	metadata := testBoundedMetadata(t, "")
	metadata.MaxFee = 1_000
	deps := stubPlannerDeps{
		keyTypes: map[string]string{authAddr: "aplane.falcon1024-bounded.v1"},
		// The v42 program surcharge needs a signer-side fee increase, but the
		// bounded path permits no increase above the client-supplied base fee.
		keyMetadata: map[string]PlannerKeyMetadata{authAddr: {
			Category:             "dsa_lsig",
			PublicKeyHex:         "aabb",
			BoundedAuthorization: metadata,
			LogicSigResources: &lsigresource.Profile{
				ProgramBytes:  2_500,
				Spend:         &lsigresource.PathProfile{MaxOpcodeCost: 1},
				SpendingRekey: &lsigresource.PathProfile{MaxOpcodeCost: 1},
				AdminRekey:    &lsigresource.PathProfile{MaxOpcodeCost: 1},
			},
		}},
	}
	planner := NewPlanner(deps, PlannerOptions{GenesisHashResolver: resolver})

	makeRequest := func(fee uint64) signerapi.GroupSignRequest {
		txn := types.Transaction{
			Type: types.PaymentTx,
			Header: types.Header{
				Sender:      types.Address{2},
				Fee:         types.MicroAlgos(fee),
				FirstValid:  1,
				LastValid:   10,
				GenesisHash: genesisHash,
			},
			PaymentTxnFields: types.PaymentTxnFields{
				Receiver: types.Address{3},
				Amount:   1,
			},
		}
		return signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{
			AuthAddress: authAddr,
			TxnBytesHex: hex.EncodeToString(msgpack.Encode(txn)),
		}}}
	}

	// The starting fee satisfies the ordinary transaction requirement, but the
	// bounded account cannot absorb the priced-program contribution.
	_, planErr := planner.PlanGroup("default", makeRequest(1000))
	if planErr == nil {
		t.Fatal("PlanGroup() error = nil, want bounded fee-capacity rejection")
	}
	if !strings.Contains(planErr.Message, "exceeds signer-controlled bounded fee capacity") {
		t.Fatalf("PlanGroup() error = %q, want bounded fee-capacity rejection", planErr.Message)
	}
}
