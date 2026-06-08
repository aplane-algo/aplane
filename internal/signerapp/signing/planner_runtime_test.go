// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

type stubPlannerDeps struct {
	keyTypes   map[string]string
	keyFiles   map[string]string
	lsigSizes  map[string]int
	minTxnFee  uint64
	minTxnFees map[types.Digest]uint64
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
		KeyFiles:  keyFiles,
		KeyTypes:  d.keyTypes,
		LSigSizes: d.lsigSizes,
	}
}

func (d stubPlannerDeps) MinTxnFee(genesisHash types.Digest) uint64 {
	if d.minTxnFees != nil {
		return d.minTxnFees[genesisHash]
	}
	return d.minTxnFee
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

func TestVerifySignableKeysRejectsSentryKeyTypes(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
		want    string
	}{
		{
			name:    "ed25519 component key",
			keyType: keytypes.SentryComponentEd25519V1,
			want:    sentryComponentSignRejectMessage,
		},
		{
			name:    "falcon component key",
			keyType: keytypes.SentryComponentFalcon1024V1,
			want:    sentryComponentSignRejectMessage,
		},
		{
			name:    "guarded account",
			keyType: keytypes.GuardedFalcon1024SentryEd25519V1,
			want:    guardedAccountSignRejectMessage,
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
			keyTypes:  map[string]string{authAddr: "ed25519"},
			lsigSizes: map[string]int{authAddr: 100},
			minTxnFee: 1000,
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
		keyTypes:  map[string]string{authAddr: "ed25519"},
		minTxnFee: 1000,
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

func TestCalculateDummies_PreGroupedImmutability(t *testing.T) {
	const largeLsigSize = 2500
	const addr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	preGroupID := types.Digest{1, 2, 3}
	emptyGroup := types.Digest{}

	tests := []struct {
		name         string
		isPreGrouped bool
		groupID      types.Digest
		lsigSize     int
		txnCount     int
		wantErr      bool
		wantDummies  int
	}{
		{
			name:         "pre-grouped with insufficient budget is rejected",
			isPreGrouped: true,
			groupID:      preGroupID,
			lsigSize:     largeLsigSize,
			txnCount:     1,
			wantErr:      true,
		},
		{
			name:         "pre-grouped with sufficient budget succeeds",
			isPreGrouped: true,
			groupID:      preGroupID,
			lsigSize:     500,
			txnCount:     1,
			wantDummies:  0,
		},
		{
			name:         "ungrouped with insufficient budget adds dummies",
			isPreGrouped: false,
			groupID:      emptyGroup,
			lsigSize:     largeLsigSize,
			txnCount:     1,
			wantDummies:  2,
		},
		{
			name:         "ungrouped with sufficient budget needs no dummies",
			isPreGrouped: false,
			groupID:      emptyGroup,
			lsigSize:     800,
			txnCount:     1,
			wantDummies:  0,
		},
		{
			name:         "pre-grouped multi-txn with sufficient budget succeeds",
			isPreGrouped: true,
			groupID:      preGroupID,
			lsigSize:     900,
			txnCount:     3,
			wantDummies:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := stubPlannerDeps{
				keyTypes:  map[string]string{addr: "ed25519"},
				lsigSizes: map[string]int{addr: tt.lsigSize},
			}

			requests := make([]signerapi.SignRequest, tt.txnCount)
			txns := make([]types.Transaction, tt.txnCount)
			for i := 0; i < tt.txnCount; i++ {
				requests[i] = signerapi.SignRequest{AuthAddress: addr, TxnBytesHex: "deadbeef"}
				txns[i] = makePlannerTxn(tt.groupID)
			}

			dummies, _, err := calculateDummies(nil, deps.Snapshot("default"), "default", requests, txns, map[int]bool{}, map[int]bool{}, false, tt.isPreGrouped)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dummies != tt.wantDummies {
				t.Errorf("expected %d dummies, got %d", tt.wantDummies, dummies)
			}
		})
	}
}

// TestCalculateDummies_PreGroupedMixedForeignAndSign pins the server-side
// assumption behind mixed guarded groups (Strategy A): a pre-grouped group whose
// non-signed positions are foreign with accurate lsig_size hints is accepted
// without adding dummies when the client already supplied enough budget, and is
// rejected early when it did not. This is the path apshell exercises for a group
// that mixes a guarded sender with an ordinary signer-managed sender.
func TestCalculateDummies_PreGroupedMixedForeignAndSign(t *testing.T) {
	const falconAddr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	preGroupID := types.Digest{1, 2, 3}

	// Index 0: non-guarded falcon signed by this signer (1500 bytes).
	// Index 1: guarded account, foreign with an honest 1500-byte hint.
	deps := stubPlannerDeps{
		keyTypes:  map[string]string{falconAddr: "aplane.falcon1024.v1"},
		lsigSizes: map[string]int{falconAddr: 1500},
	}

	t.Run("honest hints with enough dummies add no further dummies", func(t *testing.T) {
		// 1500 (sign) + 1500 (foreign hint) = 3000 demand; 3 txns * 1000 = 3000
		// budget after the client added one dummy. Exact parity → 0 dummies.
		requests := []signerapi.SignRequest{
			{AuthAddress: falconAddr, TxnBytesHex: "deadbeef"},
			{TxnBytesHex: "deadbeef", LsigSize: 1500},
			{TxnBytesHex: "deadbeef"},
		}
		txns := []types.Transaction{makePlannerTxn(preGroupID), makePlannerTxn(preGroupID), makePlannerTxn(preGroupID)}
		foreign := map[int]bool{1: true, 2: true}

		dummies, _, err := calculateDummies(nil, deps.Snapshot("default"), "default", requests, txns, map[int]bool{}, foreign, false, true)
		if err != nil {
			t.Fatalf("calculateDummies() error = %v, want accepted", err)
		}
		if dummies != 0 {
			t.Fatalf("dummies = %d, want 0 (pre-grouped budget already satisfied)", dummies)
		}
	})

	t.Run("honest hints without enough dummies are rejected early", func(t *testing.T) {
		// 3000 demand but only 2 txns * 1000 = 2000 budget (client under-sized) →
		// the signer rejects at sign time rather than mis-signing.
		requests := []signerapi.SignRequest{
			{AuthAddress: falconAddr, TxnBytesHex: "deadbeef"},
			{TxnBytesHex: "deadbeef", LsigSize: 1500},
		}
		txns := []types.Transaction{makePlannerTxn(preGroupID), makePlannerTxn(preGroupID)}
		foreign := map[int]bool{1: true}

		_, _, err := calculateDummies(nil, deps.Snapshot("default"), "default", requests, txns, map[int]bool{}, foreign, false, true)
		if err == nil {
			t.Fatal("calculateDummies() error = nil, want pre-grouped budget rejection")
		}
		if !strings.Contains(err.Error(), "pre-grouped") {
			t.Fatalf("calculateDummies() error = %q, want pre-grouped rejection", err.Error())
		}
	})
}

func TestCalculateDummiesRejectsNegativeForeignLSigSize(t *testing.T) {
	const authAddr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	requests := []signerapi.SignRequest{
		{AuthAddress: authAddr, TxnBytesHex: "deadbeef"},
		{TxnBytesHex: "deadbeef", LsigSize: -1},
	}
	txns := []types.Transaction{makePlannerTxn(types.Digest{}), makePlannerTxn(types.Digest{})}
	foreign := map[int]bool{1: true}
	snapshot := PlannerIdentitySnapshot{KeyTypes: map[string]string{authAddr: "ed25519"}}

	_, _, err := calculateDummies(nil, snapshot, "default", requests, txns, map[int]bool{}, foreign, false, false)
	if err == nil {
		t.Fatal("calculateDummies() error = nil, want negative lsig_size failure")
	}
	if !strings.Contains(err.Error(), "invalid negative lsig_size") {
		t.Fatalf("calculateDummies() error = %q, want negative lsig_size failure", err.Error())
	}
}

func TestCalculateDummiesRejectsLSigSizeOverflow(t *testing.T) {
	const authAddr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const maxInt = int(^uint(0) >> 1)

	requests := []signerapi.SignRequest{
		{AuthAddress: authAddr, TxnBytesHex: "deadbeef"},
		{TxnBytesHex: "deadbeef", LsigSize: maxInt},
		{TxnBytesHex: "deadbeef", LsigSize: 1},
	}
	txns := []types.Transaction{
		makePlannerTxn(types.Digest{}),
		makePlannerTxn(types.Digest{}),
		makePlannerTxn(types.Digest{}),
	}
	foreign := map[int]bool{1: true, 2: true}
	snapshot := PlannerIdentitySnapshot{KeyTypes: map[string]string{authAddr: "ed25519"}}

	_, _, err := calculateDummies(nil, snapshot, "default", requests, txns, map[int]bool{}, foreign, false, false)
	if err == nil {
		t.Fatal("calculateDummies() error = nil, want overflow failure")
	}
	if !strings.Contains(err.Error(), "overflows") {
		t.Fatalf("calculateDummies() error = %q, want overflow failure", err.Error())
	}
}

func TestValidateGroupConsistency(t *testing.T) {
	groupA := types.Digest{1, 2, 3}
	groupB := types.Digest{4, 5, 6}
	empty := types.Digest{}

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
			txns:        []types.Transaction{makePlannerTxn(groupA)},
			wantGrouped: true,
		},
		{
			name: "multiple matching pre-grouped transactions",
			txns: []types.Transaction{
				makePlannerTxn(groupA),
				makePlannerTxn(groupA),
			},
			wantGrouped: true,
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

func TestBuildFinalGroupUsesTransactionGenesisHashForMinFee(t *testing.T) {
	genesisHash := types.Digest{9, 8, 7}
	sender := types.Address{1}
	receiver := types.Address{2}
	txns := []types.Transaction{{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      sender,
			Fee:         1000,
			FirstValid:  10,
			LastValid:   20,
			GenesisID:   "custom-v1",
			GenesisHash: genesisHash,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: receiver,
			Amount:   1,
		},
	}}
	deps := stubPlannerDeps{
		minTxnFee: 1000,
		minTxnFees: map[types.Digest]uint64{
			genesisHash: 2000,
		},
	}

	allTxns, dummyTxns, feeInfo, _, err := buildFinalGroup(deps, nil, txns, 2, []int{0}, false)
	if err != nil {
		t.Fatalf("buildFinalGroup() error = %v", err)
	}
	if len(dummyTxns) != 2 {
		t.Fatalf("dummy count = %d, want 2", len(dummyTxns))
	}
	if feeInfo.TotalFees != 4000 {
		t.Fatalf("TotalFees = %d, want 4000 from custom min fee", feeInfo.TotalFees)
	}
	if got := uint64(allTxns[0].Fee); got != 5000 {
		t.Fatalf("signed txn fee = %d, want original 1000 + 4000 dummy fees", got)
	}
	for i, dummy := range dummyTxns {
		if dummy.GenesisHash != genesisHash {
			t.Fatalf("dummy %d genesis hash = %x, want %x", i, dummy.GenesisHash[:], genesisHash[:])
		}
	}
}
