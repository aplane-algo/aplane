// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapi"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/witness"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

type stubPlannerDeps struct {
	keyTypes         map[string]string
	keyFiles         map[string]string
	lsigSizes        map[string]int
	keyMetadata      map[string]PlannerKeyMetadata
	minTxnFee        uint64
	minTxnFees       map[types.Digest]uint64
	consensusVersion string
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
		LSigSizes:   d.lsigSizes,
		KeyMetadata: d.keyMetadata,
	}
}

func (d stubPlannerDeps) NetworkParams(genesisHash types.Digest) PlannerNetworkParams {
	minFee := d.minTxnFee
	if d.minTxnFees != nil {
		minFee = d.minTxnFees[genesisHash]
	}
	consensusVersion := d.consensusVersion
	if consensusVersion == "" {
		consensusVersion = string(protocol.ConsensusV41)
	}
	return PlannerNetworkParams{MinTxnFee: minFee, ConsensusVersion: consensusVersion}
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
		PlannerNetworkParams{ConsensusVersion: string(protocol.ConsensusV42)},
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

func TestCalculateLogicSigResourcesV42RejectsLegacyForeignScalar(t *testing.T) {
	_, _, err := calculateLogicSigResources(
		nil,
		PlannerIdentitySnapshot{},
		"default",
		[]signerapi.SignRequest{{LsigSize: 1_500}},
		[]types.Transaction{{}},
		nil,
		map[int]bool{},
		map[int]bool{0: true},
		nil,
		PlannerNetworkParams{ConsensusVersion: string(protocol.ConsensusV42)},
		false,
		false,
	)
	if err == nil || !strings.Contains(err.Error(), "provide lsig_resources") {
		t.Fatalf("calculateLogicSigResources() error = %v, want structured-profile rejection", err)
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
		PlannerNetworkParams{ConsensusVersion: string(protocol.ConsensusV42)},
		true,
		true,
	)
	if err == nil || !strings.Contains(err.Error(), "require a non-empty program") {
		t.Fatalf("calculateLogicSigResources() error = %v, want orphan-field rejection", err)
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

func TestVerifySignableKeysRejectsSentryKeyTypes(t *testing.T) {
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
		{
			name:    "guarded account",
			keyType: keytypes.GuardedFalcon1024Sentry1024V1,
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

			dummies, _, err := calculateDummies(nil, deps.Snapshot("default"), "default", requests, txns, nil, map[int]bool{}, map[int]bool{}, false, tt.isPreGrouped)
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

		dummies, _, err := calculateDummies(nil, deps.Snapshot("default"), "default", requests, txns, nil, map[int]bool{}, foreign, false, true)
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

		_, _, err := calculateDummies(nil, deps.Snapshot("default"), "default", requests, txns, nil, map[int]bool{}, foreign, false, true)
		if err == nil {
			t.Fatal("calculateDummies() error = nil, want pre-grouped budget rejection")
		}
		if !strings.Contains(err.Error(), "pre-grouped") {
			t.Fatalf("calculateDummies() error = %q, want pre-grouped rejection", err.Error())
		}
	})
}

// TestCalculateDummies_FeePoolingExcludesForeign pins Option C: dummy fees are
// pooled only across positions this signer signs. A foreign LogicSig position
// contributes to the dummy budget but never carries a fee share, so the signer
// never rewrites bytes it neither signs nor verifies.
func TestCalculateDummies_FeePoolingExcludesForeign(t *testing.T) {
	const falconAddr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	t.Run("mixed local and foreign lsig pools only onto the local position", func(t *testing.T) {
		// Index 0: local falcon (1500) signed here. Index 1: foreign falcon hint
		// (1500). Demand 3000 over 2*1000 budget -> 1 dummy. lsigIndices must be
		// exactly [0]; index 1 (foreign) must not appear.
		deps := stubPlannerDeps{
			keyTypes:  map[string]string{falconAddr: "aplane.falcon1024.v1"},
			lsigSizes: map[string]int{falconAddr: 1500},
		}
		requests := []signerapi.SignRequest{
			{AuthAddress: falconAddr, TxnBytesHex: "deadbeef"},
			{TxnBytesHex: "deadbeef", LsigSize: 1500},
		}
		txns := []types.Transaction{makePlannerTxn(types.Digest{}), makePlannerTxn(types.Digest{})}
		foreign := map[int]bool{1: true}

		dummies, lsigIndices, err := calculateDummies(nil, deps.Snapshot("default"), "default", requests, txns, nil, map[int]bool{}, foreign, false, false)
		if err != nil {
			t.Fatalf("calculateDummies() error = %v", err)
		}
		if dummies != 1 {
			t.Fatalf("dummies = %d, want 1", dummies)
		}
		if len(lsigIndices) != 1 || lsigIndices[0] != 0 {
			t.Fatalf("lsigIndices = %v, want [0] (foreign index 1 must not carry a fee share)", lsigIndices)
		}
	})

	t.Run("all-foreign lsig falls back to the first signer-signed position", func(t *testing.T) {
		// Index 0: ed25519 signed here, no local lsig. Index 1: foreign falcon
		// hint (2500). Demand 2500 over 2*1000 budget -> 1 dummy. No local lsig
		// position exists, so the pooled fee must fall back to index 0 (sign
		// mode) and never to the foreign slot.
		deps := stubPlannerDeps{
			keyTypes:  map[string]string{falconAddr: "ed25519"},
			lsigSizes: map[string]int{},
		}
		requests := []signerapi.SignRequest{
			{AuthAddress: falconAddr, TxnBytesHex: "deadbeef"},
			{TxnBytesHex: "deadbeef", LsigSize: 2500},
		}
		txns := []types.Transaction{makePlannerTxn(types.Digest{}), makePlannerTxn(types.Digest{})}
		foreign := map[int]bool{1: true}

		dummies, lsigIndices, err := calculateDummies(nil, deps.Snapshot("default"), "default", requests, txns, nil, map[int]bool{}, foreign, false, false)
		if err != nil {
			t.Fatalf("calculateDummies() error = %v", err)
		}
		if dummies != 1 {
			t.Fatalf("dummies = %d, want 1", dummies)
		}
		if len(lsigIndices) != 1 || lsigIndices[0] != 0 {
			t.Fatalf("lsigIndices = %v, want [0] (fee must fall back to the signed position, never foreign)", lsigIndices)
		}
		if foreign[lsigIndices[0]] {
			t.Fatalf("fee pooled onto foreign index %d", lsigIndices[0])
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

	_, _, err := calculateDummies(nil, snapshot, "default", requests, txns, nil, map[int]bool{}, foreign, false, false)
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

	_, _, err := calculateDummies(nil, snapshot, "default", requests, txns, nil, map[int]bool{}, foreign, false, false)
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

	allTxns, dummyTxns, feeInfo, _, err := buildFinalGroup(deps.NetworkParams(genesisHash).MinTxnFee, nil, txns, 2, []int{0}, false)
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

func TestBuildFinalGroupRejectsImplausibleMinFee(t *testing.T) {
	genesisHash := types.Digest{5, 5, 5}
	txns := []types.Transaction{{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: types.Address{1}, Fee: 1000, GenesisHash: genesisHash},
	}}
	deps := stubPlannerDeps{
		minTxnFees: map[types.Digest]uint64{genesisHash: 2_000_000}, // absurd min fee
	}

	_, _, _, _, err := buildFinalGroup(deps.NetworkParams(genesisHash).MinTxnFee, nil, txns, 2, []int{0}, false)
	if err == nil || !strings.Contains(err.Error(), "implausibly high") {
		t.Fatalf("buildFinalGroup() error = %v, want implausible-min-fee rejection", err)
	}
}

// TestCalculateDummies_BoundedAdminSlotTopUp pins per-path bounded budgeting:
// stored LSigSizes cover the spend path only, and calculateDummies reserves
// the Falcon contract-admin signature bytes solely for admin-key rekey slots.
func TestCalculateDummies_BoundedAdminSlotTopUp(t *testing.T) {
	const addr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	// Spend-path size that fits a single txn's budget exactly: no dummies for
	// a spend, but the admin signature top-up forces dummies for an admin rekey.
	deps := stubPlannerDeps{
		keyTypes:  map[string]string{addr: "aplane.falcon1024-bounded.v1"},
		lsigSizes: map[string]int{addr: coresigning.TxLsigBudget},
	}
	requests := []signerapi.SignRequest{{AuthAddress: addr, TxnBytesHex: "deadbeef"}}
	txns := []types.Transaction{makePlannerTxn(types.Digest{})}

	metadata := testBoundedMetadata(t, boundedmeta.AdminAuthorizationAdmin)
	metadata.PostSigningLogicSigSize = coresigning.TxLsigBudget + boundedmeta.FalconAdminSignatureSize
	spendItems := []*boundedPlanItem{{Path: boundedPathPureSpend, Metadata: metadata}}
	dummies, _, err := calculateDummies(nil, deps.Snapshot("default"), "default", requests, txns, spendItems, map[int]bool{}, map[int]bool{}, false, false)
	if err != nil {
		t.Fatalf("spend path: unexpected error: %v", err)
	}
	if dummies != 0 {
		t.Fatalf("spend path dummies = %d, want 0 (no admin-signature reservation)", dummies)
	}

	adminItems := []*boundedPlanItem{{Path: boundedPathAdminKeyRekey, Metadata: metadata}}
	dummies, _, err = calculateDummies(nil, deps.Snapshot("default"), "default", requests, txns, adminItems, map[int]bool{}, map[int]bool{}, false, false)
	if err != nil {
		t.Fatalf("admin path: unexpected error: %v", err)
	}
	wantDummies := (boundedmeta.FalconAdminSignatureSize + coresigning.TxLsigBudget - 1) / coresigning.TxLsigBudget
	if dummies != wantDummies {
		t.Fatalf("admin path dummies = %d, want %d (admin signature reserved)", dummies, wantDummies)
	}
}

// TestPlanGroupRejectsBoundedFeeCeilingAfterDummyPooling pins that the bounded
// MaxFee ceiling is enforced against finalized fees: pooled dummy fees are
// added to LogicSig slots after the sizing classification, and a plan whose
// pooled fee crosses the ceiling must be rejected at plan time, not at
// execution after operator approval.
func TestPlanGroupRejectsBoundedFeeCeilingAfterDummyPooling(t *testing.T) {
	var genesisHash types.Digest
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{
		base64.StdEncoding.EncodeToString(genesisHash[:]): "bounded_fee_test",
	})
	if err != nil {
		t.Fatalf("NewGenesisHashNetworkResolver() error = %v", err)
	}

	authAddr := types.Address{1}.String()
	metadata := testBoundedMetadata(t, "") // MaxFee 5000, no admin operations
	metadata.PostSigningLogicSigSize = 2500
	deps := stubPlannerDeps{
		keyTypes: map[string]string{authAddr: "aplane.falcon1024-bounded.v1"},
		// Spend size needing 2 dummies for a single txn: pooled fee = 2 * minFee.
		lsigSizes: map[string]int{authAddr: 2500},
		keyMetadata: map[string]PlannerKeyMetadata{authAddr: {
			Category:             "dsa_lsig",
			PublicKeyHex:         "aabb",
			BoundedAuthorization: metadata,
		}},
		minTxnFee: 1000,
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

	// Fee 4000 passes the pre-pooling check (4000 <= 5000) but the 2000
	// microAlgos of pooled dummy fees push the finalized fee to 6000.
	_, planErr := planner.PlanGroup("default", makeRequest(4000))
	if planErr == nil {
		t.Fatal("PlanGroup() error = nil, want bounded fee ceiling rejection after dummy pooling")
	}
	if !strings.Contains(planErr.Message, "exceeds account maximum") {
		t.Fatalf("PlanGroup() error = %q, want fee ceiling rejection", planErr.Message)
	}

	// Fee 1000 finalizes at 3000, within the ceiling: plan succeeds and the
	// authoritative bounded item reflects the finalized classification.
	plan, planErr := planner.PlanGroup("default", makeRequest(1000))
	if planErr != nil {
		t.Fatalf("PlanGroup() error = %v", planErr)
	}
	if len(plan.BoundedItems) != 1 || plan.BoundedItems[0] == nil || plan.BoundedItems[0].Path != boundedPathPureSpend {
		t.Fatalf("BoundedItems = %+v, want one pure-spend item", plan.BoundedItems)
	}
	if plan.DummiesNeeded != 2 {
		t.Fatalf("DummiesNeeded = %d, want 2", plan.DummiesNeeded)
	}
}
