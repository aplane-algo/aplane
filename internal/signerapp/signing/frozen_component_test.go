// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestFrozenComponentReconstructionMatchesCanonicalPlan(t *testing.T) {
	service, authorizer, txn := frozenBoundedTestService(t, 4_500)
	requestForPlan := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{
		AuthAddress: authorizer, TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
	}}}
	planned, planErr := service.Planner.PlanGroup(requestForPlan)
	if planErr != nil {
		t.Fatal(planErr)
	}
	groupHex := make([]string, len(planned.AllTxns))
	componentRequest := signerapi.ComponentRequest{
		Targets: []signerapi.ComponentTarget{{
			TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: authorizer,
		}},
	}
	for i, plannedTxn := range planned.AllTxns {
		groupHex[i] = txnutil.EncodeWithPrefixHex(plannedTxn)
		if i > 0 {
			componentRequest.DummyPositions = append(componentRequest.DummyPositions, signerapi.ComponentDummyPosition{TargetIndex: i})
		}
	}
	componentRequest.GroupBytesHex = groupHex

	reconstructed, groupRequest, serviceErr := service.ValidateFrozenComponentContext(componentRequest)
	if serviceErr != nil {
		t.Fatalf("ValidateFrozenComponentContext() error = %v", serviceErr)
	}
	if want := componentRequest.GroupSignRequest(); !reflect.DeepEqual(groupRequest, want) {
		t.Fatalf("reconstructed request = %#v, want frozen request %#v", groupRequest, want)
	}
	for i := range planned.AllTxns {
		if !bytes.Equal(txnutil.EncodeWithPrefix(planned.AllTxns[i]), txnutil.EncodeWithPrefix(reconstructed.AllTxns[i])) {
			t.Fatalf("reconstructed transaction %d differs from canonical plan", i)
		}
	}
	if planned.DummiesNeeded != reconstructed.DummiesNeeded ||
		!reflect.DeepEqual(planned.LsigIndices, reconstructed.LsigIndices) ||
		!reflect.DeepEqual(planned.LogicSigResourcePlan, reconstructed.LogicSigResourcePlan) ||
		!reflect.DeepEqual(planned.AuthKeyTypes, reconstructed.AuthKeyTypes) ||
		!reflect.DeepEqual(planned.KnownAddresses, reconstructed.KnownAddresses) ||
		!reflect.DeepEqual(planned.BoundedItems, reconstructed.BoundedItems) {
		t.Fatalf("frozen gate inputs drifted from canonical plan:\nplanned=%#v\nreconstructed=%#v", planned, reconstructed)
	}
}

func frozenBoundedTestService(t *testing.T, programBytes uint64) (*Service, string, types.Transaction) {
	t.Helper()
	return frozenBoundedTestServiceWith(t, programBytes, nil)
}

// frozenBoundedTestServiceWith also gives the signer the extra keys, by
// address and key type.
func frozenBoundedTestServiceWith(t *testing.T, programBytes uint64, extraKeyTypes map[string]string) (*Service, string, types.Transaction) {
	t.Helper()
	genesisHash := types.Digest{9}
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{
		base64.StdEncoding.EncodeToString(genesisHash[:]): "frozen_component_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizer := types.Address{1}.String()
	metadata := boundedCosignerTestMetadata(t, bytes.Repeat([]byte{0x51}, boundedmeta.CosignerPublicKeySizeV1))
	profile := &lsigresource.Profile{
		ProgramBytes: programBytes,
		Spend: &lsigresource.PathProfile{
			ArgumentBytes: uint64(2 * boundedmeta.CosignerSignatureMaxSizeV1),
			MaxOpcodeCost: 1,
		},
		SpendingRekey: &lsigresource.PathProfile{ArgumentBytes: uint64(boundedmeta.CosignerSignatureMaxSizeV1), MaxOpcodeCost: 1},
	}
	keyTypes := map[string]string{authorizer: "aplane.test-bounded-cosigner.v1"}
	for address, keyType := range extraKeyTypes {
		keyTypes[address] = keyType
	}
	planner := NewPlanner(stubPlannerDeps{
		keyTypes: keyTypes,
		keyMetadata: map[string]PlannerKeyMetadata{authorizer: {
			Category: "dsa_lsig", PublicKeyHex: "aabb",
			BoundedAuthorization: metadata, LogicSigResources: profile,
		}},
	}, PlannerOptions{GenesisHashResolver: resolver})
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			// A sender distinct from the signer-owned auth address models a
			// rekeyed account. Authorization must still resolve through authorizer.
			// The fee is the client's suggested minimum; the planner adds its
			// authorization charge on top, within the bounded max_fee.
			Sender: types.Address{2}, Fee: 1_000, FirstValid: 1, LastValid: 10,
			GenesisHash: genesisHash,
		},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{3}, Amount: 1},
	}
	return &Service{Planner: planner}, authorizer, txn
}

func TestValidateFrozenComponentContextAcceptsRekeyedAuthorizer(t *testing.T) {
	service, authorizer, txn := frozenBoundedTestService(t, 1)
	planned, planErr := service.Planner.PlanGroup(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{
		AuthAddress: authorizer, TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
	}}})
	if planErr != nil {
		t.Fatal(planErr)
	}
	groupHex := make([]string, len(planned.AllTxns))
	dummyPositions := make([]signerapi.ComponentDummyPosition, len(planned.DummyTxns))
	for i := range planned.AllTxns {
		groupHex[i] = txnutil.EncodeWithPrefixHex(planned.AllTxns[i])
		if i > 0 {
			dummyPositions[i-1] = signerapi.ComponentDummyPosition{TargetIndex: i}
		}
	}
	request := signerapi.ComponentRequest{
		GroupBytesHex:  groupHex,
		Targets:        []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: authorizer}},
		DummyPositions: dummyPositions,
	}
	plan, groupRequest, serviceErr := service.ValidateFrozenComponentContext(request)
	if serviceErr != nil {
		t.Fatalf("ValidateFrozenComponentContext() error = %v", serviceErr)
	}
	if got := groupRequest.Requests[0].AuthAddress; got != authorizer {
		t.Fatalf("auth address = %q, want durable authorizer %q", got, authorizer)
	}
	if got := plan.AllTxns[0].Sender.String(); got == authorizer {
		t.Fatal("test did not exercise a rekeyed sender/auth-address pair")
	}
}

func TestValidateFrozenComponentContextRejectsFabricatedDummy(t *testing.T) {
	service, authorizer, txn := frozenBoundedTestService(t, 4_500)
	planned, planErr := service.Planner.PlanGroup(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{
		AuthAddress: authorizer, TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
	}}})
	if planErr != nil {
		t.Fatal(planErr)
	}
	if len(planned.DummyTxns) == 0 {
		t.Fatal("plan did not create a dummy")
	}
	fabricated := append([]types.Transaction(nil), planned.AllTxns...)
	fabricated[1].Note = []byte{0xff}
	for i := range fabricated {
		fabricated[i].Group = types.Digest{}
	}
	groupID, err := algocrypto.ComputeGroupID(fabricated)
	if err != nil {
		t.Fatal(err)
	}
	groupHex := make([]string, len(fabricated))
	for i := range fabricated {
		fabricated[i].Group = groupID
		groupHex[i] = txnutil.EncodeWithPrefixHex(fabricated[i])
	}
	request := signerapi.ComponentRequest{
		GroupBytesHex: groupHex,
		Targets:       []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: authorizer}},
	}
	for index := 1; index < len(groupHex); index++ {
		request.DummyPositions = append(request.DummyPositions, signerapi.ComponentDummyPosition{TargetIndex: index})
	}
	_, _, serviceErr := service.ValidateFrozenComponentContext(request)
	if serviceErr == nil || !strings.Contains(serviceErr.Error(), "not the canonical signer-added dummy") {
		t.Fatalf("ValidateFrozenComponentContext() error = %v, want fabricated dummy rejection", serviceErr)
	}
}

func TestFrozenComponentDummyPartitionIsSemanticForEveryKind(t *testing.T) {
	service, authorizer, txn := frozenBoundedTestService(t, 4_500)
	planned, planErr := service.Planner.PlanGroup(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{
		AuthAddress: authorizer, TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
	}}})
	if planErr != nil {
		t.Fatal(planErr)
	}
	if len(planned.DummyTxns) == 0 {
		t.Fatal("plan did not create a dummy")
	}
	groupHex := make([]string, len(planned.AllTxns))
	for i := range planned.AllTxns {
		groupHex[i] = txnutil.EncodeWithPrefixHex(planned.AllTxns[i])
	}

	for _, kind := range []signerapi.ComponentTargetKind{
		signerapi.ComponentTargetKindCosigner,
		signerapi.ComponentTargetKindBoundedBase,
	} {
		t.Run(string(kind), func(t *testing.T) {
			target := signerapi.ComponentTarget{TargetIndex: 0, Kind: kind}
			switch kind {
			case signerapi.ComponentTargetKindCosigner:
				target.ComponentKey = "cosigner-component"
			default:
				target.AuthAddress = authorizer
			}
			request := signerapi.ComponentRequest{
				GroupBytesHex: groupHex,
				Targets:       []signerapi.ComponentTarget{target},
			}
			for index := 1; index < len(groupHex); index++ {
				request.ContextualPositions = append(request.ContextualPositions, signerapi.ComponentContextPosition{TargetIndex: index})
			}
			if err := request.Validate(); err != nil {
				t.Fatalf("structural request validation failed: %v", err)
			}
			if _, err := service.SignComponentsWithContext(context.Background(), request, nil); err == nil ||
				!strings.Contains(err.Error(), "must be declared as dummy_positions") {
				t.Fatalf("SignComponentsWithContext() error = %v, want undeclared dummy rejection", err)
			}

			request.ContextualPositions = nil
			for index := 1; index < len(groupHex); index++ {
				request.DummyPositions = append(request.DummyPositions, signerapi.ComponentDummyPosition{TargetIndex: index})
			}
			if err := request.Validate(); err != nil {
				t.Fatalf("declared request validation failed: %v", err)
			}
			if err := validateFrozenComponentDummyPartition(request, planned.AllTxns); err != nil {
				t.Fatalf("declared canonical dummies rejected: %v", err)
			}
		})
	}
}

func TestValidateFrozenComponentContextPrefersConcurrentLock(t *testing.T) {
	service, authorizer, txn := frozenBoundedTestService(t, 1)
	planned, planErr := service.Planner.PlanGroup(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{
		AuthAddress: authorizer, TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
	}}})
	if planErr != nil {
		t.Fatal(planErr)
	}
	request := signerapi.ComponentRequest{
		Targets: []signerapi.ComponentTarget{{
			TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: authorizer,
		}},
	}
	for i, plannedTxn := range planned.AllTxns {
		request.GroupBytesHex = append(request.GroupBytesHex, txnutil.EncodeWithPrefixHex(plannedTxn))
		if i > 0 {
			request.DummyPositions = append(request.DummyPositions, signerapi.ComponentDummyPosition{TargetIndex: i})
		}
	}
	service.Planner.VerifySignableKeys = func(PlannerRuntimeSnapshot, []signerapi.SignRequest, map[int]bool, map[int]bool) (int, *ServiceError) {
		return 0, badRequest("key not found")
	}
	service.IsUnlocked = func() bool { return false }

	_, _, serviceErr := service.ValidateFrozenComponentContext(request)
	if serviceErr == nil || serviceErr.Kind != ErrorLocked {
		t.Fatalf("ValidateFrozenComponentContext() error = %#v, want locked", serviceErr)
	}
}

func TestValidateFrozenComponentContextAuditsEveryOriginalPosition(t *testing.T) {
	service, authorizer, txn := frozenBoundedTestService(t, 1)
	planned, planErr := service.Planner.PlanGroup(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{
		AuthAddress: authorizer, TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
	}}})
	if planErr != nil {
		t.Fatal(planErr)
	}
	audit := &captureAuditLog{}
	service.Planner.AuditLog = audit
	service.Planner.GenerateTxnDescription = func(string) string { return "frozen bounded transaction" }
	request := signerapi.ComponentRequest{
		Targets: []signerapi.ComponentTarget{{
			TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: authorizer,
		}},
	}
	for i, plannedTxn := range planned.AllTxns {
		request.GroupBytesHex = append(request.GroupBytesHex, txnutil.EncodeWithPrefixHex(plannedTxn))
		if i > 0 {
			request.DummyPositions = append(request.DummyPositions, signerapi.ComponentDummyPosition{TargetIndex: i})
		}
	}

	if _, _, serviceErr := service.ValidateFrozenComponentContext(request); serviceErr != nil {
		t.Fatalf("ValidateFrozenComponentContext() error = %v", serviceErr)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("sign-request audit entries = %#v, want one per original position", audit.entries)
	}
	entry := audit.entries[0]
	if entry.authAddress != authorizer || entry.txnSender != txn.Sender.String() || entry.details != "frozen bounded transaction" {
		t.Fatalf("sign-request audit entry = %#v, want frozen request attribution", entry)
	}
}

// A contextual position that names one of the signer's own accounts is sized
// from the signer's records, as /plan sized it, and it is where /plan put the
// authorization charge. It stays out of what this request signs and judges
// (audit #10, #19).
func TestFrozenComponentSizesAHeldContextPositionFromSignerRecords(t *testing.T) {
	falcon := types.Address{7}
	service, authorizer, txn := frozenBoundedTestServiceWith(t, 4_500, map[string]string{falcon.String(): nativefalcon.KeyType})
	falconTxn := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: falcon, Fee: 1_000, FirstValid: 1, LastValid: 10, GenesisHash: txn.GenesisHash},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{3}, Amount: 1},
	}
	planned, planErr := service.Planner.PlanGroup(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
		{AuthAddress: authorizer, TxnBytesHex: txnutil.EncodeWithPrefixHex(txn)},
		{AuthAddress: falcon.String(), TxnBytesHex: txnutil.EncodeWithPrefixHex(falconTxn)},
	}})
	if planErr != nil {
		t.Fatal(planErr)
	}
	// /plan charges the held native Falcon position, not the bounded target.
	if planned.AllTxns[0].Fee != 1_000 || planned.AllTxns[1].Fee < 3_000 {
		t.Fatalf("planned fees = %d, %d; want the target at 1000 and the Falcon position carrying the charge",
			planned.AllTxns[0].Fee, planned.AllTxns[1].Fee)
	}

	request := func(position signerapi.ComponentContextPosition) signerapi.ComponentRequest {
		componentRequest := signerapi.ComponentRequest{
			Targets: []signerapi.ComponentTarget{{
				TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: authorizer,
			}},
			ContextualPositions: []signerapi.ComponentContextPosition{position},
		}
		for i, plannedTxn := range planned.AllTxns {
			componentRequest.GroupBytesHex = append(componentRequest.GroupBytesHex, txnutil.EncodeWithPrefixHex(plannedTxn))
			if i > 1 {
				componentRequest.DummyPositions = append(componentRequest.DummyPositions, signerapi.ComponentDummyPosition{TargetIndex: i})
			}
		}
		return componentRequest
	}

	reconstructed, _, serviceErr := service.ValidateFrozenComponentContext(request(
		signerapi.ComponentContextPosition{TargetIndex: 1, AuthAddress: falcon.String()}))
	if serviceErr != nil {
		t.Fatalf("ValidateFrozenComponentContext() error = %v", serviceErr)
	}
	if reconstructed.DummiesNeeded != planned.DummiesNeeded ||
		!reflect.DeepEqual(reconstructed.LogicSigResourcePlan, planned.LogicSigResourcePlan) ||
		reconstructed.FeeInfo.NativePQFeeContribution != planned.FeeInfo.NativePQFeeContribution {
		t.Fatalf("frozen sizing drifted from /plan:\nplanned=%#v\nreconstructed=%#v", planned.LogicSigResourcePlan, reconstructed.LogicSigResourcePlan)
	}
	// Not signed or judged here: foreign to this request, with no plan item.
	if !reconstructed.ForeignIndices[1] || reconstructed.BoundedItems[1] != nil || reconstructed.AuthKeyTypes[1] != "" {
		t.Fatalf("held context position leaked into this request's signing plan: foreign=%v item=%v keyType=%q",
			reconstructed.ForeignIndices[1], reconstructed.BoundedItems[1], reconstructed.AuthKeyTypes[1])
	}
	if !reflect.DeepEqual(reconstructed.LsigIndices, []int{0}) {
		t.Fatalf("LsigIndices = %v, want only the target", reconstructed.LsigIndices)
	}

	// An address the signer doesn't hold can't be claimed as its own.
	if _, _, err := service.ValidateFrozenComponentContext(request(
		signerapi.ComponentContextPosition{TargetIndex: 1, AuthAddress: types.Address{8}.String()})); err == nil || !strings.Contains(err.Message, "no key found") {
		t.Fatalf("unheld auth_address: err = %v, want the no-key refusal", err)
	}
	// A position the signer sizes takes no hint from the caller.
	hinted := request(signerapi.ComponentContextPosition{TargetIndex: 1, AuthAddress: falcon.String(), PQScheme: signerapi.PQSchemeFalcon1024})
	if _, _, err := service.ValidateFrozenComponentContext(hinted); err == nil || !strings.Contains(err.Message, "pq_scheme is allowed only for foreign") {
		t.Fatalf("hinted held position: err = %v, want the hint refused", err)
	}
}
