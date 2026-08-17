// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

func frozenBoundedTestService(t *testing.T, programBytes uint64) (*Service, string, types.Transaction) {
	t.Helper()
	genesisHash := types.Digest{9}
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{
		base64.StdEncoding.EncodeToString(genesisHash[:]): "frozen_component_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizer := types.Address{1}.String()
	metadata := boundedSentryTestMetadata(t, bytes.Repeat([]byte{0x51}, boundedmeta.SentryPublicKeySizeV1))
	profile := &lsigresource.Profile{
		ProgramBytes: programBytes,
		Spend: &lsigresource.PathProfile{
			ArgumentBytes: uint64(2 * boundedmeta.SentrySignatureMaxSizeV1),
			MaxOpcodeCost: 1,
		},
		SpendingRekey: &lsigresource.PathProfile{ArgumentBytes: uint64(boundedmeta.SentrySignatureMaxSizeV1), MaxOpcodeCost: 1},
		AdminRekey:    &lsigresource.PathProfile{ArgumentBytes: uint64(boundedmeta.SentrySignatureMaxSizeV1), MaxOpcodeCost: 1},
	}
	planner := NewPlanner(stubPlannerDeps{
		keyTypes: map[string]string{authorizer: "aplane.test-bounded-sentry.v1"},
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
			Sender: types.Address{2}, Fee: 10_000, FirstValid: 1, LastValid: 10,
			GenesisHash: genesisHash,
		},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{3}, Amount: 1},
	}
	return &Service{Planner: planner}, authorizer, txn
}

func TestValidateFrozenComponentContextAcceptsRekeyedAuthorizer(t *testing.T) {
	service, authorizer, txn := frozenBoundedTestService(t, 1)
	planned, planErr := service.Planner.PlanGroup("default", signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{
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
	plan, groupRequest, serviceErr := service.ValidateFrozenComponentContext("default", request)
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
	planned, planErr := service.Planner.PlanGroup("default", signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{
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
	_, _, serviceErr := service.ValidateFrozenComponentContext("default", request)
	if serviceErr == nil || !strings.Contains(serviceErr.Error(), "not the canonical signer-added dummy") {
		t.Fatalf("ValidateFrozenComponentContext() error = %v, want fabricated dummy rejection", serviceErr)
	}
}

func TestFrozenComponentDummyPartitionIsSemanticForEveryKind(t *testing.T) {
	service, authorizer, txn := frozenBoundedTestService(t, 4_500)
	planned, planErr := service.Planner.PlanGroup("default", signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{
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
		signerapi.ComponentTargetKindUser,
		signerapi.ComponentTargetKindSentry,
		signerapi.ComponentTargetKindBoundedBase,
	} {
		t.Run(string(kind), func(t *testing.T) {
			target := signerapi.ComponentTarget{TargetIndex: 0, Kind: kind}
			switch kind {
			case signerapi.ComponentTargetKindSentry:
				target.ComponentKey = "sentry-component"
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
			if _, err := service.SignComponentsWithContext(context.Background(), "default", request, nil); err == nil ||
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
