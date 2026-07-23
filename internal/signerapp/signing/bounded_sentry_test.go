// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	"github.com/aplane-algo/aplane/internal/signerapi"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

func TestValidateBoundedComponentPlanRequiresSentrySpend(t *testing.T) {
	metadata := boundedSentryTestMetadata(t, bytes.Repeat([]byte{0x41}, boundedmeta.SentryPublicKeySizeV1))
	request := signerapi.BoundedComponentRequest{Requests: []signerapi.SignRequest{{AuthAddress: "ACCOUNT", TxnBytesHex: "TX00"}}}
	plan := &PlanResult{BoundedItems: []*boundedPlanItem{{Path: boundedPathPureSpend, Metadata: metadata}}}
	indices, err := validateBoundedComponentPlan(request, plan)
	if err != nil || len(indices) != 1 || indices[0] != 0 {
		t.Fatalf("validateBoundedComponentPlan() = %v, %#v", err, indices)
	}
	plan.BoundedItems[0].Path = boundedPathSpendingKeyRekey
	if _, err := validateBoundedComponentPlan(request, plan); err == nil {
		t.Fatal("validateBoundedComponentPlan(rekey) error = nil")
	}
	plan.BoundedItems[0] = &boundedPlanItem{Path: boundedPathPureSpend, Metadata: testBoundedMetadata(t, "")}
	if _, err := validateBoundedComponentPlan(request, plan); err == nil {
		t.Fatal("validateBoundedComponentPlan(non-sentry) error = nil")
	}
}

func TestPrepareBoundedComponentRejectsNilSessionBeforePlanning(t *testing.T) {
	svc := &Service{Planner: &Planner{}, Approval: &ApprovalService{}, Executor: &Executor{}}
	_, err := svc.PrepareBoundedComponentWithContext(
		t.Context(),
		"default",
		signerapi.BoundedComponentRequest{},
		nil,
	)
	if err == nil || err.Kind != ErrorInternal || err.Message != "key session is nil" {
		t.Fatalf("PrepareBoundedComponentWithContext() error = %#v, want immediate nil-session rejection", err)
	}
}

func TestLoadBoundedKeyMaterialMapsExpectedErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		kind ErrorKind
	}{
		{name: "locked", err: keystore.ErrStoreLocked, kind: ErrorLocked},
		{name: "not found", err: keystore.ErrKeyNotFound, kind: ErrorBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, got := loadBoundedKeyMaterial(t.Context(), &componentKeyTestSession{err: test.err}, "ACCOUNT", "bounded account key")
			if got == nil || got.Kind != test.kind {
				t.Fatalf("loadBoundedKeyMaterial() error = %#v, want kind %s", got, test.kind)
			}
		})
	}
}

func TestAssembleBoundedRejectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := (&Service{}).AssembleBoundedWithContext(ctx, "default", signerapi.BoundedAssemblyRequest{}, nil)
	if err == nil || err.Kind != ErrorUnavailable {
		t.Fatalf("AssembleBoundedWithContext() error = %#v, want canceled request", err)
	}
}

func TestBoundedAssemblyReceiptBindsRuntimeAndMetadata(t *testing.T) {
	metadata := boundedSentryTestMetadata(t, bytes.Repeat([]byte{0x42}, boundedmeta.SentryPublicKeySizeV1))
	txID := bytes.Repeat([]byte{0x43}, 32)
	first, err := boundedAssemblyReceiptMessage("ACCOUNT", txID, metadata, map[string][]byte{"preimage": {1}})
	if err != nil {
		t.Fatal(err)
	}
	changedRuntime, _ := boundedAssemblyReceiptMessage("ACCOUNT", txID, metadata, map[string][]byte{"preimage": {2}})
	if first == changedRuntime {
		t.Fatal("receipt did not bind runtime arguments")
	}
	changedMetadata := boundedmeta.Clone(metadata)
	changedMetadata.MaxFee++
	changedProfile, _ := boundedAssemblyReceiptMessage("ACCOUNT", txID, changedMetadata, map[string][]byte{"preimage": {1}})
	if first == changedProfile {
		t.Fatal("receipt did not bind durable metadata")
	}
}

func TestAssembleBoundedTargetVerifiesBothAuthorities(t *testing.T) {
	spendingPublicKey, spendingPrivateKey := testFalconComponentKeypair(t, 0x44)
	sentryPublicKey, sentryPrivateKey := testFalconComponentKeypair(t, 0x45)
	bytecode := []byte{0x06, 0x20, 0x01, 0x01, 0x22, 0x44, 0x55}
	account := logicSigAddressForTest(t, bytecode)
	txn := paymentTransaction(t, account, types.Address{0x46}.String(), 7)
	txn.Fee = 1_000
	group, err := canonical.DecodeGroupHex([]string{txnutil.EncodeWithPrefixHex(txn)})
	if err != nil {
		t.Fatal(err)
	}
	metadata := boundedSentryTestMetadata(t, sentryPublicKey)
	baseSignature, err := signerops.New(nil).Sign(spendingPrivateKey, group.Entries[0].TxID[:])
	if err != nil {
		t.Fatal(err)
	}
	receiptMessage, err := boundedAssemblyReceiptMessage(account, group.Entries[0].TxID[:], metadata, nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := signerops.New(nil).Sign(spendingPrivateKey, receiptMessage[:])
	if err != nil {
		t.Fatal(err)
	}
	sentryMessage := message.ComponentMessage(message.RoleSentry, group.Entries[0].TxID)
	sentrySignature, err := signerops.New(nil).Sign(sentryPrivateKey, sentryMessage[:])
	if err != nil {
		t.Fatal(err)
	}
	newKeyMaterial := func() *coresigning.KeyMaterial {
		return &coresigning.KeyMaterial{
			Type: "test.bounded-sentry.v1", Category: keys.CategoryDSALsig,
			BaseKeyType: witness.Falcon1024V1, PublicKey: append([]byte(nil), spendingPublicKey...),
			Bytecode: append([]byte(nil), bytecode...), BoundedAuthorization: boundedmeta.Clone(metadata),
			SigningMetadataVersion: keys.BoundedSigningMetadataVersion,
		}
	}
	target := signerapi.BoundedAssemblyTarget{
		TargetIndex: 0, BoundedAccount: account,
		BaseSignatures:  []string{hex.EncodeToString(baseSignature)},
		AssemblyReceipt: hex.EncodeToString(receipt), SentrySignature: hex.EncodeToString(sentrySignature),
	}
	badReceipt := target
	badReceipt.AssemblyReceipt = hex.EncodeToString(sentrySignature)
	if _, svcErr := assembleBoundedTarget(context.Background(), badReceipt, group.Entries[0], &componentKeyTestSession{key: newKeyMaterial()}); svcErr == nil {
		t.Fatal("assembleBoundedTarget(wrong receipt) error = nil")
	}
	signedHex, svcErr := assembleBoundedTarget(context.Background(), target, group.Entries[0], &componentKeyTestSession{key: newKeyMaterial()})
	if svcErr != nil {
		t.Fatalf("assembleBoundedTarget() error = %v", svcErr)
	}
	signedBytes, err := hex.DecodeString(signedHex)
	if err != nil {
		t.Fatal(err)
	}
	var signed types.SignedTxn
	if err := msgpack.Decode(signedBytes, &signed); err != nil {
		t.Fatal(err)
	}
	if len(signed.Lsig.Args) != 2 || !bytes.Equal(signed.Lsig.Args[0], baseSignature) || !bytes.Equal(signed.Lsig.Args[1], sentrySignature) {
		t.Fatalf("assembled args = %#v", signed.Lsig.Args)
	}
}

func boundedSentryTestMetadata(t *testing.T, sentryPublicKey []byte) *boundedmeta.Metadata {
	t.Helper()
	componentKeyID, err := witness.ID(witness.Falcon1024V1, sentryPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	metadata := &boundedmeta.Metadata{
		Contract:               boundedmeta.ContractV1,
		BaseSignatureArgLayout: boundedmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{boundedmeta.SentrySignatureMaxSizeV1}},
		SpendEffects:           []string{boundedmeta.SpendEffectPay}, MaxFee: 10_000,
		Layer3Policy: boundedmeta.Layer3PolicyCustom,
		Sentry: &boundedmeta.SentryAuthorization{
			Contract: boundedmeta.SentryContractV1, ComponentKeyType: witness.Falcon1024V1,
			PublicKeyHex: hex.EncodeToString(sentryPublicKey), ComponentKeyID: componentKeyID,
			SignatureMaxSize: boundedmeta.SentrySignatureMaxSizeV1, RequiredOn: []string{boundedmeta.PathSpend},
		},
		ArgumentLayout: []boundedmeta.ArgumentSlot{
			{Index: 0, Name: "base_signature_0", Source: boundedmeta.ArgSourceBaseSignature, MaxSize: boundedmeta.SentrySignatureMaxSizeV1, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgRequired, AdminRekey: boundedmeta.ArgRequired}},
			{Index: 1, Name: boundedmeta.SentrySignatureSlot, Source: boundedmeta.ArgSourceSentry, MaxSize: boundedmeta.SentrySignatureMaxSizeV1, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgForbidden, AdminRekey: boundedmeta.ArgForbidden}},
		},
		PostSigningLogicSigSize: 4_000,
	}
	if err := metadata.Validate(); err != nil {
		t.Fatalf("test metadata invalid: %v", err)
	}
	return metadata
}
