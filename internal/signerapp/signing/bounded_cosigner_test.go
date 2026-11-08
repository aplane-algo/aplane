// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestValidateBoundedComponentPlanRequiresCosignerSpend(t *testing.T) {
	metadata := boundedCosignerTestMetadata(t, bytes.Repeat([]byte{0x41}, boundedmeta.CosignerPublicKeySizeV1))
	request := signerapi.ComponentRequest{
		GroupBytesHex: []string{"TX00"},
		Targets:       []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: "ACCOUNT"}},
	}
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
		t.Fatal("validateBoundedComponentPlan(non-cosigner) error = nil")
	}
}

func TestPrepareBoundedComponentRejectsNilSessionBeforePlanning(t *testing.T) {
	svc := &Service{Planner: &Planner{}, Approval: &ApprovalService{}, Executor: &Executor{}}
	_, err := svc.PrepareBoundedComponentWithContext(
		t.Context(),

		signerapi.ComponentRequest{},
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

func TestUnifiedAssemblyRejectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := (&Service{}).AssembleWithContext(ctx, signerapi.AssemblyRequest{}, nil)
	if err == nil || err.Kind != ErrorUnavailable {
		t.Fatalf("AssembleWithContext() error = %#v, want canceled request", err)
	}
}

func TestBoundedAssemblyReceiptBindsRuntimeAndMetadata(t *testing.T) {
	metadata := boundedCosignerTestMetadata(t, bytes.Repeat([]byte{0x42}, boundedmeta.CosignerPublicKeySizeV1))
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
	cosignerPublicKey, cosignerPrivateKey := testFalconComponentKeypair(t, 0x45)
	bytecode := []byte{0x06, 0x20, 0x01, 0x01, 0x22, 0x44, 0x55}
	account := logicSigAddressForTest(t, bytecode)
	txn := paymentTransaction(t, account, types.Address{0x46}.String(), 7)
	txn.Fee = 1_000
	group, err := canonical.DecodeGroupHex([]string{txnutil.EncodeWithPrefixHex(txn)})
	if err != nil {
		t.Fatal(err)
	}
	metadata := boundedCosignerTestMetadata(t, cosignerPublicKey)
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
	cosignerMessage := message.ComponentMessage(message.RoleCosigner, group.Entries[0].TxID)
	cosignerSignature, err := signerops.New(nil).Sign(cosignerPrivateKey, cosignerMessage[:])
	if err != nil {
		t.Fatal(err)
	}
	newKeyMaterial := func() *coresigning.KeyMaterial {
		return &coresigning.KeyMaterial{
			Type: "test.bounded-cosigner.v1", Category: keys.CategoryDSALsig,
			BaseKeyType: "aplane.falcon1024.v1", PublicKey: append([]byte(nil), spendingPublicKey...),
			Bytecode: append([]byte(nil), bytecode...), BoundedAuthorization: boundedmeta.Clone(metadata),
			SigningMetadataVersion: keys.BoundedSigningMetadataVersion,
		}
	}
	target := signerapi.AssemblyTarget{
		TargetIndex: 0, Kind: signerapi.AssemblyTargetKindBoundedCosigner, AuthAddress: account,
		BaseSignatures:  []string{hex.EncodeToString(baseSignature)},
		AssemblyReceipt: hex.EncodeToString(receipt), CosignerSignature: hex.EncodeToString(cosignerSignature),
	}
	badReceipt := target
	badReceipt.AssemblyReceipt = hex.EncodeToString(cosignerSignature)
	if _, svcErr := assembleBoundedTarget(context.Background(), badReceipt, group.Entries[0], &componentKeyTestSession{key: newKeyMaterial()}); svcErr == nil {
		t.Fatal("assembleBoundedTarget(wrong receipt) error = nil")
	}
	badBase := target
	badBase.BaseSignatures = []string{hex.EncodeToString(cosignerSignature)}
	if _, svcErr := assembleBoundedTarget(context.Background(), badBase, group.Entries[0], &componentKeyTestSession{key: newKeyMaterial()}); svcErr == nil {
		t.Fatal("assembleBoundedTarget(wrong base signature) error = nil")
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
	if len(signed.Lsig.Args) != 2 || !bytes.Equal(signed.Lsig.Args[0], baseSignature) || !bytes.Equal(signed.Lsig.Args[1], cosignerSignature) {
		t.Fatalf("assembled args = %#v", signed.Lsig.Args)
	}
}

func boundedCosignerTestMetadata(t *testing.T, cosignerPublicKey []byte) *boundedmeta.Metadata {
	t.Helper()
	componentKeyID, err := witness.ID(witness.Falcon1024V1, cosignerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	metadata := &boundedmeta.Metadata{
		Contract:               boundedmeta.ContractV1,
		BaseSignatureArgLayout: boundedmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{boundedmeta.CosignerSignatureMaxSizeV1}},
		SpendEffects:           []string{boundedmeta.SpendEffectPay}, MaxFee: 10_000,
		Layer3Policy: boundedmeta.Layer3PolicyCustom,
		Cosigner: &boundedmeta.CosignerAuthorization{
			Contract: boundedmeta.CosignerContractV1, ComponentKeyType: witness.Falcon1024V1,
			PublicKeyHex: hex.EncodeToString(cosignerPublicKey), ComponentKeyID: componentKeyID,
			SignatureMaxSize: boundedmeta.CosignerSignatureMaxSizeV1, RequiredOn: []string{boundedmeta.PathSpend},
		},
		ArgumentLayout: []boundedmeta.ArgumentSlot{
			{Index: 0, Name: "base_signature_0", Source: boundedmeta.ArgSourceBaseSignature, MaxSize: boundedmeta.CosignerSignatureMaxSizeV1, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgRequired, AdminRekey: boundedmeta.ArgRequired}},
			{Index: 1, Name: boundedmeta.CosignerSignatureSlot, Source: boundedmeta.ArgSourceCosigner, MaxSize: boundedmeta.CosignerSignatureMaxSizeV1, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgForbidden, AdminRekey: boundedmeta.ArgForbidden}},
		},
	}
	if err := metadata.Validate(); err != nil {
		t.Fatalf("test metadata invalid: %v", err)
	}
	return metadata
}

// The bounded cosigner flow is reviewed for Falcon spending only. A valid signature on
// any other base stays refused at the point it always was, because resolving the base
// alone would let Ed25519 through to a ceremony it can't finish.
func TestBoundedSpendingProofRequiresSupportedConstruction(t *testing.T) {
	seed := make([]byte, 48)
	seed[0] = 1
	falconPublicKey, falconPrivateKey, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatal(err)
	}
	message := bytes.Repeat([]byte{5}, 32)
	falconSignature, err := signerops.New(nil).Sign(falconPrivateKey, message)
	if err != nil {
		t.Fatal(err)
	}
	edPublicKey, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSignature := ed25519.Sign(edPrivateKey, message)

	for name, workflow := range map[string]boundedSigningWorkflow{
		"cosigner": boundedWorkflowCosigner,
	} {
		t.Run(name, func(t *testing.T) {
			falconLayout := layoutOf(sigconstruction.Falcon1024())
			for label, test := range map[string]struct {
				base      string
				contract  string
				layout    boundedmeta.SignatureArgLayout
				publicKey []byte
				message   []byte
				proof     [][]byte
				want      bool
			}{
				"Falcon":            {"aplane.falcon1024.v1", boundedmeta.ContractV1, falconLayout, falconPublicKey, message, [][]byte{falconSignature}, true},
				"wrong message":     {"aplane.falcon1024.v1", boundedmeta.ContractV1, falconLayout, falconPublicKey, []byte("other"), [][]byte{falconSignature}, false},
				"no proof":          {"aplane.falcon1024.v1", boundedmeta.ContractV1, falconLayout, falconPublicKey, message, nil, false},
				"two proof slots":   {"aplane.falcon1024.v1", boundedmeta.ContractV1, falconLayout, falconPublicKey, message, [][]byte{falconSignature, falconSignature}, false},
				"valid on Ed25519":  {"aplane.ed25519.v1", boundedmeta.ContractV1, layoutOf(sigconstruction.Ed25519()), edPublicKey, message, [][]byte{edSignature}, false},
				"unknown contract":  {"aplane.falcon1024.v1", "bounded-unknown", falconLayout, falconPublicKey, message, [][]byte{falconSignature}, false},
				"witness as a base": {witness.Falcon1024V1, boundedmeta.ContractV1, falconLayout, falconPublicKey, message, [][]byte{falconSignature}, false},
				// Stored metadata that disagrees with the construction is refused, even
				// with a valid signature, rather than trusted on either side.
				"stored max size differs":   {"aplane.falcon1024.v1", boundedmeta.ContractV1, boundedmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{1280}}, falconPublicKey, message, [][]byte{falconSignature}, false},
				"stored slot count differs": {"aplane.falcon1024.v1", boundedmeta.ContractV1, boundedmeta.SignatureArgLayout{Count: 2, MaxSizes: []int{1423, 1423}}, falconPublicKey, message, [][]byte{falconSignature}, false},
				"no stored layout":          {"aplane.falcon1024.v1", boundedmeta.ContractV1, boundedmeta.SignatureArgLayout{}, falconPublicKey, message, [][]byte{falconSignature}, false},
			} {
				keyMaterial := &coresigning.KeyMaterial{BaseKeyType: test.base, PublicKey: test.publicKey, BoundedAuthorization: &boundedmeta.Metadata{Contract: test.contract, BaseSignatureArgLayout: test.layout}}
				if got := boundedSpendingProofVerifies(keyMaterial, workflow, test.message, test.proof...); got != test.want {
					t.Errorf("%s: boundedSpendingProofVerifies() = %v, want %v", label, got, test.want)
				}
			}
		})
	}
}

func TestCosignerAssemblySignatureRequiresAWitnessKeyType(t *testing.T) {
	seed := make([]byte, 48)
	seed[0] = 2
	publicKey, privateKey, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("message")
	signature, err := signerops.New(nil).Sign(privateKey, message)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCosignerAssemblySignature(witness.Falcon1024V1, publicKey, message, signature); err != nil {
		t.Fatalf("verifyCosignerAssemblySignature() error = %v", err)
	}
	err = verifyCosignerAssemblySignature("aplane.falcon1024.v1", publicKey, message, signature)
	if err == nil || !strings.Contains(err.Error(), "is not a cosigner key type") {
		t.Fatalf("spending key type: error = %v", err)
	}
}

// layoutOf is the durable layout generation writes for a construction.
func layoutOf(construction sigconstruction.Construction) boundedmeta.SignatureArgLayout {
	layout := construction.Layout()
	return boundedmeta.SignatureArgLayout{Count: layout.Count(), MaxSizes: layout.MaxSizes()}
}

func TestBoundedCosignerRequiredEmitsContractedCode(t *testing.T) {
	err := boundedCosignerRequired()
	if err.Code() != signerapi.ErrCodeBoundedCosignerRequired {
		t.Fatalf("Code() = %q, want %q", err.Code(), signerapi.ErrCodeBoundedCosignerRequired)
	}
	if err.HTTPStatus() != 400 {
		t.Fatalf("HTTPStatus() = %d, want 400", err.HTTPStatus())
	}
}
