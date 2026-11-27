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

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/rekeylist"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// The cosigned flow carries a cosigned account's spends, its cosigned rekeys and
// its listed rekeys; no other path and no uncosigned account.
func TestValidateHostComponentPlanAdmitsOnlyCosignedPaths(t *testing.T) {
	metadata := boundedCosignerTestMetadata(t, bytes.Repeat([]byte{0x41}, hostmeta.DefaultCosignerPublicKeySize))
	request := signerapi.ComponentRequest{
		GroupBytesHex: []string{"TX00"},
		Targets:       []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindBase, AuthAddress: "ACCOUNT"}},
	}
	for _, path := range []hostPath{hostPathPureSpend, hostPathSpendingKeyRekey, hostPathListedRekey} {
		plan := &PlanResult{HostItems: []*hostPlanItem{{Path: path, Metadata: metadata}}}
		indices, err := validateHostComponentPlan(request, plan)
		if err != nil || len(indices) != 1 || indices[0] != 0 {
			t.Fatalf("validateHostComponentPlan(%s) = %v, %#v", path, err, indices)
		}
	}
	plan := &PlanResult{HostItems: []*hostPlanItem{{Path: "admin_rekey", Metadata: metadata}}}
	if _, err := validateHostComponentPlan(request, plan); err == nil {
		t.Fatal("validateHostComponentPlan(unknown path) error = nil")
	}
	plan.HostItems[0] = &hostPlanItem{Path: hostPathPureSpend, Metadata: testBoundedMetadata(t, hostmeta.RekeyRefused)}
	if _, err := validateHostComponentPlan(request, plan); err == nil {
		t.Fatal("validateHostComponentPlan(non-cosigner) error = nil")
	}
	if !hostPathNeedsCosigner(hostPathPureSpend) || !hostPathNeedsCosigner(hostPathSpendingKeyRekey) || hostPathNeedsCosigner(hostPathListedRekey) {
		t.Fatal("the cosigner signs a listed rekey, or skips a spend or a declared rekey")
	}
}

func TestPrepareHostComponentRejectsNilSessionBeforePlanning(t *testing.T) {
	svc := &Service{Planner: &Planner{}, Approval: &ApprovalService{}, Executor: &Executor{}}
	_, err := svc.PrepareHostComponentWithContext(
		t.Context(),

		signerapi.ComponentRequest{},
		nil,
	)
	if err == nil || err.Kind != ErrorInternal || err.Message != "key session is nil" {
		t.Fatalf("PrepareHostComponentWithContext() error = %#v, want immediate nil-session rejection", err)
	}
}

func TestLoadHostKeyMaterialMapsExpectedErrors(t *testing.T) {
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
			_, got := loadHostKeyMaterial(t.Context(), &componentKeyTestSession{err: test.err}, "ACCOUNT", "bounded account key")
			if got == nil || got.Kind != test.kind {
				t.Fatalf("loadHostKeyMaterial() error = %#v, want kind %s", got, test.kind)
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

func TestHostAssemblyReceiptBindsRuntimeAndMetadata(t *testing.T) {
	metadata := boundedCosignerTestMetadata(t, bytes.Repeat([]byte{0x42}, hostmeta.DefaultCosignerPublicKeySize))
	txID := bytes.Repeat([]byte{0x43}, 32)
	first, err := hostAssemblyReceiptMessage("ACCOUNT", txID, metadata, map[string][]byte{"preimage": {1}})
	if err != nil {
		t.Fatal(err)
	}
	changedRuntime, _ := hostAssemblyReceiptMessage("ACCOUNT", txID, metadata, map[string][]byte{"preimage": {2}})
	if first == changedRuntime {
		t.Fatal("receipt did not bind runtime arguments")
	}
	changedMetadata := hostmeta.Clone(metadata)
	changedMetadata.Bounds.MaxFee = new(*changedMetadata.FeeCeiling() + 1)
	changedProfile, _ := hostAssemblyReceiptMessage("ACCOUNT", txID, changedMetadata, map[string][]byte{"preimage": {1}})
	if first == changedProfile {
		t.Fatal("receipt did not bind durable metadata")
	}
}

func TestAssembleHostTargetVerifiesBothAuthorities(t *testing.T) {
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
	baseSignature, err := signerops.New().Sign(spendingPrivateKey, group.Entries[0].TxID[:])
	if err != nil {
		t.Fatal(err)
	}
	receiptMessage, err := hostAssemblyReceiptMessage(account, group.Entries[0].TxID[:], metadata, nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := signerops.New().Sign(spendingPrivateKey, receiptMessage[:])
	if err != nil {
		t.Fatal(err)
	}
	cosignerMessage := message.ComponentMessage(message.RoleCosigner, group.Entries[0].TxID)
	cosignerSignature, err := signerops.New().Sign(cosignerPrivateKey, cosignerMessage[:])
	if err != nil {
		t.Fatal(err)
	}
	newKeyMaterial := func() *coresigning.KeyMaterial {
		return &coresigning.KeyMaterial{
			Type: "test.bounded-cosigner.v1", Category: keys.CategoryDSALsig,
			BaseKeyType: "aplane.falcon1024.v1", PublicKey: append([]byte(nil), spendingPublicKey...),
			Bytecode: append([]byte(nil), bytecode...), Host: hostmeta.Clone(metadata),
		}
	}
	target := signerapi.AssemblyTarget{
		TargetIndex: 0, AuthAddress: account,
		BaseSignatures:  []string{hex.EncodeToString(baseSignature)},
		AssemblyReceipt: hex.EncodeToString(receipt), CosignerSignature: hex.EncodeToString(cosignerSignature),
	}
	badReceipt := target
	badReceipt.AssemblyReceipt = hex.EncodeToString(cosignerSignature)
	if _, svcErr := assembleHostTarget(context.Background(), badReceipt, group.Entries[0], &componentKeyTestSession{key: newKeyMaterial()}); svcErr == nil {
		t.Fatal("assembleHostTarget(wrong receipt) error = nil")
	}
	badBase := target
	badBase.BaseSignatures = []string{hex.EncodeToString(cosignerSignature)}
	if _, svcErr := assembleHostTarget(context.Background(), badBase, group.Entries[0], &componentKeyTestSession{key: newKeyMaterial()}); svcErr == nil {
		t.Fatal("assembleHostTarget(wrong base signature) error = nil")
	}
	signedHex, svcErr := assembleHostTarget(context.Background(), target, group.Entries[0], &componentKeyTestSession{key: newKeyMaterial()})
	if svcErr != nil {
		t.Fatalf("assembleHostTarget() error = %v", svcErr)
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

// Assembly decides whether the cosigner signs from the canonical transaction and
// the stored contract, not from the client: a cosigned rekey and a spend need the
// cosigner's signature, and a listed rekey refuses one.
func TestAssembleHostTargetFollowsThePathForTheCosigner(t *testing.T) {
	spendingPublicKey, spendingPrivateKey := testFalconComponentKeypair(t, 0x54)
	cosignerPublicKey, cosignerPrivateKey := testFalconComponentKeypair(t, 0x55)
	bytecode := []byte{0x06, 0x20, 0x01, 0x01, 0x22, 0x44, 0x56}
	account := logicSigAddressForTest(t, bytecode)
	listedTarget, otherTarget := types.Address{0x61}, types.Address{0x62}

	cosignedRekey := boundedCosignerTestMetadata(t, cosignerPublicKey)
	cosignedRekey.Rekey = hostmeta.RekeySpendingKey
	cosignedRekey.Cosigner.RequiredOn = hostmeta.CosignerRequiredOn(hostmeta.RekeySpendingKey)
	cosignedRekey.ArgumentLayout[1].Paths = hostmeta.CosignerSlotPaths(cosignedRekey.Cosigner)

	// Only these on a cosigned account: the list proof sits between the base and
	// cosigner slots, and the root comes from the spending private key.
	list, err := rekeylist.FromSpendingKey(spendingPrivateKey, []types.Address{listedTarget})
	if err != nil {
		t.Fatal(err)
	}
	root := list.Root()
	list.Zero()
	onlyThese := boundedCosignerTestMetadata(t, cosignerPublicKey)
	onlyThese.Bounds.SpendEffects = []string{hostmeta.SpendEffectAxfer}
	onlyThese.RekeyList = &hostmeta.RekeyList{Contract: hostmeta.RekeyListContractV1, Depth: rekeylist.Depth, RootHex: hex.EncodeToString(root[:])}
	onlyThese.DerivedArgs = []hostmeta.DerivedArg{{Name: "rekey_list_proof", Kind: hostmeta.DerivedArgRekeyListProof, Parameter: hostmeta.RekeyListEntriesParameter, MaxSize: rekeylist.ProofSize}}
	cosignerSlot := onlyThese.ArgumentLayout[1]
	cosignerSlot.Index = 2
	onlyThese.ArgumentLayout = []hostmeta.ArgumentSlot{onlyThese.ArgumentLayout[0], {
		Index: 1, Name: "rekey_list_proof", Source: hostmeta.ArgSourceDerived, MaxSize: rekeylist.ProofSize,
		Paths: hostmeta.ArgumentPathMask{Spend: hostmeta.ArgForbidden, SpendingRekey: hostmeta.ArgForbidden, ListedRekey: hostmeta.ArgRequired},
	}, cosignerSlot}
	if err := onlyThese.Validate(); err != nil {
		t.Fatal(err)
	}

	payment := func(receiver string, amount uint64) types.Transaction {
		txn := paymentTransaction(t, account, receiver, amount)
		txn.Fee = 1_000
		return txn
	}
	rekey := func(to types.Address) types.Transaction {
		txn := payment(account, 0)
		txn.RekeyTo = to
		return txn
	}
	for _, test := range []struct {
		name     string
		metadata *hostmeta.Metadata
		txn      types.Transaction
		cosigner bool
		want     string
		args     int
	}{
		{"a cosigned rekey with the cosigner", cosignedRekey, rekey(otherTarget), true, "", 2},
		{"a cosigned rekey without the cosigner", cosignedRekey, rekey(otherTarget), false, "needs a cosigner_signature on spending_rekey", 0},
		{"a spend without the cosigner", cosignedRekey, payment(otherTarget.String(), 7), false, "needs a cosigner_signature on spend", 0},
		{"a listed rekey alone", onlyThese, rekey(listedTarget), false, "", 2},
		{"a listed rekey with the cosigner", onlyThese, rekey(listedTarget), true, "takes no cosigner_signature", 0},
		{"an unlisted rekey", onlyThese, rekey(otherTarget), false, "not on this account's rekey-to list", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			group, err := canonical.DecodeGroupHex([]string{txnutil.EncodeWithPrefixHex(test.txn)})
			if err != nil {
				t.Fatal(err)
			}
			txID := group.Entries[0].TxID
			sign := func(key, message []byte) string {
				signature, err := signerops.New().Sign(key, message)
				if err != nil {
					t.Fatal(err)
				}
				return hex.EncodeToString(signature)
			}
			receiptMessage, err := hostAssemblyReceiptMessage(account, txID[:], test.metadata, nil)
			if err != nil {
				t.Fatal(err)
			}
			target := signerapi.AssemblyTarget{
				TargetIndex: 0, AuthAddress: account,
				BaseSignatures: []string{sign(spendingPrivateKey, txID[:])}, AssemblyReceipt: sign(spendingPrivateKey, receiptMessage[:]),
			}
			if test.cosigner {
				cosignerMessage := message.ComponentMessage(message.RoleCosigner, txID)
				target.CosignerSignature = sign(cosignerPrivateKey, cosignerMessage[:])
			}
			keyMaterial := &coresigning.KeyMaterial{
				Type: "test.bounded-cosigner.v1", Category: keys.CategoryDSALsig,
				BaseKeyType: "aplane.falcon1024.v1", PublicKey: append([]byte(nil), spendingPublicKey...),
				Value:    &coresigning.LsigKeyMaterial{PrivateKey: append([]byte(nil), spendingPrivateKey...)},
				Bytecode: append([]byte(nil), bytecode...), Host: hostmeta.Clone(test.metadata),
				Parameters: map[string]string{hostmeta.RekeyListEntriesParameter: listedTarget.String()},
			}
			signedHex, svcErr := assembleHostTarget(context.Background(), target, group.Entries[0], &componentKeyTestSession{key: keyMaterial})
			if test.want != "" {
				if svcErr == nil || !strings.Contains(svcErr.Message, test.want) {
					t.Fatalf("assembleHostTarget() error = %v, want %q", svcErr, test.want)
				}
				return
			}
			if svcErr != nil {
				t.Fatalf("assembleHostTarget() error = %v", svcErr)
			}
			signedBytes, err := hex.DecodeString(signedHex)
			if err != nil {
				t.Fatal(err)
			}
			var signed types.SignedTxn
			if err := msgpack.Decode(signedBytes, &signed); err != nil {
				t.Fatal(err)
			}
			if len(signed.Lsig.Args) != test.args {
				t.Fatalf("assembled %d args, want %d", len(signed.Lsig.Args), test.args)
			}
			if test.metadata == onlyThese && len(signed.Lsig.Args[1]) != rekeylist.ProofSize {
				t.Fatalf("the listed rekey's second argument is %d bytes, want the list proof", len(signed.Lsig.Args[1]))
			}
		})
	}
}

func boundedCosignerTestMetadata(t *testing.T, cosignerPublicKey []byte) *hostmeta.Metadata {
	t.Helper()
	componentKeyID, err := witness.ID(witness.Falcon1024V1, cosignerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	metadata := &hostmeta.Metadata{
		Contract:               hostmeta.BoundedContract,
		BaseSignatureArgLayout: hostmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{hostmeta.DefaultCosignerSignatureMaxSize}},
		Bounds:                 &hostmeta.Bounds{SpendEffects: []string{hostmeta.SpendEffectPay}, MaxFee: new(uint64(10_000)), Layer3Policy: hostmeta.Layer3PolicyCustom},
		Rekey:                  hostmeta.RekeyRefused,
		Cosigner: &hostmeta.CosignerAuthorization{
			Contract: hostmeta.CosignerContractV1, ComponentKeyType: witness.Falcon1024V1,
			PublicKeyHex: hex.EncodeToString(cosignerPublicKey), ComponentKeyID: componentKeyID,
			SignatureMaxSize: hostmeta.DefaultCosignerSignatureMaxSize, RequiredOn: []string{hostmeta.PathSpend},
		},
		ArgumentLayout: []hostmeta.ArgumentSlot{
			{Index: 0, Name: "base_signature_0", Source: hostmeta.ArgSourceBaseSignature, MaxSize: hostmeta.DefaultCosignerSignatureMaxSize, Paths: hostmeta.ArgumentPathMask{Spend: hostmeta.ArgRequired, SpendingRekey: hostmeta.ArgRequired, ListedRekey: hostmeta.ArgRequired}},
			{Index: 1, Name: hostmeta.CosignerSignatureSlot, Source: hostmeta.ArgSourceCosigner, MaxSize: hostmeta.DefaultCosignerSignatureMaxSize, Paths: hostmeta.ArgumentPathMask{Spend: hostmeta.ArgRequired, SpendingRekey: hostmeta.ArgForbidden, ListedRekey: hostmeta.ArgForbidden}},
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
func TestHostSpendingProofRequiresSupportedConstruction(t *testing.T) {
	seed := make([]byte, 48)
	seed[0] = 1
	falconPublicKey, falconPrivateKey, err := signerops.New().GenerateKeypair(seed)
	if err != nil {
		t.Fatal(err)
	}
	message := bytes.Repeat([]byte{5}, 32)
	falconSignature, err := signerops.New().Sign(falconPrivateKey, message)
	if err != nil {
		t.Fatal(err)
	}
	edPublicKey, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSignature := ed25519.Sign(edPrivateKey, message)

	for name, workflow := range map[string]hostSigningWorkflow{
		"cosigner": hostWorkflowCosigner,
	} {
		t.Run(name, func(t *testing.T) {
			falconLayout := layoutOf(sigconstruction.Falcon1024())
			for label, test := range map[string]struct {
				base      string
				contract  string
				layout    hostmeta.SignatureArgLayout
				publicKey []byte
				message   []byte
				proof     [][]byte
				want      bool
			}{
				"Falcon":          {"aplane.falcon1024.v1", hostmeta.BoundedContract, falconLayout, falconPublicKey, message, [][]byte{falconSignature}, true},
				"wrong message":   {"aplane.falcon1024.v1", hostmeta.BoundedContract, falconLayout, falconPublicKey, []byte("other"), [][]byte{falconSignature}, false},
				"no proof":        {"aplane.falcon1024.v1", hostmeta.BoundedContract, falconLayout, falconPublicKey, message, nil, false},
				"two proof slots": {"aplane.falcon1024.v1", hostmeta.BoundedContract, falconLayout, falconPublicKey, message, [][]byte{falconSignature, falconSignature}, false},
				// A bounded host is cosigned on either base too (phase 6.5).
				"valid on Ed25519":       {"aplane.ed25519.v1", hostmeta.BoundedContract, layoutOf(sigconstruction.Ed25519()), edPublicKey, message, [][]byte{edSignature}, true},
				"Ed25519, wrong message": {"aplane.ed25519.v1", hostmeta.BoundedContract, layoutOf(sigconstruction.Ed25519()), edPublicKey, []byte("other"), [][]byte{edSignature}, false},
				// A plain host is cosigned on either base.
				"plain host on Falcon":      {"aplane.falcon1024.v1", hostmeta.PlainContract, falconLayout, falconPublicKey, message, [][]byte{falconSignature}, true},
				"plain host on Ed25519":     {"aplane.ed25519.v1", hostmeta.PlainContract, layoutOf(sigconstruction.Ed25519()), edPublicKey, message, [][]byte{edSignature}, true},
				"plain host, wrong message": {"aplane.ed25519.v1", hostmeta.PlainContract, layoutOf(sigconstruction.Ed25519()), edPublicKey, []byte("other"), [][]byte{edSignature}, false},
				"unknown contract":          {"aplane.falcon1024.v1", "bounded-unknown", falconLayout, falconPublicKey, message, [][]byte{falconSignature}, false},
				"witness as a base":         {witness.Falcon1024V1, hostmeta.BoundedContract, falconLayout, falconPublicKey, message, [][]byte{falconSignature}, false},
				// Stored metadata that disagrees with the construction is refused, even
				// with a valid signature, rather than trusted on either side.
				"stored max size differs":   {"aplane.falcon1024.v1", hostmeta.BoundedContract, hostmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{1280}}, falconPublicKey, message, [][]byte{falconSignature}, false},
				"stored slot count differs": {"aplane.falcon1024.v1", hostmeta.BoundedContract, hostmeta.SignatureArgLayout{Count: 2, MaxSizes: []int{1423, 1423}}, falconPublicKey, message, [][]byte{falconSignature}, false},
				"no stored layout":          {"aplane.falcon1024.v1", hostmeta.BoundedContract, hostmeta.SignatureArgLayout{}, falconPublicKey, message, [][]byte{falconSignature}, false},
			} {
				keyMaterial := &coresigning.KeyMaterial{BaseKeyType: test.base, PublicKey: test.publicKey, Host: &hostmeta.Metadata{Contract: test.contract, BaseSignatureArgLayout: test.layout}}
				if got := hostSpendingProofVerifies(keyMaterial, workflow, test.message, test.proof...); got != test.want {
					t.Errorf("%s: hostSpendingProofVerifies() = %v, want %v", label, got, test.want)
				}
			}
		})
	}
}

func TestCosignerAssemblySignatureRequiresAWitnessKeyType(t *testing.T) {
	seed := make([]byte, 48)
	seed[0] = 2
	publicKey, privateKey, err := signerops.New().GenerateKeypair(seed)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("message")
	signature, err := signerops.New().Sign(privateKey, message)
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
func layoutOf(construction sigconstruction.Construction) hostmeta.SignatureArgLayout {
	layout := construction.Layout()
	return hostmeta.SignatureArgLayout{Count: layout.Count(), MaxSizes: layout.MaxSizes()}
}

func TestBoundedCosignerRequiredEmitsContractedCode(t *testing.T) {
	err := cosignerRequired()
	if err.Code() != signerapi.ErrCodeCosignerRequired {
		t.Fatalf("Code() = %q, want %q", err.Code(), signerapi.ErrCodeCosignerRequired)
	}
	if err.HTTPStatus() != 400 {
		t.Fatalf("HTTPStatus() = %d, want 400", err.HTTPStatus())
	}
}

// A plain host's spends carry what the dedicated cosigned account's did: a close,
// an app call, any type. Assembly takes each down the spend path, with both
// signatures, and the program, not the client, decides that.
func TestAssembleHostTargetCarriesPlainHostSpends(t *testing.T) {
	spendingPublicKey, spendingPrivateKey := testFalconComponentKeypair(t, 0x64)
	cosignerPublicKey, cosignerPrivateKey := testFalconComponentKeypair(t, 0x65)
	bytecode := []byte{0x06, 0x20, 0x01, 0x01, 0x22, 0x44, 0x57}
	account := logicSigAddressForTest(t, bytecode)
	metadata := boundedCosignerTestMetadata(t, cosignerPublicKey)
	metadata.Contract, metadata.Bounds = hostmeta.PlainContract, nil
	if err := metadata.Validate(); err != nil {
		t.Fatal(err)
	}

	closing := paymentTransaction(t, account, types.Address{0x66}.String(), 7)
	closing.CloseRemainderTo, closing.Fee = types.Address{0x66}, 50_000
	sender, err := types.DecodeAddress(account)
	if err != nil {
		t.Fatal(err)
	}
	appCall := types.Transaction{Type: types.ApplicationCallTx}
	appCall.Sender, appCall.ApplicationID, appCall.Fee = sender, 7, 1_000
	appCall.FirstValid, appCall.LastValid, appCall.GenesisHash = closing.FirstValid, closing.LastValid, closing.GenesisHash

	for name, txn := range map[string]types.Transaction{"close": closing, "app call": appCall} {
		t.Run(name, func(t *testing.T) {
			group, err := canonical.DecodeGroupHex([]string{txnutil.EncodeWithPrefixHex(txn)})
			if err != nil {
				t.Fatal(err)
			}
			txID := group.Entries[0].TxID
			baseSignature, err := signerops.New().Sign(spendingPrivateKey, txID[:])
			if err != nil {
				t.Fatal(err)
			}
			receiptMessage, err := hostAssemblyReceiptMessage(account, txID[:], metadata, nil)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := signerops.New().Sign(spendingPrivateKey, receiptMessage[:])
			if err != nil {
				t.Fatal(err)
			}
			cosignerMessage := message.ComponentMessage(message.RoleCosigner, txID)
			cosignerSignature, err := signerops.New().Sign(cosignerPrivateKey, cosignerMessage[:])
			if err != nil {
				t.Fatal(err)
			}
			keyMaterial := func() *coresigning.KeyMaterial {
				return &coresigning.KeyMaterial{
					Type: "aplane.falcon1024.v1", Category: keys.CategoryDSALsig,
					BaseKeyType: "aplane.falcon1024.v1", PublicKey: append([]byte(nil), spendingPublicKey...),
					Bytecode: append([]byte(nil), bytecode...), Host: hostmeta.Clone(metadata),
				}
			}
			target := signerapi.AssemblyTarget{
				TargetIndex: 0, AuthAddress: account,
				BaseSignatures:  []string{hex.EncodeToString(baseSignature)},
				AssemblyReceipt: hex.EncodeToString(receipt), CosignerSignature: hex.EncodeToString(cosignerSignature),
			}
			signedHex, svcErr := assembleHostTarget(context.Background(), target, group.Entries[0], &componentKeyTestSession{key: keyMaterial()})
			if svcErr != nil {
				t.Fatalf("assembleHostTarget() error = %v", svcErr)
			}
			signedBytes, err := hex.DecodeString(signedHex)
			if err != nil {
				t.Fatal(err)
			}
			var signed types.SignedTxn
			if err := msgpack.Decode(signedBytes, &signed); err != nil {
				t.Fatal(err)
			}
			if len(signed.Lsig.Args) != 2 || !bytes.Equal(signed.Lsig.Args[1], cosignerSignature) {
				t.Fatalf("assembled args = %#v", signed.Lsig.Args)
			}
			// Without the cosigner's signature the spend is refused.
			missing := target
			missing.CosignerSignature = ""
			if _, svcErr := assembleHostTarget(context.Background(), missing, group.Entries[0], &componentKeyTestSession{key: keyMaterial()}); svcErr == nil {
				t.Fatal("assembleHostTarget() without the cosigner signature succeeded")
			}
		})
	}
}

// A2: plain /sign refuses any plan with a cosigned account, a plain host's or a
// bounded host's, before signing anything; an account without a cosigner is
// signed there.
func TestPlainSignRefusesACosignedAccount(t *testing.T) {
	cosignerKey := bytes.Repeat([]byte{0x47}, hostmeta.DefaultCosignerPublicKeySize)
	bounded := boundedCosignerTestMetadata(t, cosignerKey)
	plain := hostmeta.Clone(bounded)
	plain.Contract, plain.Bounds = hostmeta.PlainContract, nil
	uncosigned := hostmeta.Clone(plain)
	uncosigned.Cosigner = nil
	for name, test := range map[string]struct {
		metadata *hostmeta.Metadata
		refused  bool
	}{
		"cosigned bounded host":         {bounded, true},
		"cosigned plain host":           {plain, true},
		"plain host without a cosigner": {uncosigned, false},
	} {
		plan := &PlanResult{HostItems: []*hostPlanItem{nil, {Metadata: test.metadata, Path: hostPathPureSpend}}}
		if got := planHasCosignedHostTarget(plan); got != test.refused {
			t.Fatalf("%s: planHasCosignedHostTarget() = %v, want %v", name, got, test.refused)
		}
	}
	if err := cosignerRequired(); err.Code() != signerapi.ErrCodeCosignerRequired {
		t.Fatalf("refusal code = %q", err.Code())
	}
}
