// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/attestor/message"
	"github.com/aplane-algo/aplane/internal/attestor/verify"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapi"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	falcon1024attested "github.com/aplane-algo/aplane/lsig/falcon1024_attested"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func init() {
	falcon1024attested.RegisterClient()
}

func TestPrepareComponentSigningCanonicalizesTargetsAndMessages(t *testing.T) {
	sender := types.Address{1}.String()
	receiver := types.Address{2}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	req := signerapi.ComponentSignRequest{
		RequestID:     "cli-component-1",
		Role:          signerapi.ComponentSignRoleUser,
		ComponentKey:  sender,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])},
		TargetIndices: []int{1, 0},
	}

	plan, err := PrepareComponentSigning(req)
	if err != nil {
		t.Fatalf("PrepareComponentSigning() error = %v", err)
	}
	if plan.RequestID != req.RequestID || plan.ComponentKey != sender {
		t.Fatalf("plan request metadata = %#v, want request_id %q component key %q", plan, req.RequestID, sender)
	}
	if plan.MessageRole != message.RoleUser {
		t.Fatalf("MessageRole = %v, want user", plan.MessageRole)
	}
	if len(plan.Targets) != 2 {
		t.Fatalf("Targets len = %d, want 2", len(plan.Targets))
	}
	for i, target := range plan.Targets {
		if target.TargetIndex != i {
			t.Fatalf("Targets[%d].TargetIndex = %d, want %d", i, target.TargetIndex, i)
		}
		if target.Sender != sender {
			t.Fatalf("Targets[%d].Sender = %q, want %q", i, target.Sender, sender)
		}
		wantMsg := message.ComponentMessage(message.RoleUser, plan.Group.Entries[i].TxID)
		if !bytes.Equal(target.Message[:], wantMsg[:]) {
			t.Fatalf("Targets[%d].Message = %x, want %x", i, target.Message, wantMsg)
		}
		if !bytes.Equal(target.TxID[:], algocrypto.TransactionID(txns[i])[:]) {
			t.Fatalf("Targets[%d].TxID = %x, want SDK transaction ID", i, target.TxID)
		}
	}
}

func TestPrepareComponentSigningUsesAttestorRoleDomain(t *testing.T) {
	sender := types.Address{3}.String()
	receiver := types.Address{4}.String()
	txn := paymentTransaction(t, sender, receiver, 7)

	req := signerapi.ComponentSignRequest{
		Role:          signerapi.ComponentSignRoleAttestor,
		ComponentKey:  strings.Repeat("ab", stded25519.PublicKeySize),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}

	plan, err := PrepareComponentSigning(req)
	if err != nil {
		t.Fatalf("PrepareComponentSigning() error = %v", err)
	}
	if plan.MessageRole != message.RoleAttestor {
		t.Fatalf("MessageRole = %v, want attestor", plan.MessageRole)
	}
	userMsg := message.ComponentMessage(message.RoleUser, plan.Group.Entries[0].TxID)
	if bytes.Equal(plan.Targets[0].Message[:], userMsg[:]) {
		t.Fatal("attestor component message matched user-role message")
	}
}

func TestPrepareComponentSigningRejectsMalformedGroupBytes(t *testing.T) {
	_, err := PrepareComponentSigning(signerapi.ComponentSignRequest{
		Role:          signerapi.ComponentSignRoleAttestor,
		GroupBytesHex: []string{"5458aa"},
		TargetIndices: []int{0},
	})
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("PrepareComponentSigning() error = %v, want bad request", err)
	}
	if !strings.Contains(err.Message, "decode transaction") {
		t.Fatalf("PrepareComponentSigning() error = %q, want decode transaction", err.Message)
	}
}

func TestPrepareComponentSigningRejectsDivergentGroup(t *testing.T) {
	sender := types.Address{5}.String()
	receiver := types.Address{6}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)
	txns[1].Group = types.Digest{9}

	_, err := PrepareComponentSigning(signerapi.ComponentSignRequest{
		Role:          signerapi.ComponentSignRoleAttestor,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])},
		TargetIndices: []int{0},
	})
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("PrepareComponentSigning() error = %v, want bad request", err)
	}
	if !strings.Contains(err.Message, "divergent group ID") {
		t.Fatalf("PrepareComponentSigning() error = %q, want divergent group ID", err.Message)
	}
}

func TestPrepareComponentSigningRejectsInvalidRequestShape(t *testing.T) {
	_, err := PrepareComponentSigning(signerapi.ComponentSignRequest{
		Role:          signerapi.ComponentSignRoleUser,
		GroupBytesHex: []string{"5458aa"},
		TargetIndices: []int{0},
	})
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("PrepareComponentSigning() error = %v, want bad request", err)
	}
	if !strings.Contains(err.Message, "component_key is required") {
		t.Fatalf("PrepareComponentSigning() error = %q, want missing component_key", err.Message)
	}
}

func TestSigningServiceSignComponentDispatchesAfterValidation(t *testing.T) {
	sender := types.Address{7}.String()
	receiver := types.Address{8}.String()
	txn := paymentTransaction(t, sender, receiver, 10)

	_, err := (&Service{}).SignComponentWithContext(nil, "default", signerapi.ComponentSignRequest{
		Role:          signerapi.ComponentSignRoleAttestor,
		ComponentKey:  strings.Repeat("ab", stded25519.PublicKeySize),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, nil)
	if err == nil || err.Kind != ErrorInternal {
		t.Fatalf("SignComponentWithContext() error = %#v, want internal", err)
	}
	if !strings.Contains(err.Message, "key session is nil") {
		t.Fatalf("SignComponentWithContext() error = %q, want key session", err.Message)
	}

	_, err = (&Service{}).SignComponentWithContext(nil, "default", signerapi.ComponentSignRequest{
		Role:          signerapi.ComponentSignRoleUser,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, nil)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("SignComponentWithContext(invalid) error = %#v, want bad request", err)
	}
}

func TestSignPreparedUserComponentsSignsAttestedAccountMessages(t *testing.T) {
	baseKeyType := "test.user-component-signing.v1"
	provider := &componentUserTestProvider{family: baseKeyType}
	coresigning.Register(provider)

	sender := types.Address{13}.String()
	receiver := types.Address{14}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)
	plan, err := PrepareComponentSigning(signerapi.ComponentSignRequest{
		RequestID:     "cmp-user",
		Role:          signerapi.ComponentSignRoleUser,
		ComponentKey:  sender,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])},
		TargetIndices: []int{0, 1},
	})
	if err != nil {
		t.Fatalf("PrepareComponentSigning() error = %v", err)
	}

	keyMaterial := &coresigning.KeyMaterial{
		Type:        keytypes.AttestedFalcon1024V1,
		Category:    keys.CategoryDSALsig,
		BaseKeyType: baseKeyType,
		Bytecode:    []byte{0x01, 0x02, 0x03},
		Value:       []byte{0xaa, 0xbb, 0xcc},
	}
	session := &componentKeyTestSession{key: keyMaterial}

	result, signErr := signPreparedUserComponents(nil, plan, session)
	if signErr != nil {
		t.Fatalf("signPreparedUserComponents() error = %v", signErr)
	}
	if session.calls != 1 || session.gotAddress != sender {
		t.Fatalf("session calls = %d address %q, want one call for %q", session.calls, session.gotAddress, sender)
	}
	if result.RequestID != plan.RequestID || result.ComponentKey != sender {
		t.Fatalf("result metadata = %#v, want request_id %q component_key %q", result, plan.RequestID, sender)
	}
	if len(result.Signatures) != len(plan.Targets) {
		t.Fatalf("Signatures len = %d, want %d", len(result.Signatures), len(plan.Targets))
	}
	if len(provider.messages) != len(plan.Targets) {
		t.Fatalf("provider messages len = %d, want %d", len(provider.messages), len(plan.Targets))
	}
	for i, sig := range result.Signatures {
		if sig.TargetIndex != plan.Targets[i].TargetIndex {
			t.Fatalf("signature %d target index = %d, want %d", i, sig.TargetIndex, plan.Targets[i].TargetIndex)
		}
		if sig.SignatureScheme != baseKeyType {
			t.Fatalf("signature scheme = %q, want %s", sig.SignatureScheme, baseKeyType)
		}
		if !bytes.Equal(provider.messages[i], plan.Targets[i].Message[:]) {
			t.Fatalf("provider message %d = %x, want %x", i, provider.messages[i], plan.Targets[i].Message)
		}
		gotSignature, err := hex.DecodeString(sig.Signature)
		if err != nil {
			t.Fatalf("DecodeString(signature) error = %v", err)
		}
		if !bytes.Equal(gotSignature, provider.signatures[i]) {
			t.Fatalf("signature %d = %x, want provider signature %x", i, gotSignature, provider.signatures[i])
		}
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil || keyMaterial.Bytecode != nil {
		t.Fatalf("key material was not zeroed after signing: %#v", keyMaterial)
	}
}

func TestSignPreparedUserComponentsRejectsSenderMismatchBeforeKeyLoad(t *testing.T) {
	sender := types.Address{15}.String()
	receiver := types.Address{16}.String()
	componentKey := types.Address{17}.String()
	txn := paymentTransaction(t, sender, receiver, 13)
	plan, err := PrepareComponentSigning(signerapi.ComponentSignRequest{
		RequestID:     "cmp-user-mismatch",
		Role:          signerapi.ComponentSignRoleUser,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	})
	if err != nil {
		t.Fatalf("PrepareComponentSigning() error = %v", err)
	}
	session := &componentKeyTestSession{}

	result, signErr := signPreparedUserComponents(nil, plan, session)
	if result != nil {
		t.Fatalf("result = %#v, want nil", result)
	}
	if signErr == nil || signErr.Kind != ErrorBadRequest {
		t.Fatalf("signPreparedUserComponents() error = %#v, want bad request", signErr)
	}
	if session.calls != 0 {
		t.Fatalf("session calls = %d, want 0 before sender mismatch rejection", session.calls)
	}
}

func TestSigningServiceAssembleAttestedDispatchesAfterValidation(t *testing.T) {
	_, err := (&Service{}).AssembleAttestedWithContext(nil, "default", signerapi.AttestedAssemblyRequest{
		RequestID:     "asm-1",
		GroupBytesHex: []string{"5458aa"},
		Targets: []signerapi.AttestedAssemblyTarget{{
			TargetIndex:       0,
			AttestedAccount:   "ADDR",
			UserSignature:     "aa",
			AttestorSignature: "bb",
		}},
	}, nil)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("AssembleAttestedWithContext() error = %#v, want bad request", err)
	}
	if !strings.Contains(err.Message, "decode transaction") {
		t.Fatalf("AssembleAttestedWithContext() error = %q, want decode transaction", err.Message)
	}

	_, err = (&Service{}).AssembleAttestedWithContext(nil, "default", signerapi.AttestedAssemblyRequest{}, nil)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("AssembleAttestedWithContext(invalid) error = %#v, want bad request", err)
	}
}

func TestAssembleDecodedAttestedVerifiesAndBuildsSignedGroup(t *testing.T) {
	attestorSeed := bytes.Repeat([]byte{0x52}, stded25519.SeedSize)
	attestorPrivateKey := stded25519.NewKeyFromSeed(attestorSeed)
	attestorPublicKey := append([]byte(nil), attestorPrivateKey.Public().(stded25519.PublicKey)...)

	userPublicKey, userPrivateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0x53}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	bytecode := []byte{0x06, 0x20, 0x01, 0x01, 0x22, 0x12, 0x34}
	attestedAccount := logicSigAddressForTest(t, bytecode)
	receiver := types.Address{18}.String()
	txns := groupedPaymentTransactions(t, attestedAccount, receiver)
	groupBytesHex := []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])}
	group, decodeErr := verify.DecodeCanonicalGroupHex(groupBytesHex)
	if decodeErr != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", decodeErr)
	}

	userMsg := message.ComponentMessage(message.RoleUser, group.Entries[0].TxID)
	userSignature, err := signerops.New(nil).Sign(userPrivateKey, userMsg[:])
	if err != nil {
		t.Fatalf("Sign(user) error = %v", err)
	}
	attestorMsg := message.ComponentMessage(message.RoleAttestor, group.Entries[0].TxID)
	attestorSignature := stded25519.Sign(attestorPrivateKey, attestorMsg[:])
	passthroughBytes := msgpack.Encode(types.SignedTxn{Txn: txns[1]})

	keyMaterial := &coresigning.KeyMaterial{
		Type:                   keytypes.AttestedFalcon1024V1,
		Category:               keys.CategoryDSALsig,
		BaseKeyType:            falcon1024attested.BaseKeyType,
		PublicKey:              append([]byte(nil), userPublicKey...),
		Bytecode:               append([]byte(nil), bytecode...),
		Parameters:             map[string]string{keytypes.ParameterAttestorPublicKey: hex.EncodeToString(attestorPublicKey)},
		SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
		Value:                  &coresigning.LsigKeyMaterial{PrivateKey: append([]byte(nil), userPrivateKey...)},
	}
	session := &componentKeyTestSession{key: keyMaterial}
	req := signerapi.AttestedAssemblyRequest{
		RequestID:     "asm-live",
		GroupBytesHex: groupBytesHex,
		Targets: []signerapi.AttestedAssemblyTarget{{
			TargetIndex:       0,
			AttestedAccount:   attestedAccount,
			UserSignature:     hex.EncodeToString(userSignature),
			AttestorSignature: hex.EncodeToString(attestorSignature),
		}},
		Passthrough: []signerapi.AttestedPassthroughItem{{
			TargetIndex:  1,
			SignedTxnHex: hex.EncodeToString(passthroughBytes),
		}},
	}

	result, signErr := assembleDecodedAttested(nil, req, group, session)
	if signErr != nil {
		t.Fatalf("assembleDecodedAttested() error = %v", signErr)
	}
	if result.RequestID != req.RequestID {
		t.Fatalf("RequestID = %q, want %q", result.RequestID, req.RequestID)
	}
	if len(result.SignedGroup) != 2 {
		t.Fatalf("SignedGroup len = %d, want 2", len(result.SignedGroup))
	}
	if result.SignedGroup[1] != hex.EncodeToString(passthroughBytes) {
		t.Fatalf("passthrough signed txn = %q, want original passthrough", result.SignedGroup[1])
	}

	signedTargetBytes, err := hex.DecodeString(result.SignedGroup[0])
	if err != nil {
		t.Fatalf("DecodeString(signed target) error = %v", err)
	}
	var signedTarget types.SignedTxn
	if err := msgpack.Decode(signedTargetBytes, &signedTarget); err != nil {
		t.Fatalf("Decode(signed target) error = %v", err)
	}
	gotTxID := algocrypto.TransactionID(signedTarget.Txn)
	wantTxID := algocrypto.TransactionID(txns[0])
	if !bytes.Equal(gotTxID, wantTxID) {
		t.Fatalf("signed target txid = %x, want %x", gotTxID, wantTxID)
	}
	if !bytes.Equal(signedTarget.Lsig.Logic, bytecode) {
		t.Fatalf("LogicSig bytecode = %x, want %x", signedTarget.Lsig.Logic, bytecode)
	}
	if len(signedTarget.Lsig.Args) != 2 {
		t.Fatalf("LogicSig args len = %d, want 2", len(signedTarget.Lsig.Args))
	}
	if !bytes.Equal(signedTarget.Lsig.Args[0], userSignature) {
		t.Fatalf("LogicSig arg 0 = %x, want user signature %x", signedTarget.Lsig.Args[0], userSignature)
	}
	if !bytes.Equal(signedTarget.Lsig.Args[1], attestorSignature) {
		t.Fatalf("LogicSig arg 1 = %x, want attestor signature %x", signedTarget.Lsig.Args[1], attestorSignature)
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil || keyMaterial.Bytecode != nil || keyMaterial.PublicKey != nil {
		t.Fatalf("key material was not zeroed after assembly: %#v", keyMaterial)
	}
}

func TestAssembleDecodedAttestedRejectsWrongAttestorSignature(t *testing.T) {
	attestorPrivateKey := stded25519.NewKeyFromSeed(bytes.Repeat([]byte{0x54}, stded25519.SeedSize))
	wrongPrivateKey := stded25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, stded25519.SeedSize))
	attestorPublicKey := append([]byte(nil), attestorPrivateKey.Public().(stded25519.PublicKey)...)

	userPublicKey, userPrivateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0x56}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	bytecode := []byte{0x06, 0x20, 0x01, 0x01, 0x22, 0x56, 0x78}
	attestedAccount := logicSigAddressForTest(t, bytecode)
	txn := paymentTransaction(t, attestedAccount, types.Address{19}.String(), 14)
	groupBytesHex := []string{txnutil.EncodeWithPrefixHex(txn)}
	group, decodeErr := verify.DecodeCanonicalGroupHex(groupBytesHex)
	if decodeErr != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", decodeErr)
	}

	userMsg := message.ComponentMessage(message.RoleUser, group.Entries[0].TxID)
	userSignature, err := signerops.New(nil).Sign(userPrivateKey, userMsg[:])
	if err != nil {
		t.Fatalf("Sign(user) error = %v", err)
	}
	attestorMsg := message.ComponentMessage(message.RoleAttestor, group.Entries[0].TxID)
	wrongSignature := stded25519.Sign(wrongPrivateKey, attestorMsg[:])

	keyMaterial := &coresigning.KeyMaterial{
		Type:                   keytypes.AttestedFalcon1024V1,
		Category:               keys.CategoryDSALsig,
		BaseKeyType:            falcon1024attested.BaseKeyType,
		PublicKey:              append([]byte(nil), userPublicKey...),
		Bytecode:               append([]byte(nil), bytecode...),
		Parameters:             map[string]string{keytypes.ParameterAttestorPublicKey: hex.EncodeToString(attestorPublicKey)},
		SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
		Value:                  &coresigning.LsigKeyMaterial{PrivateKey: append([]byte(nil), userPrivateKey...)},
	}
	session := &componentKeyTestSession{key: keyMaterial}

	result, signErr := assembleDecodedAttested(nil, signerapi.AttestedAssemblyRequest{
		RequestID:     "asm-bad-attestor",
		GroupBytesHex: groupBytesHex,
		Targets: []signerapi.AttestedAssemblyTarget{{
			TargetIndex:       0,
			AttestedAccount:   attestedAccount,
			UserSignature:     hex.EncodeToString(userSignature),
			AttestorSignature: hex.EncodeToString(wrongSignature),
		}},
	}, group, session)
	if result != nil {
		t.Fatalf("result = %#v, want nil", result)
	}
	if signErr == nil || signErr.Kind != ErrorBadRequest {
		t.Fatalf("assembleDecodedAttested() error = %#v, want bad request", signErr)
	}
	if !strings.Contains(signErr.Message, "attestor_signature invalid") {
		t.Fatalf("assembleDecodedAttested() error = %q, want attestor_signature invalid", signErr.Message)
	}
}

func TestSignPreparedAttestorComponentsSignsEd25519Messages(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, stded25519.SeedSize)
	privateKey := stded25519.NewKeyFromSeed(seed)
	publicKey := append([]byte(nil), privateKey.Public().(stded25519.PublicKey)...)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.AttestorComponentEd25519V1, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}

	keyMaterial := &coresigning.KeyMaterial{
		Type:     keytypes.AttestorComponentEd25519V1,
		Category: keys.CategoryComponent,
		Value: &coresigning.ComponentKeyMaterial{
			ComponentKey: componentKey,
			PublicKey:    append([]byte(nil), publicKey...),
			PrivateKey:   append([]byte(nil), privateKey...),
		},
	}
	session := &componentKeyTestSession{key: keyMaterial}
	plan := preparedAttestorComponentPlan(t, componentKey)

	result, signErr := signPreparedAttestorComponents(nil, plan, session)
	if signErr != nil {
		t.Fatalf("signPreparedAttestorComponents() error = %v", signErr)
	}
	if session.calls != 1 || session.gotAddress != componentKey {
		t.Fatalf("session calls = %d address %q, want one call for %q", session.calls, session.gotAddress, componentKey)
	}
	if result.RequestID != plan.RequestID || result.ComponentKey != componentKey {
		t.Fatalf("result metadata = %#v, want request_id %q component_key %q", result, plan.RequestID, componentKey)
	}
	if len(result.Signatures) != len(plan.Targets) {
		t.Fatalf("Signatures len = %d, want %d", len(result.Signatures), len(plan.Targets))
	}
	for i, sig := range result.Signatures {
		if sig.TargetIndex != plan.Targets[i].TargetIndex {
			t.Fatalf("signature %d target index = %d, want %d", i, sig.TargetIndex, plan.Targets[i].TargetIndex)
		}
		if sig.SignatureScheme != keytypes.AttestorComponentEd25519V1 {
			t.Fatalf("signature scheme = %q, want %s", sig.SignatureScheme, keytypes.AttestorComponentEd25519V1)
		}
		sigBytes, err := hex.DecodeString(sig.Signature)
		if err != nil {
			t.Fatalf("DecodeString(signature) error = %v", err)
		}
		if !stded25519.Verify(stded25519.PublicKey(publicKey), plan.Targets[i].Message[:], sigBytes) {
			t.Fatalf("signature %d does not verify over prepared component message", i)
		}
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil {
		t.Fatalf("key material was not zeroed after signing: %#v", keyMaterial)
	}
}

func TestSignPreparedAttestorComponentsSignsFalcon1024Messages(t *testing.T) {
	publicKey, privateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0x43}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	if len(publicKey) != falconfamily.PublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(publicKey), falconfamily.PublicKeySize)
	}
	componentKey, err := keytypes.ComponentKeySelector(keytypes.AttestorComponentFalcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}

	keyMaterial := &coresigning.KeyMaterial{
		Type:     keytypes.AttestorComponentFalcon1024V1,
		Category: keys.CategoryComponent,
		Value: &coresigning.ComponentKeyMaterial{
			ComponentKey: componentKey,
			PublicKey:    append([]byte(nil), publicKey...),
			PrivateKey:   append([]byte(nil), privateKey...),
		},
	}
	session := &componentKeyTestSession{key: keyMaterial}
	plan := preparedAttestorComponentPlan(t, componentKey)

	result, signErr := signPreparedAttestorComponents(nil, plan, session)
	if signErr != nil {
		t.Fatalf("signPreparedAttestorComponents() error = %v", signErr)
	}
	if session.calls != 1 || session.gotAddress != componentKey {
		t.Fatalf("session calls = %d address %q, want one call for %q", session.calls, session.gotAddress, componentKey)
	}
	if result.RequestID != plan.RequestID || result.ComponentKey != componentKey {
		t.Fatalf("result metadata = %#v, want request_id %q component_key %q", result, plan.RequestID, componentKey)
	}
	if len(result.Signatures) != len(plan.Targets) {
		t.Fatalf("Signatures len = %d, want %d", len(result.Signatures), len(plan.Targets))
	}
	for i, sig := range result.Signatures {
		if sig.TargetIndex != plan.Targets[i].TargetIndex {
			t.Fatalf("signature %d target index = %d, want %d", i, sig.TargetIndex, plan.Targets[i].TargetIndex)
		}
		if sig.SignatureScheme != keytypes.AttestorComponentFalcon1024V1 {
			t.Fatalf("signature scheme = %q, want %s", sig.SignatureScheme, keytypes.AttestorComponentFalcon1024V1)
		}
		sigBytes, err := hex.DecodeString(sig.Signature)
		if err != nil {
			t.Fatalf("DecodeString(signature) error = %v", err)
		}
		if err := verify.VerifyFalcon1024(publicKey, plan.Targets[i].Message[:], sigBytes); err != nil {
			t.Fatalf("signature %d does not verify over prepared component message: %v", i, err)
		}
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil {
		t.Fatalf("key material was not zeroed after signing: %#v", keyMaterial)
	}
}

func TestSignPreparedAttestorComponentsRejectsUserRoleBeforeKeyLoad(t *testing.T) {
	sender := types.Address{9}.String()
	receiver := types.Address{10}.String()
	txn := paymentTransaction(t, sender, receiver, 11)
	plan, err := PrepareComponentSigning(signerapi.ComponentSignRequest{
		RequestID:     "cmp-user",
		Role:          signerapi.ComponentSignRoleUser,
		ComponentKey:  sender,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	})
	if err != nil {
		t.Fatalf("PrepareComponentSigning() error = %v", err)
	}
	session := &componentKeyTestSession{}

	result, signErr := signPreparedAttestorComponents(nil, plan, session)
	if result != nil {
		t.Fatalf("result = %#v, want nil", result)
	}
	if signErr == nil || signErr.Kind != ErrorBadRequest {
		t.Fatalf("signPreparedAttestorComponents() error = %#v, want bad request", signErr)
	}
	if session.calls != 0 {
		t.Fatalf("session calls = %d, want 0 before role rejection", session.calls)
	}
}

func TestSignPreparedAttestorComponentsRejectsWrongKeyType(t *testing.T) {
	plan := preparedAttestorComponentPlan(t, strings.Repeat("11", stded25519.PublicKeySize))
	session := &componentKeyTestSession{key: &coresigning.KeyMaterial{Type: "ed25519"}}

	_, err := signPreparedAttestorComponents(nil, plan, session)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("signPreparedAttestorComponents() error = %#v, want bad request", err)
	}
}

func groupedPaymentTransactions(t *testing.T, sender, receiver string) []types.Transaction {
	t.Helper()
	txns := []types.Transaction{
		paymentTransaction(t, sender, receiver, 1),
		paymentTransaction(t, sender, receiver, 2),
	}
	groupID, err := algocrypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	txns[0].Group = groupID
	txns[1].Group = groupID
	return txns
}

func paymentTransaction(t *testing.T, sender, receiver string, amount uint64) types.Transaction {
	t.Helper()
	txn, err := transaction.MakePaymentTxn(
		sender,
		receiver,
		amount,
		nil,
		"",
		types.SuggestedParams{
			Fee:             types.MicroAlgos(1000),
			GenesisHash:     []byte("0123456789abcdef0123456789abcdef"),
			GenesisID:       "testnet-v1.0",
			FirstRoundValid: 10,
			LastRoundValid:  20,
		},
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}
	return txn
}

func logicSigAddressForTest(t *testing.T, bytecode []byte) string {
	t.Helper()
	lsig := algocrypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: append([]byte(nil), bytecode...)},
	}
	address, err := lsig.Address()
	if err != nil {
		t.Fatalf("LogicSigAccount.Address() error = %v", err)
	}
	return address.String()
}

func preparedAttestorComponentPlan(t *testing.T, componentKey string) *ComponentSignPlan {
	t.Helper()
	sender := types.Address{11}.String()
	receiver := types.Address{12}.String()
	txn := paymentTransaction(t, sender, receiver, 12)
	plan, err := PrepareComponentSigning(signerapi.ComponentSignRequest{
		RequestID:     "cmp-attestor",
		Role:          signerapi.ComponentSignRoleAttestor,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	})
	if err != nil {
		t.Fatalf("PrepareComponentSigning() error = %v", err)
	}
	return plan
}

type componentKeyTestSession struct {
	key        *coresigning.KeyMaterial
	err        error
	calls      int
	gotAddress string
}

func (s *componentKeyTestSession) GetKeyWithContext(_ context.Context, address string) (*coresigning.KeyMaterial, error) {
	s.calls++
	s.gotAddress = address
	if s.err != nil {
		return nil, s.err
	}
	return s.key, nil
}

type componentUserTestProvider struct {
	family     string
	messages   [][]byte
	signatures [][]byte
}

func (p *componentUserTestProvider) Family() string {
	return p.family
}

func (p *componentUserTestProvider) LoadKeysFromData(_ []byte) (*coresigning.KeyMaterial, error) {
	return nil, nil
}

func (p *componentUserTestProvider) SignMessage(_ *coresigning.KeyMaterial, msg []byte) ([]byte, error) {
	msgCopy := append([]byte(nil), msg...)
	signature := append([]byte("user-component-signature:"), msgCopy...)
	p.messages = append(p.messages, msgCopy)
	p.signatures = append(p.signatures, append([]byte(nil), signature...))
	return signature, nil
}

func (p *componentUserTestProvider) ZeroKey(key *coresigning.KeyMaterial) {
	if value, ok := key.Value.([]byte); ok {
		for i := range value {
			value[i] = 0
		}
	}
	key.Type = ""
	key.Value = nil
}

func (p *componentUserTestProvider) DetectKeyType(_ []byte, _ string) bool {
	return false
}

func TestLoadAttestorComponentKeyMapsMissingKey(t *testing.T) {
	session := &componentKeyTestSession{err: keystore.ErrKeyNotFound}
	_, _, err := loadAttestorComponentKey(nil, session, strings.Repeat("22", stded25519.PublicKeySize))
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("loadAttestorComponentKey() error = %#v, want bad request", err)
	}
}

func TestLoadAttestorComponentKeyRejectsMismatchedPublicPrivateKey(t *testing.T) {
	privateKey := stded25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, stded25519.SeedSize))
	wrongPublicKey := stded25519.NewKeyFromSeed(bytes.Repeat([]byte{0x45}, stded25519.SeedSize)).Public().(stded25519.PublicKey)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.AttestorComponentEd25519V1, wrongPublicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}

	keyMaterial := &coresigning.KeyMaterial{
		Type:     keytypes.AttestorComponentEd25519V1,
		Category: keys.CategoryComponent,
		Value: &coresigning.ComponentKeyMaterial{
			ComponentKey: componentKey,
			PublicKey:    append([]byte(nil), wrongPublicKey...),
			PrivateKey:   append([]byte(nil), privateKey...),
		},
	}
	session := &componentKeyTestSession{key: keyMaterial}

	_, _, loadErr := loadAttestorComponentKey(nil, session, componentKey)
	if loadErr == nil || loadErr.Kind != ErrorInternal {
		t.Fatalf("loadAttestorComponentKey() error = %#v, want internal", loadErr)
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil {
		t.Fatalf("key material was not zeroed after mismatch: %#v", keyMaterial)
	}
}
