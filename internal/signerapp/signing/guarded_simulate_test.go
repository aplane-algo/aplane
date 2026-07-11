// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	sentryverify "github.com/aplane-algo/aplane/internal/sentry/verify"
	"github.com/aplane-algo/aplane/internal/signerapi"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// falconUserSigningTestProvider signs user component messages with a real
// Falcon-1024 key so assembly verification passes against the stored public
// key, without requiring the production signer-side provider registration.
type falconUserSigningTestProvider struct {
	family string
}

func (p *falconUserSigningTestProvider) RoutingFamily() string {
	return p.family
}

func (p *falconUserSigningTestProvider) LoadKeyMaterial(_ coresigning.ProviderKey) (*coresigning.KeyMaterial, error) {
	return nil, nil
}

func (p *falconUserSigningTestProvider) SignMessage(km *coresigning.KeyMaterial, msg []byte) ([]byte, error) {
	lsigKM, ok := km.Value.(*coresigning.LsigKeyMaterial)
	if !ok || lsigKM == nil {
		return nil, fmt.Errorf("unexpected key material value %T", km.Value)
	}
	return signerops.New(nil).Sign(lsigKM.PrivateKey, msg)
}

func (p *falconUserSigningTestProvider) ZeroKey(key *coresigning.KeyMaterial) {
	if lsigKM, ok := key.Value.(*coresigning.LsigKeyMaterial); ok && lsigKM != nil {
		for i := range lsigKM.PrivateKey {
			lsigKM.PrivateKey[i] = 0
		}
	}
	key.Type = ""
	key.Value = nil
}

type guardedSimulateFixture struct {
	guardedAccount     string
	sender             string
	receiver           string
	txns               []types.Transaction
	groupBytesHex      []string
	userPublicKey      []byte
	sentrySignatureHex string
	passthroughHex     string
	freshKey           func() *coresigning.KeyMaterial
}

func newGuardedSimulateFixture(t *testing.T, baseKeyType string) *guardedSimulateFixture {
	t.Helper()

	sentrySeed := bytes.Repeat([]byte{0x61}, stded25519.SeedSize)
	sentryPrivateKey := stded25519.NewKeyFromSeed(sentrySeed)
	sentryPublicKey := append([]byte(nil), sentryPrivateKey.Public().(stded25519.PublicKey)...)

	userPublicKey, userPrivateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0x62}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	bytecode := []byte{0x06, 0x20, 0x01, 0x01, 0x22, 0x12, 0x34}
	guardedAccount := logicSigAddressForTest(t, bytecode)

	sender := types.Address{41}.String()
	receiver := types.Address{42}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)
	groupBytesHex := []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])}
	group, decodeErr := canonical.DecodeGroupHex(groupBytesHex)
	if decodeErr != nil {
		t.Fatalf("DecodeGroupHex() error = %v", decodeErr)
	}

	sentryMsg := message.ComponentMessage(message.RoleSentry, group.Entries[0].TxID)
	sentrySignature := stded25519.Sign(sentryPrivateKey, sentryMsg[:])
	passthroughBytes := msgpack.Encode(types.SignedTxn{Txn: txns[1], Sig: types.Signature{0x01}})

	privateKeyCopy := append([]byte(nil), userPrivateKey...)
	publicKeyCopy := append([]byte(nil), userPublicKey...)
	bytecodeCopy := append([]byte(nil), bytecode...)
	sentryPublicKeyHex := hex.EncodeToString(sentryPublicKey)

	return &guardedSimulateFixture{
		guardedAccount:     guardedAccount,
		sender:             sender,
		receiver:           receiver,
		txns:               txns,
		groupBytesHex:      groupBytesHex,
		userPublicKey:      publicKeyCopy,
		sentrySignatureHex: hex.EncodeToString(sentrySignature),
		passthroughHex:     hex.EncodeToString(passthroughBytes),
		freshKey: func() *coresigning.KeyMaterial {
			return &coresigning.KeyMaterial{
				Type:                   keytypes.GuardedFalcon1024SentryEd25519V1,
				Category:               keys.CategoryDSALsig,
				BaseKeyType:            baseKeyType,
				PublicKey:              append([]byte(nil), publicKeyCopy...),
				Bytecode:               append([]byte(nil), bytecodeCopy...),
				Parameters:             map[string]string{keytypes.ParameterSentryPublicKey: sentryPublicKeyHex},
				SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
				Value:                  &coresigning.LsigKeyMaterial{PrivateKey: append([]byte(nil), privateKeyCopy...)},
			}
		},
	}
}

func (fx *guardedSimulateFixture) request() signerapi.GuardedSimulateRequest {
	return signerapi.GuardedSimulateRequest{
		RequestID: "gsim-test",
		Requests: []signerapi.SignRequest{
			{TxnBytesHex: fx.groupBytesHex[0]},
			{TxnBytesHex: fx.groupBytesHex[1]},
		},
		Targets: []signerapi.GuardedSimulateTarget{{
			TargetIndex:     0,
			GuardedAccount:  fx.guardedAccount,
			SentrySignature: fx.sentrySignatureHex,
		}},
		Passthrough: []signerapi.GuardedPassthroughItem{{
			TargetIndex:  1,
			SignedTxnHex: fx.passthroughHex,
		}},
	}
}

func TestAssembleGuardedForSimulationProducesSignedGroupInternally(t *testing.T) {
	provider := &falconUserSigningTestProvider{family: "test.guarded-simulate-falcon.v1"}
	coresigning.Register(provider)
	fx := newGuardedSimulateFixture(t, provider.family)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: false}
	svc := newComponentGateService(audit, prompt.approvalService(audit), &policy.Config{})
	session := &cloningComponentSession{address: fx.guardedAccount, fresh: fx.freshKey}

	result, err := svc.assembleGuardedForSimulation(context.Background(), "default", fx.request(), session, nil)
	if err != nil {
		t.Fatalf("assembleGuardedForSimulation() error = %v", err)
	}
	if result.RequestID != "gsim-test" {
		t.Fatalf("RequestID = %q, want gsim-test", result.RequestID)
	}
	if prompt.calls != 0 {
		t.Fatalf("prompt calls = %d, want 0 for contained simulation", prompt.calls)
	}
	if len(audit.approved) != 0 {
		t.Fatalf("approved audit entries = %#v, want none for simulation", audit.approved)
	}
	if len(result.SignedGroup) != 2 {
		t.Fatalf("SignedGroup len = %d, want 2", len(result.SignedGroup))
	}
	if result.SignedGroup[1] != fx.passthroughHex {
		t.Fatalf("passthrough position = %q, want original passthrough", result.SignedGroup[1])
	}

	signedTargetBytes, decErr := hex.DecodeString(result.SignedGroup[0])
	if decErr != nil {
		t.Fatalf("DecodeString(signed target) error = %v", decErr)
	}
	var signedTarget types.SignedTxn
	if err := msgpack.Decode(signedTargetBytes, &signedTarget); err != nil {
		t.Fatalf("Decode(signed target) error = %v", err)
	}
	if signedTarget.AuthAddr.String() != fx.guardedAccount {
		t.Fatalf("signed target auth address = %q, want %q", signedTarget.AuthAddr.String(), fx.guardedAccount)
	}
	if len(signedTarget.Lsig.Args) != 2 {
		t.Fatalf("LogicSig args len = %d, want 2", len(signedTarget.Lsig.Args))
	}
	group, decodeErr := canonical.DecodeGroupHex(fx.groupBytesHex)
	if decodeErr != nil {
		t.Fatalf("DecodeGroupHex() error = %v", decodeErr)
	}
	userMsg := message.ComponentMessage(message.RoleUser, group.Entries[0].TxID)
	if verifyErr := sentryverify.VerifyFalcon1024(fx.userPublicKey, userMsg[:], signedTarget.Lsig.Args[0]); verifyErr != nil {
		t.Fatalf("internally produced user component signature does not verify: %v", verifyErr)
	}
	wantSentrySig, _ := hex.DecodeString(fx.sentrySignatureHex)
	if !bytes.Equal(signedTarget.Lsig.Args[1], wantSentrySig) {
		t.Fatalf("LogicSig arg 1 = %x, want sentry signature", signedTarget.Lsig.Args[1])
	}
}

func TestAssembleGuardedForSimulationRejectsPolicyViolation(t *testing.T) {
	provider := &falconUserSigningTestProvider{family: "test.guarded-simulate-policy.v1"}
	coresigning.Register(provider)
	fx := newGuardedSimulateFixture(t, provider.family)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: true}
	svc := newComponentGateService(audit, prompt.approvalService(audit), &policy.Config{MaxFeeMicroAlgos: 1})
	session := &cloningComponentSession{address: fx.guardedAccount, fresh: fx.freshKey}

	_, err := svc.assembleGuardedForSimulation(context.Background(), "default", fx.request(), session, nil)
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("assembleGuardedForSimulation() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, "policy engine rejected request") {
		t.Fatalf("assembleGuardedForSimulation() error = %q, want policy rejection", err.Message)
	}
	if prompt.calls != 0 {
		t.Fatalf("prompt calls = %d, want 0", prompt.calls)
	}
	if len(audit.rejected) != 1 {
		t.Fatalf("rejected audit entries = %#v, want 1", audit.rejected)
	}
}

func TestAssembleGuardedForSimulationSignsLocalLegs(t *testing.T) {
	provider := &falconUserSigningTestProvider{family: "test.guarded-simulate-local.v1"}
	coresigning.Register(provider)
	fx := newGuardedSimulateFixture(t, provider.family)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: false}
	svc := newComponentGateService(audit, prompt.approvalService(audit), &policy.Config{})
	session := &cloningComponentSession{address: fx.guardedAccount, fresh: fx.freshKey}

	req := fx.request()
	req.Passthrough = nil
	req.Requests[1].AuthAddress = fx.sender

	var gotLocalReq signerapi.GroupSignRequest
	localCalls := 0
	signLocal := func(_ context.Context, groupReq signerapi.GroupSignRequest) (*SignGroupResult, *ServiceError) {
		localCalls++
		gotLocalReq = groupReq
		return &SignGroupResult{Signed: []string{"", fx.passthroughHex}}, nil
	}

	result, err := svc.assembleGuardedForSimulation(context.Background(), "default", req, session, signLocal)
	if err != nil {
		t.Fatalf("assembleGuardedForSimulation() error = %v", err)
	}
	if localCalls != 1 {
		t.Fatalf("local signing calls = %d, want 1", localCalls)
	}
	if len(gotLocalReq.Requests) != 2 || gotLocalReq.Requests[1].AuthAddress != fx.sender {
		t.Fatalf("local signing request = %#v, want full group with sign-mode position 1", gotLocalReq)
	}
	if len(result.SignedGroup) != 2 || result.SignedGroup[1] != fx.passthroughHex {
		t.Fatalf("SignedGroup = %#v, want locally signed position 1", result.SignedGroup)
	}
}

func TestAssembleGuardedForSimulationRejectsUncoveredPosition(t *testing.T) {
	provider := &falconUserSigningTestProvider{family: "test.guarded-simulate-uncovered.v1"}
	coresigning.Register(provider)
	fx := newGuardedSimulateFixture(t, provider.family)

	svc := newComponentGateService(&testAuditLogger{}, (&componentGatePrompt{}).approvalService(&testAuditLogger{}), nil)
	session := &cloningComponentSession{address: fx.guardedAccount, fresh: fx.freshKey}

	req := fx.request()
	req.Passthrough = nil

	_, err := svc.assembleGuardedForSimulation(context.Background(), "default", req, session, nil)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("assembleGuardedForSimulation() error = %#v, want bad request", err)
	}
	if !strings.Contains(err.Message, "not covered") {
		t.Fatalf("assembleGuardedForSimulation() error = %q, want coverage error", err.Message)
	}
}
