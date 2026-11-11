// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cosigned

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/sshtunnel/sshtest"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/clientsign"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/witness"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestCosignedTargetsNormalizeCosignerPublicKey(t *testing.T) {
	sender := testAddress(1).String()
	cosignerHex := testCosignerPublicKeyHex(0xd6)
	s, _ := newCosignedTestSigner(t, sender, 1500, "0X"+strings.ToUpper(cosignerHex))
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "cosigned")

	if !s.HasCosignedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasCosignedEffectiveSigner() = false, want true")
	}

	targets, err := s.cosignedTargets([]types.Transaction{txn})
	if err != nil {
		t.Fatalf("cosignedTargets() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Index != 0 || targets[0].Sender != sender || targets[0].Account != sender {
		t.Fatalf("target = %+v, want index 0 sender/account %s", targets[0], sender)
	}
	if targets[0].CosignerComponentKeyType != witness.Falcon1024V1 {
		t.Fatalf("cosigner key type = %q, want %q", targets[0].CosignerComponentKeyType, witness.Falcon1024V1)
	}
	if targets[0].CosignerPublicKey != cosignerHex {
		t.Fatalf("cosigner public key = %q, want %q", targets[0].CosignerPublicKey, cosignerHex)
	}
}

func TestCosignedTargetsUseEffectiveSigner(t *testing.T) {
	sender := testAddress(1).String()
	cosigned := testAddress(3).String()
	cosignerHex := testCosignerPublicKeyHex(0xd6)
	s, _ := newCosignedTestSigner(t, cosigned, 1500, cosignerHex)
	s.authCache.AuthAddresses = map[string]string{sender: cosigned}
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "cosigned-authorizer")

	if !s.HasCosignedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasCosignedEffectiveSigner() = false, want true")
	}

	targets, err := s.cosignedTargets([]types.Transaction{txn})
	if err != nil {
		t.Fatalf("cosignedTargets() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Index != 0 || targets[0].Sender != sender || targets[0].Account != cosigned {
		t.Fatalf("target = %+v, want index 0 sender %s account %s", targets[0], sender, cosigned)
	}
	if targets[0].CosignerPublicKey != cosignerHex {
		t.Fatalf("cosigner public key = %q, want %q", targets[0].CosignerPublicKey, cosignerHex)
	}
}

func TestCosignedTargetsNormalizeFalconCosignerPublicKey(t *testing.T) {
	sender := testAddress(1).String()
	cosignerHex := testFalconCosignerPublicKeyHex(0xd6)
	s, _ := newCosignedTestSigner(t, sender, 1500, "0X"+strings.ToUpper(cosignerHex))
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "cosigned")

	if !s.HasCosignedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasCosignedEffectiveSigner() = false, want true")
	}

	targets, err := s.cosignedTargets([]types.Transaction{txn})
	if err != nil {
		t.Fatalf("cosignedTargets() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].CosignerComponentKeyType != witness.Falcon1024V1 {
		t.Fatalf("cosigner key type = %q, want %q", targets[0].CosignerComponentKeyType, witness.Falcon1024V1)
	}
	if targets[0].CosignerPublicKey != cosignerHex {
		t.Fatalf("cosigner public key = %q, want %q", targets[0].CosignerPublicKey, cosignerHex)
	}
}

func TestCosignedTargetsRequireCosignerMetadata(t *testing.T) {
	sender := testAddress(1).String()
	s, _ := newCosignedTestSigner(t, sender, 1500, "")
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "cosigned")

	_, err := s.cosignedTargets([]types.Transaction{txn})
	if err == nil || !strings.Contains(err.Error(), "missing cosigner_public_key") {
		t.Fatalf("cosignedTargets() error = %v, want missing cosigner_public_key", err)
	}
}

func TestCosignedTargetsRejectUnsupportedSigningFlow(t *testing.T) {
	sender := testAddress(1).String()
	cosignerHex := testCosignerPublicKeyHex(0xd6)
	s, sc := newCosignedTestSigner(t, sender, 1500, cosignerHex)
	sc.SetSigningFlowForAddress(sender, "cosigner2")
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "cosigned")

	if !s.HasCosignedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasCosignedEffectiveSigner() = false, want true for unknown flow (must not fall through to /sign)")
	}
	_, err := s.cosignedTargets([]types.Transaction{txn})
	if err == nil || !strings.Contains(err.Error(), `signing flow "cosigner2"`) {
		t.Fatalf("cosignedTargets() error = %v, want unsupported signing flow rejection", err)
	}
}

func TestCosignedTargetsDispatchBoundedOutsideCosignerFlow(t *testing.T) {
	sender := testAddress(1).String()
	s, sc := newCosignedTestSigner(t, sender, 1500, testCosignerPublicKeyHex(0xd6))
	sc.SetSigningFlowForAddress(sender, signerapi.SigningFlowBounded1)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "bounded")

	if s.HasCosignedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("HasCosignedEffectiveSigner() = true for bounded1")
	}
	targets, err := s.cosignedTargets([]types.Transaction{txn})
	if err != nil {
		t.Fatalf("cosignedTargets() error = %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("cosignedTargets() = %#v, want no cosigner targets", targets)
	}
}

func TestBoundedCosignerTargetsAndComponentRequestShape(t *testing.T) {
	bounded := testAddress(1).String()
	plain := testAddress(2).String()
	cosignerHex := testCosignerPublicKeyHex(0xd6)
	s, sc := newTestSigner(t, func(c *cache.SignerCache) {
		c.AddAddress(bounded, "test.bounded-cosigner.v1")
		c.SetSigningFlowForAddress(bounded, signerapi.SigningFlowCosigned1)
		c.SetCosignerComponentKeyTypeForAddress(bounded, witness.Falcon1024V1)
		c.SetCosignerPublicKeyForAddress(bounded, cosignerHex)
		c.SetBoundedContractForAddress(bounded, signerapi.BoundedContractBounded2)
		c.SetBoundedMaxFeeForAddress(bounded, 10_000)
		setTestLogicSigResources(c, bounded, 4000)
		c.AddAddress(plain, "aplane.falcon1024.v1")
		setTestLogicSigResources(c, plain, 1700)
	})
	txns := []types.Transaction{
		testPaymentTxn(t, testAddress(1), testAddress(3), "bounded"),
		testPaymentTxn(t, testAddress(2), testAddress(3), "plain"),
	}
	targets, err := s.cosignedTargets(txns)
	if err != nil || len(targets) != 1 || targets[0].Route != flowRouteBoundedCosigner {
		t.Fatalf("cosignedTargets() = %#v, %v", targets, err)
	}
	if targets[0].BoundedMaxFee == nil || *targets[0].BoundedMaxFee != 10_000 {
		t.Fatalf("bounded max fee = %v, want 10000", targets[0].BoundedMaxFee)
	}
	requests, err := s.buildBoundedComponentRequests(txns, map[int]cosignedTarget{0: targets[0]}, clientsign.SubmitOptions{
		LsigArgsMap: []map[string][]byte{{"preimage": {0xaa}}, nil},
	})
	if err != nil {
		t.Fatalf("buildBoundedComponentRequests() error = %v", err)
	}
	if mode, _ := requests[0].Mode(); mode != signerapi.RequestModeSign || requests[0].AuthAddress != bounded || requests[0].LsigArgs["preimage"] != "aa" {
		t.Fatalf("bounded request = %#v", requests[0])
	}
	// The signer holds the plain account too, so it is sent as the signer's
	// own, with no size hint.
	if mode, _ := requests[1].Mode(); mode != signerapi.RequestModeSign || requests[1].LsigResources != nil {
		t.Fatalf("plain context request = %#v", requests[1])
	}
	if sc.SigningFlowForAddress(bounded) != signerapi.SigningFlowCosigned1 || !s.HasCosignedEffectiveSigner(txns) {
		t.Fatal("bounded-cosigner flow did not enter cosigned orchestration")
	}
}

func TestCosignedTargetsRequireCosignerComponentKeyTypeMetadata(t *testing.T) {
	sender := testAddress(1).String()
	cosignerHex := testCosignerPublicKeyHex(0xd6)
	s, sc := newCosignedTestSigner(t, sender, 1500, cosignerHex)
	sc.SetCosignerComponentKeyTypeForAddress(sender, "")
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "cosigned")

	_, err := s.cosignedTargets([]types.Transaction{txn})
	if err == nil || !strings.Contains(err.Error(), "missing cosigner_component_key_type") {
		t.Fatalf("cosignedTargets() error = %v, want missing cosigner_component_key_type", err)
	}
}

func TestCollectComponentSignaturesRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name        string
		resp        *signerapi.ComponentResponse
		wantMessage string
	}{
		{
			name:        "empty response",
			resp:        nil,
			wantMessage: "empty component sign response",
		},
		{
			name: "unexpected target index",
			resp: &signerapi.ComponentResponse{Components: []signerapi.Component{{
				TargetIndex:     9,
				SignatureScheme: witness.Falcon1024V1,
				Signature:       "aa",
			}}},
			wantMessage: "unexpected signature for target index 9",
		},
		{
			name: "duplicate target index",
			resp: &signerapi.ComponentResponse{Components: []signerapi.Component{{
				TargetIndex:     0,
				SignatureScheme: witness.Falcon1024V1,
				Signature:       "aa",
			}, {
				TargetIndex:     0,
				SignatureScheme: witness.Falcon1024V1,
				Signature:       "bb",
			}}},
			wantMessage: "duplicate signature for target index 0",
		},
		{
			name: "wrong scheme",
			resp: &signerapi.ComponentResponse{Components: []signerapi.Component{{
				TargetIndex:     0,
				SignatureScheme: "aplane.cosigner-unknown.v1",
				Signature:       "aa",
			}, {
				TargetIndex:     1,
				SignatureScheme: witness.Falcon1024V1,
				Signature:       "bb",
			}}},
			wantMessage: "signature for target index 0 used scheme",
		},
		{
			name: "missing target index",
			resp: &signerapi.ComponentResponse{Components: []signerapi.Component{{
				TargetIndex:     0,
				SignatureScheme: witness.Falcon1024V1,
				Signature:       "aa",
			}}},
			wantMessage: "missing signature for target index 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst := map[int]string{}
			err := collectComponentSignatures(
				tt.resp,
				[]int{0, 1},
				witness.Falcon1024V1,
				dst,
			)
			if err == nil {
				t.Fatal("collectComponentSignatures() error = nil, want malformed response rejection")
			}
			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Fatalf("collectComponentSignatures() error = %q, want %q", err, tt.wantMessage)
			}
		})
	}
}

func TestRequestCosignerComponentSignaturesUsesConfiguredSSHEndpoint(t *testing.T) {
	publicKey, privateKey := testFalconCosignerKeypair(t, 0x61)
	cosignerHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "cosigned")
	groupBytesHex := encodeGroupHex([]types.Transaction{txn})
	node := newCosignerEndpointNode(t, cosignerHex, privateKey, nil)
	s, _ := newCosignedTestSigner(t, txn.Sender.String(), 1500, cosignerHex)
	s.endpointRegistry = cosignerEndpointRegistry("cosigner-ssh", cosignerNodeEndpoint(node))

	signatures, requestIDs, err := s.requestCosignerComponentSignatures(
		context.Background(),
		groupBytesHex,
		len(groupBytesHex),
		[]cosignedTarget{cosignedTargetForTest(txn.Sender.String(), cosignerHex)},
		nil,
	)
	if err != nil {
		t.Fatalf("requestCosignerComponentSignatures() error = %v", err)
	}
	if signatures[0] == "" {
		t.Fatal("signature for target 0 is empty")
	}
	if requestIDs[cosignerRequestKey{ComponentKeyType: witness.Falcon1024V1, PublicKey: cosignerHex}] == "" {
		t.Fatal("request ID for cosigner is empty")
	}
}

func TestComponentRequestForIndicesDeclaresPlannerDummySuffix(t *testing.T) {
	request := componentRequestForIndices(
		[]string{"TX00", "TX11", "TX22"},
		2,
		[]int{0},
		signerapi.ComponentTargetKindCosigner,
		"COMPONENT",
		[]*signerapi.AppCallInfo{{Mode: "abi", Method: "do(uint64)void"}, {Mode: "raw"}},
	)
	if len(request.Targets) != 1 || request.Targets[0].TargetIndex != 0 {
		t.Fatalf("targets = %#v, want target 0", request.Targets)
	}
	if len(request.ContextualPositions) != 1 || request.ContextualPositions[0].TargetIndex != 1 {
		t.Fatalf("contextual positions = %#v, want original position 1", request.ContextualPositions)
	}
	if len(request.DummyPositions) != 1 || request.DummyPositions[0].TargetIndex != 2 {
		t.Fatalf("dummy positions = %#v, want planner-appended position 2", request.DummyPositions)
	}
	if request.Targets[0].AppCallInfo == nil || request.Targets[0].AppCallInfo.Method != "do(uint64)void" {
		t.Fatalf("target app-call metadata = %#v, want ABI method", request.Targets[0].AppCallInfo)
	}
	if request.ContextualPositions[0].AppCallInfo == nil || request.ContextualPositions[0].AppCallInfo.Mode != "raw" {
		t.Fatalf("context app-call metadata = %#v, want raw", request.ContextualPositions[0].AppCallInfo)
	}
}

func TestRequestCosignerComponentSignaturesExplicitMismatchDoesNotFallback(t *testing.T) {
	publicKey, privateKey := testFalconCosignerKeypair(t, 0x62)
	wrongPublicKey, wrongPrivateKey := testFalconCosignerKeypair(t, 0x63)
	cosignerHex := hex.EncodeToString(publicKey)
	wrongHex := hex.EncodeToString(wrongPublicKey)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "cosigned")
	groupBytesHex := encodeGroupHex([]types.Transaction{txn})

	selfServer := newCosignerEndpointTestServer(t, cosignerHex, privateKey, nil)
	defer selfServer.Close()
	var wrongSignCalls atomic.Int32
	wrongNode := newCosignerEndpointNode(t, wrongHex, wrongPrivateKey, &wrongSignCalls)

	s, _ := newCosignedTestSigner(t, txn.Sender.String(), 1500, cosignerHex)
	s.conn.SignerClient = signerclient.NewSignerClient(selfServer.URL)
	s.endpointRegistry = cosignerEndpointRegistry("cosigner-wrong", cosignerNodeEndpoint(wrongNode))

	_, _, err := s.requestCosignerComponentSignatures(
		context.Background(),
		groupBytesHex,
		len(groupBytesHex),
		[]cosignedTarget{cosignedTargetForTest(txn.Sender.String(), cosignerHex)},
		nil,
	)
	if err == nil {
		t.Fatal("requestCosignerComponentSignatures() error = nil, want explicit endpoint mismatch")
	}
	componentSelector, selectorErr := cosignerComponentSelector(witness.Falcon1024V1, cosignerHex)
	if selectorErr != nil {
		t.Fatalf("cosignerComponentSelector() error = %v", selectorErr)
	}
	errText := err.Error()
	if !strings.Contains(errText, "no live cosigner route for Witness Key ID") || !strings.Contains(errText, componentSelector) {
		t.Fatalf("requestCosignerComponentSignatures() error = %q, want endpoint mismatch with Witness Key ID %s", err, componentSelector)
	}
	if strings.Contains(errText, cosignerHex) {
		t.Fatalf("requestCosignerComponentSignatures() error exposed raw cosigner public key: %q", err)
	}
	if got := wrongSignCalls.Load(); got != 0 {
		t.Fatalf("wrong endpoint /sign/component calls = %d, want 0", got)
	}
}

func TestRequestCosignerComponentSignaturesReportsLockedEndpoint(t *testing.T) {
	publicKey, _ := testFalconCosignerKeypair(t, 0x64)
	cosignerHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "cosigned")
	groupBytesHex := encodeGroupHex([]types.Transaction{txn})

	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"signer is locked"}`, http.StatusForbidden)
	})
	node := sshtest.Serve(t, mux)

	s, _ := newCosignedTestSigner(t, txn.Sender.String(), 1500, cosignerHex)
	s.endpointRegistry = cosignerEndpointRegistry("cosigner-locked", cosignerNodeEndpoint(node))

	_, _, err := s.requestCosignerComponentSignatures(
		context.Background(),
		groupBytesHex,
		len(groupBytesHex),
		[]cosignedTarget{cosignedTargetForTest(txn.Sender.String(), cosignerHex)},
		nil,
	)
	if err == nil {
		t.Fatal("requestCosignerComponentSignatures() error = nil, want locked endpoint")
	}
	if !errors.Is(err, ErrCosignerDiscoveryLocked) {
		t.Fatalf("requestCosignerComponentSignatures() error = %q, want ErrCosignerDiscoveryLocked", err)
	}
	if !strings.Contains(err.Error(), "cosigner-locked: signer locked") {
		t.Fatalf("requestCosignerComponentSignatures() error = %q, want locked endpoint summary", err)
	}
	if strings.Contains(err.Error(), "did not advertise cosigner") {
		t.Fatalf("requestCosignerComponentSignatures() error = %q, should not report missing cosigner", err)
	}
}

func TestRequestCosignerComponentSignaturesUsesExplicitLoopbackEndpoint(t *testing.T) {
	publicKey, privateKey := testFalconCosignerKeypair(t, 0x65)
	cosignerHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "cosigned")
	groupBytesHex := encodeGroupHex([]types.Transaction{txn})
	node := newCosignerEndpointNode(t, cosignerHex, privateKey, nil)
	s, _ := newCosignedTestSigner(t, txn.Sender.String(), 1500, cosignerHex)
	s.endpointRegistry = cosignerEndpointRegistry("local-cosigner", cosignerNodeEndpoint(node))

	signatures, _, err := s.requestCosignerComponentSignatures(
		context.Background(),
		groupBytesHex,
		len(groupBytesHex),
		[]cosignedTarget{cosignedTargetForTest(txn.Sender.String(), cosignerHex)},
		nil,
	)
	if err != nil {
		t.Fatalf("requestCosignerComponentSignatures() error = %v", err)
	}
	if signatures[0] == "" {
		t.Fatal("signature for target 0 is empty")
	}
}

// cosignerNodeEndpoint is the endpoint configuration that reaches node with
// the test client's enrolled identity.
func cosignerNodeEndpoint(node *sshtest.Node) config.ClientEndpointConfig {
	return config.ClientEndpointConfig{URL: node.URL, IdentityFile: node.IdentityFile, KnownHostsPath: node.KnownHostsPath}
}

func cosignerEndpointRegistry(alias string, endpoint config.ClientEndpointConfig) config.ClientEndpointRegistry {
	endpoint.Role = config.ClientEndpointRoleCosigner
	return config.ClientEndpointRegistry{
		SchemaVersion: config.ClientEndpointSchemaVersion,
		Endpoints:     map[string]config.ClientEndpointConfig{alias: endpoint},
	}
}

func TestDecodeCosignedSignedGroupReturnsSignedObjects(t *testing.T) {
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "cosigned")
	signedHex := []string{hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn}))}

	signedBytes, signedObjects, txns, err := decodeCosignedSignedGroup(signedHex)
	if err != nil {
		t.Fatalf("decodeCosignedSignedGroup() error = %v", err)
	}
	if len(signedBytes) != 1 || len(signedObjects) != 1 || len(txns) != 1 {
		t.Fatalf("decoded lengths = %d/%d/%d, want 1/1/1", len(signedBytes), len(signedObjects), len(txns))
	}
	if signedObjects[0].Txn.Sender != txn.Sender || txns[0].Sender != txn.Sender {
		t.Fatalf("decoded sender = %s/%s, want %s", signedObjects[0].Txn.Sender, txns[0].Sender, txn.Sender)
	}
}

// The assembled bytes are submitted as returned and the decoded transactions
// are what is checked against the frozen group, so bytes that decode to the
// right transaction but are not its canonical encoding are refused.
func TestDecodeCosignedSignedGroupRefusesBytesThatAreNotCanonical(t *testing.T) {
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "cosigned")
	signed := msgpack.Encode(types.SignedTxn{Txn: txn, Sig: types.Signature{1}})
	repeated := append([]byte{signed[0] + 1}, signed[1:]...)
	repeated = append(repeated, msgpack.Encode(map[string]types.Signature{"sig": {2}})[1:]...)

	for name, raw := range map[string][]byte{
		"trailing byte":      append(append([]byte{}, signed...), 0xc0),
		"second transaction": append(append([]byte{}, signed...), signed...),
		"repeated field":     repeated,
	} {
		_, _, _, err := decodeCosignedSignedGroup([]string{hex.EncodeToString(raw)})
		if !errors.Is(err, canonical.ErrNotCanonical) || !strings.HasPrefix(err.Error(), "assembled signed transaction 1: ") {
			t.Errorf("%s: error = %v, want refused as not canonical", name, err)
		}
	}
}

// testCacheView adapts a cache.SignerCache to SignerCacheView for tests.
type testCacheView struct{ c *cache.SignerCache }

func (v testCacheView) AuthorizationKind(address string) (string, bool) {
	if !v.c.HasAddress(address) {
		return "", false
	}
	if v.c.IsGenericLsig(address) {
		return authorizationLogicSig, true
	}
	if _, ok := v.c.LogicSigResourceProfile(address); ok {
		return authorizationLogicSig, true
	}
	keyType := v.c.GetKeyType(address)
	if keyType == "ed25519" {
		return "ed25519", true
	}
	if keyType == "falcon1024" {
		return authorizationNativePQ, true
	}
	return "", true
}

func (v testCacheView) SigningFlow(address string) string { return v.c.SigningFlowForAddress(address) }
func (v testCacheView) CosignerComponentKeyType(address string) (string, bool) {
	return v.c.CosignerComponentKeyTypeForAddress(address)
}
func (v testCacheView) CosignerPublicKey(address string) (string, bool) {
	return v.c.CosignerPublicKeyForAddress(address)
}
func (v testCacheView) BoundedContract(address string) (string, bool) {
	return v.c.BoundedContractForAddress(address)
}
func (v testCacheView) BoundedMaxFee(address string) (uint64, bool) {
	return v.c.BoundedMaxFeeForAddress(address)
}
func (v testCacheView) LogicSigResourceProfile(address string) (lsigresource.Profile, bool) {
	return v.c.LogicSigResourceProfile(address)
}

// newTestSigner builds a Signer over a populated signer cache, a fresh
// in-memory auth cache, and an unconnected connection state. Tests reach the
// auth cache, connection, and cosigner endpoints directly through the Signer's
// fields (same package), and the returned cache for post-construction
// metadata edits.
func newTestSigner(t *testing.T, build func(c *cache.SignerCache)) (*Signer, *cache.SignerCache) {
	t.Helper()
	signerCache := cache.NewSignerCache()
	if build != nil {
		build(&signerCache)
	}
	authCache := cache.NewAuthAddressCache()
	s := New(Deps{
		Conn:      connect.NewState(),
		AuthCache: &authCache,
		Cache:     testCacheView{&signerCache},
	})
	return s, &signerCache
}

// newCosignedTestSigner holds one cosigned plain host, with the signing-flow
// metadata the daemon serves for it.
func newCosignedTestSigner(t *testing.T, sender string, programBytes int, cosignerPublicKey string) (*Signer, *cache.SignerCache) {
	t.Helper()
	return newTestSigner(t, func(signerCache *cache.SignerCache) {
		signerCache.AddAddress(sender, "aplane.falcon1024.v1")
		signerCache.SetSigningFlowForAddress(sender, signerapi.SigningFlowCosigned1)
		signerCache.SetCosignerComponentKeyTypeForAddress(sender, witness.Falcon1024V1)
		signerCache.SetBoundedContractForAddress(sender, signerapi.BoundedContractPlain1)
		if programBytes > 0 {
			setTestCosignedResources(signerCache, sender, programBytes)
		}
		if cosignerPublicKey != "" {
			signerCache.SetCosignerPublicKeyForAddress(sender, cosignerPublicKey)
		}
	})
}

func setTestLogicSigResources(signerCache *cache.SignerCache, address string, programBytes int) {
	signerCache.SetLogicSigResourceProfile(address, lsigresource.Profile{
		ProgramBytes: uint64(programBytes),
		Default:      &lsigresource.PathProfile{MaxOpcodeCost: 1},
	})
}

func testAddress(index int) types.Address {
	var addr types.Address
	addr[0] = byte(index)
	addr[1] = byte(index >> 8)
	return addr
}

// testPaymentTxn builds a minimal payment transaction for cosigned planning
// and component-signing tests.
func testPaymentTxn(t *testing.T, from, to types.Address, note string) types.Transaction {
	t.Helper()
	sp := types.SuggestedParams{
		Fee:             1000,
		FlatFee:         true,
		FirstRoundValid: 1,
		LastRoundValid:  100,
		GenesisID:       "testnet-v1.0",
		GenesisHash:     []byte("12345678901234567890123456789012"),
	}
	txn, err := transaction.MakePaymentTxn(from.String(), to.String(), 1234, []byte(note), "", sp)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}
	return txn
}

func testCosignerPublicKeyHex(prefix byte) string {
	var publicKey [falconfamily.PublicKeySize]byte
	publicKey[0] = prefix
	return hex.EncodeToString(publicKey[:])
}

func testFalconCosignerPublicKeyHex(prefix byte) string {
	publicKey := make([]byte, falconfamily.PublicKeySize)
	publicKey[0] = prefix
	return hex.EncodeToString(publicKey)
}

func cosignedTargetForTest(account, cosignerHex string) cosignedTarget {
	return cosignedTarget{
		Index:                    0,
		Sender:                   account,
		Account:                  account,
		CosignerComponentKeyType: witness.Falcon1024V1,
		CosignerPublicKey:        cosignerHex,
		Route:                    flowRouteBoundedCosigner,
		BoundedPath:              signerapi.ComponentPathSpend,
	}
}

func TestCosignerComponentLabelUsesFalconCosignerKeyID(t *testing.T) {
	cosignerHex := testFalconCosignerPublicKeyHex(0x0a)
	componentSelector, err := cosignerComponentSelector(witness.Falcon1024V1, cosignerHex)
	if err != nil {
		t.Fatalf("cosignerComponentSelector() error = %v", err)
	}

	label := cosignerComponentLabel(witness.Falcon1024V1, cosignerHex)
	if !strings.Contains(label, componentSelector) || !strings.Contains(label, witness.Falcon1024V1) {
		t.Fatalf("cosignerComponentLabel() = %q, want Witness Key ID %s and key type", label, componentSelector)
	}
	if strings.Contains(label, cosignerHex) {
		t.Fatalf("cosignerComponentLabel() exposed raw Falcon cosigner public key: %q", label)
	}
}

// newCosignerEndpointTestServer serves a cosigner node's surface over
// loopback HTTP, for the user signer client that is pointed at it directly.
func newCosignerEndpointTestServer(t *testing.T, publicKeyHex string, privateKey []byte, signCalls *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(cosignerEndpointHandler(t, publicKeyHex, privateKey, signCalls))
}

// newCosignerEndpointNode starts an in-process cosigner node reachable over
// SSH with the test client's enrolled key.
func newCosignerEndpointNode(t *testing.T, publicKeyHex string, privateKey []byte, signCalls *atomic.Int32) *sshtest.Node {
	t.Helper()
	return sshtest.Serve(t, cosignerEndpointHandler(t, publicKeyHex, privateKey, signCalls))
}

func cosignerEndpointHandler(t *testing.T, publicKeyHex string, privateKey []byte, signCalls *atomic.Int32) http.Handler {
	t.Helper()
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("decode cosigner public key: %v", err)
	}
	componentSelector, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("Witness Key ID: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{
			Count: 1,
			Keys: []signerapi.KeyInfo{{
				Address:      componentSelector,
				PublicKeyHex: publicKeyHex,
				KeyType:      witness.Falcon1024V1,
				IsWitnessKey: true,
			}},
		})
	})
	mux.HandleFunc("/sign/component", func(w http.ResponseWriter, r *http.Request) {
		if signCalls != nil {
			signCalls.Add(1)
		}
		var req signerapi.ComponentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.TargetKind() != signerapi.ComponentTargetKindCosigner || req.Targets[0].ComponentKey != componentSelector {
			http.Error(w, "wrong Witness Key ID", http.StatusBadRequest)
			return
		}
		group, err := canonical.DecodeGroupHex(req.GroupBytesHex)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := signerapi.ComponentResponse{
			RequestID:  req.RequestID,
			Components: make([]signerapi.Component, 0, len(req.Targets)),
		}
		for _, target := range req.Targets {
			msg := message.ComponentMessage(message.RoleCosigner, group.Entries[target.TargetIndex].TxID)
			signature, err := signerops.New(nil).Sign(privateKey, msg[:])
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			resp.Components = append(resp.Components, signerapi.Component{
				TargetIndex:     target.TargetIndex,
				Kind:            signerapi.ComponentTargetKindCosigner,
				SignatureScheme: witness.Falcon1024V1,
				Signature:       hex.EncodeToString(signature),
			})
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	return mux
}

func testFalconCosignerKeypair(t *testing.T, fill byte) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{fill}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	return publicKey, privateKey
}

func TestVerifyAssembledAgainstFrozen(t *testing.T) {
	txnA := testPaymentTxn(t, testAddress(1), testAddress(2), "cosigned")
	txnB := testPaymentTxn(t, testAddress(3), testAddress(4), "cosigned")
	frozen := encodeGroupHex([]types.Transaction{txnA, txnB})

	if err := verifyAssembledAgainstFrozen(frozen, []types.Transaction{txnA, txnB}); err != nil {
		t.Fatalf("matching group: unexpected error %v", err)
	}
	if err := verifyAssembledAgainstFrozen(frozen, []types.Transaction{txnA}); err == nil {
		t.Fatal("wrong length: expected error, got nil")
	}
	if err := verifyAssembledAgainstFrozen(frozen, []types.Transaction{txnA, txnA}); err == nil {
		t.Fatal("substituted transaction: expected error, got nil")
	}
}

func TestValidatePlannedGroup(t *testing.T) {
	original := testPaymentTxn(t, testAddress(1), testAddress(2), "bounded")
	plannedOriginal := original
	plannedOriginal.Fee += 1_000
	dummies, err := signing.CreateDummyTransactions(1, suggestedParamsFromTxn(original))
	if err != nil {
		t.Fatal(err)
	}
	planned := []types.Transaction{plannedOriginal, dummies[0]}
	regroupForTest(t, planned)
	plannedOriginal = planned[0]
	mutations := &signerapi.MutationReport{
		DummiesAdded: 1, GroupIDChanged: true, FeesModified: []int{0},
		TotalFeesDelta: 1_000, OriginalCount: 1, FinalCount: 2,
	}

	if err := validatePlannedGroup([]types.Transaction{original}, planned, mutations); err != nil {
		t.Fatalf("valid plan: unexpected error %v", err)
	}

	t.Run("wrong counts", func(t *testing.T) {
		bad := *mutations
		bad.OriginalCount = 2
		if err := validatePlannedGroup([]types.Transaction{original}, planned, &bad); err == nil || !strings.Contains(err.Error(), "original_count") {
			t.Fatalf("error = %v, want original_count rejection", err)
		}
	})
	t.Run("unreported original mutation", func(t *testing.T) {
		badPlanned := append([]types.Transaction(nil), planned...)
		badPlanned[0].Receiver = testAddress(3)
		// Zero-based, as this path's other positions are.
		if err := validatePlannedGroup([]types.Transaction{original}, badPlanned, mutations); err == nil || !strings.Contains(err.Error(), "unreported fields at original index 0") {
			t.Fatalf("error = %v, want original mutation rejection", err)
		}
	})
	t.Run("unreported fee mutation", func(t *testing.T) {
		bad := *mutations
		bad.FeesModified = nil
		bad.TotalFeesDelta = 0
		if err := validatePlannedGroup([]types.Transaction{original}, planned, &bad); err == nil || !strings.Contains(err.Error(), "unreported fields") {
			t.Fatalf("error = %v, want fee mutation rejection", err)
		}
	})
	t.Run("wrong fee delta", func(t *testing.T) {
		bad := *mutations
		bad.TotalFeesDelta++
		if err := validatePlannedGroup([]types.Transaction{original}, planned, &bad); err == nil || !strings.Contains(err.Error(), "total_fees_delta") {
			t.Fatalf("error = %v, want fee delta rejection", err)
		}
	})
	// The plain /sign path's reconciliation, shared here.
	t.Run("reported fee unchanged", func(t *testing.T) {
		unchanged := append([]types.Transaction(nil), planned...)
		unchanged[0].Fee = original.Fee
		bad := *mutations
		bad.TotalFeesDelta = 0
		if err := validatePlannedGroup([]types.Transaction{original}, unchanged, &bad); err == nil || !strings.Contains(err.Error(), "original index 0 did not increase the fee") {
			t.Fatalf("error = %v, want an unchanged reported fee refused", err)
		}
	})
	t.Run("negative fee delta", func(t *testing.T) {
		bad := *mutations
		bad.TotalFeesDelta = -1
		if err := validatePlannedGroup([]types.Transaction{original}, planned, &bad); err == nil || !strings.Contains(err.Error(), "must not be negative") {
			t.Fatalf("error = %v, want a negative total refused", err)
		}
	})
	t.Run("fee rises that overflow", func(t *testing.T) {
		second := testPaymentTxn(t, testAddress(3), testAddress(4), "bounded")
		pair := []types.Transaction{original, second}
		overflowing := append([]types.Transaction(nil), pair...)
		for i := range overflowing {
			overflowing[i].Fee += 1 << 63
		}
		report := &signerapi.MutationReport{
			FeesModified: []int{0, 1}, GroupIDChanged: true, OriginalCount: 2, FinalCount: 2,
		}
		if err := validatePlannedGroup(pair, overflowing, report); err == nil || !strings.Contains(err.Error(), "overflows uint64") {
			t.Fatalf("error = %v, want rises that wrap around refused", err)
		}
	})
	// Appended positions get the canonical dummy check every other path runs,
	// which the cosigned client's own shape check lacked: the validity window,
	// genesis and lease have to be the planner's too.
	for name, edit := range map[string]func(*types.Transaction){
		"amount":       func(txn *types.Transaction) { txn.Amount = 1 },
		"first valid":  func(txn *types.Transaction) { txn.FirstValid++ },
		"last valid":   func(txn *types.Transaction) { txn.LastValid++ },
		"genesis hash": func(txn *types.Transaction) { txn.GenesisHash[0] ^= 0xff },
		"genesis id":   func(txn *types.Transaction) { txn.GenesisID = "othernet-v1" },
		"lease":        func(txn *types.Transaction) { txn.Lease = [32]byte{7} },
		"note":         func(txn *types.Transaction) { txn.Note = []byte{9} },
	} {
		t.Run("appended dummy with another "+name, func(t *testing.T) {
			badPlanned := append([]types.Transaction(nil), planned...)
			edit(&badPlanned[1])
			regroupForTest(t, badPlanned)
			if err := validatePlannedGroup([]types.Transaction{original}, badPlanned, mutations); err == nil || !strings.Contains(err.Error(), "canonical resource dummy") {
				t.Fatalf("error = %v, want the dummy refused", err)
			}
			if _, err := signCosignedDummies(frozenGroup{Txns: badPlanned, OriginalCount: 1}); err == nil || !strings.Contains(err.Error(), "canonical resource dummy") {
				t.Fatalf("signCosignedDummies() error = %v, want the dummy refused before it is signed", err)
			}
		})
	}
	t.Run("appended dummy outside the group", func(t *testing.T) {
		badPlanned := append([]types.Transaction(nil), planned...)
		badPlanned[1].Group = types.Digest{0x45}
		if err := validatePlannedGroup([]types.Transaction{original}, badPlanned, mutations); err == nil || !strings.Contains(err.Error(), "canonical group ID") {
			t.Fatalf("error = %v, want the stray group ID refused", err)
		}
	})
	t.Run("canonical dummies are signed", func(t *testing.T) {
		signed, err := signCosignedDummies(frozenGroup{Txns: planned, OriginalCount: 1})
		if err != nil || len(signed) != 1 {
			t.Fatalf("signCosignedDummies() = %d, %v; want one signed dummy", len(signed), err)
		}
	})
	t.Run("gratuitous existing group change", func(t *testing.T) {
		grouped := original
		grouped.Group = types.Digest{0x31}
		regrouped := grouped
		regrouped.Group = types.Digest{0x32}
		report := &signerapi.MutationReport{
			GroupIDChanged: true, OriginalCount: 1, FinalCount: 1,
		}
		if err := validatePlannedGroup([]types.Transaction{grouped}, []types.Transaction{regrouped}, report); err == nil ||
			!strings.Contains(err.Error(), "existing group ID") {
			t.Fatalf("error = %v, want gratuitous regrouping rejection", err)
		}
	})
	t.Run("fee exceeds advertised ceiling", func(t *testing.T) {
		if err := validateBoundedTargetFees(
			[]types.Transaction{plannedOriginal},
			[]cosignedTarget{{Index: 0, BoundedMaxFee: new(uint64(plannedOriginal.Fee) - 1)}},
		); err == nil || !strings.Contains(err.Error(), "exceeds advertised max_fee") {
			t.Fatalf("error = %v, want max_fee rejection", err)
		}
	})
}

// regroupForTest stamps the canonical group ID over txns, so a test edit is
// the only thing a check sees as wrong.
func regroupForTest(t *testing.T, txns []types.Transaction) {
	t.Helper()
	ungrouped := append([]types.Transaction(nil), txns...)
	for i := range ungrouped {
		ungrouped[i].Group = types.Digest{}
	}
	groupID, err := crypto.ComputeGroupID(ungrouped)
	if err != nil {
		t.Fatal(err)
	}
	for i := range txns {
		txns[i].Group = groupID
	}
}

func suggestedParamsFromTxn(txn types.Transaction) types.SuggestedParams {
	return types.SuggestedParams{
		Fee:             txn.Fee,
		FirstRoundValid: txn.FirstValid,
		LastRoundValid:  txn.LastValid,
		GenesisID:       txn.GenesisID,
		GenesisHash:     txn.GenesisHash[:],
		FlatFee:         true,
	}
}

// A plain host has no fee ceiling, so any planned fee passes the client's check;
// a bounded host keeps its ceiling, and an account whose contract is missing or
// unknown fails closed before any request.
func TestBoundedTargetsTakeTheirFeeCeilingFromTheContract(t *testing.T) {
	account := testAddress(1).String()
	setup := func(contract string, maxFee *uint64) *Signer {
		s, _ := newTestSigner(t, func(c *cache.SignerCache) {
			c.AddAddress(account, "aplane.falcon1024.v1")
			c.SetSigningFlowForAddress(account, signerapi.SigningFlowCosigned1)
			c.SetCosignerComponentKeyTypeForAddress(account, witness.Falcon1024V1)
			c.SetCosignerPublicKeyForAddress(account, testCosignerPublicKeyHex(0xd6))
			c.SetBoundedContractForAddress(account, contract)
			if maxFee != nil {
				c.SetBoundedMaxFeeForAddress(account, *maxFee)
			}
			setTestLogicSigResources(c, account, 4_000)
		})
		return s
	}
	closing := testPaymentTxn(t, testAddress(1), testAddress(3), "close")
	closing.CloseRemainderTo = testAddress(3)
	closing.Fee = 1_000_000

	targets, err := setup(signerapi.BoundedContractPlain1, nil).cosignedTargets([]types.Transaction{closing})
	if err != nil || len(targets) != 1 || targets[0].BoundedMaxFee != nil {
		t.Fatalf("plain host targets = %#v, %v", targets, err)
	}
	if err := validateBoundedTargetFees([]types.Transaction{closing}, targets); err != nil {
		t.Fatalf("plain host fee check: %v", err)
	}

	targets, err = setup(signerapi.BoundedContractBounded2, new(uint64(10_000))).cosignedTargets([]types.Transaction{closing})
	if err != nil || len(targets) != 1 {
		t.Fatalf("bounded host targets = %#v, %v", targets, err)
	}
	if err := validateBoundedTargetFees([]types.Transaction{closing}, targets); err == nil || !strings.Contains(err.Error(), "exceeds advertised max_fee") {
		t.Fatalf("bounded host fee check: %v", err)
	}

	for name, s := range map[string]*Signer{
		"no contract":                    setup("", nil),
		"unknown contract":               setup("bounded3", new(uint64(1))),
		"bounded host without a ceiling": setup(signerapi.BoundedContractBounded2, nil),
	} {
		if _, err := s.cosignedTargets([]types.Transaction{closing}); err == nil {
			t.Fatalf("%s: cosignedTargets() accepted it", name)
		}
	}
}
