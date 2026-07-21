// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package guarded

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

func TestGuardedTargetsNormalizeSentryPublicKey(t *testing.T) {
	sender := testAddress(1).String()
	sentryHex := testSentryPublicKeyHex(0xd6)
	s, _ := newGuardedTestSigner(t, sender, 1500, "0X"+strings.ToUpper(sentryHex))
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")

	if !s.HasGuardedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasGuardedEffectiveSigner() = false, want true")
	}

	targets, err := s.guardedTargets([]types.Transaction{txn})
	if err != nil {
		t.Fatalf("guardedTargets() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Index != 0 || targets[0].Sender != sender || targets[0].Account != sender {
		t.Fatalf("target = %+v, want index 0 sender/account %s", targets[0], sender)
	}
	if targets[0].SentryComponentKeyType != keytypes.SentryComponentFalcon1024V1 {
		t.Fatalf("sentry key type = %q, want %q", targets[0].SentryComponentKeyType, keytypes.SentryComponentFalcon1024V1)
	}
	if targets[0].SentryPublicKey != sentryHex {
		t.Fatalf("sentry public key = %q, want %q", targets[0].SentryPublicKey, sentryHex)
	}
}

func TestGuardedTargetsUseEffectiveSigner(t *testing.T) {
	sender := testAddress(1).String()
	guarded := testAddress(3).String()
	sentryHex := testSentryPublicKeyHex(0xd6)
	s, _ := newGuardedTestSigner(t, guarded, 1500, sentryHex)
	s.authCache.AuthAddresses = map[string]string{sender: guarded}
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded-authorizer")

	if !s.HasGuardedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasGuardedEffectiveSigner() = false, want true")
	}

	targets, err := s.guardedTargets([]types.Transaction{txn})
	if err != nil {
		t.Fatalf("guardedTargets() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Index != 0 || targets[0].Sender != sender || targets[0].Account != guarded {
		t.Fatalf("target = %+v, want index 0 sender %s account %s", targets[0], sender, guarded)
	}
	if targets[0].SentryPublicKey != sentryHex {
		t.Fatalf("sentry public key = %q, want %q", targets[0].SentryPublicKey, sentryHex)
	}
}

func TestGuardedTargetsNormalizeFalconSentryPublicKey(t *testing.T) {
	sender := testAddress(1).String()
	sentryHex := testFalconSentryPublicKeyHex(0xd6)
	s, _ := newGuardedTestSignerForKeyType(t, sender, keytypes.GuardedFalcon1024Sentry1024V1, 1500, "0X"+strings.ToUpper(sentryHex))
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")

	if !s.HasGuardedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasGuardedEffectiveSigner() = false, want true")
	}

	targets, err := s.guardedTargets([]types.Transaction{txn})
	if err != nil {
		t.Fatalf("guardedTargets() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].SentryComponentKeyType != keytypes.SentryComponentFalcon1024V1 {
		t.Fatalf("sentry key type = %q, want %q", targets[0].SentryComponentKeyType, keytypes.SentryComponentFalcon1024V1)
	}
	if targets[0].SentryPublicKey != sentryHex {
		t.Fatalf("sentry public key = %q, want %q", targets[0].SentryPublicKey, sentryHex)
	}
}

func TestGuardedTargetsRequireSentryMetadata(t *testing.T) {
	sender := testAddress(1).String()
	s, _ := newGuardedTestSigner(t, sender, 1500, "")
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")

	_, err := s.guardedTargets([]types.Transaction{txn})
	if err == nil || !strings.Contains(err.Error(), "missing sentry_public_key") {
		t.Fatalf("guardedTargets() error = %v, want missing sentry_public_key", err)
	}
}

func TestGuardedTargetsRejectUnsupportedSigningFlow(t *testing.T) {
	sender := testAddress(1).String()
	sentryHex := testSentryPublicKeyHex(0xd6)
	s, sc := newGuardedTestSigner(t, sender, 1500, sentryHex)
	sc.SetSigningFlowForAddress(sender, "sentry2")
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")

	if !s.HasGuardedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasGuardedEffectiveSigner() = false, want true for unknown flow (must not fall through to /sign)")
	}
	_, err := s.guardedTargets([]types.Transaction{txn})
	if err == nil || !strings.Contains(err.Error(), `signing flow "sentry2"`) {
		t.Fatalf("guardedTargets() error = %v, want unsupported signing flow rejection", err)
	}
}

func TestGuardedTargetsDispatchBoundedOutsideSentryFlow(t *testing.T) {
	sender := testAddress(1).String()
	s, sc := newGuardedTestSigner(t, sender, 1500, testSentryPublicKeyHex(0xd6))
	sc.SetSigningFlowForAddress(sender, signerapi.SigningFlowBounded1)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "bounded")

	if s.HasGuardedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("HasGuardedEffectiveSigner() = true for bounded1")
	}
	targets, err := s.guardedTargets([]types.Transaction{txn})
	if err != nil {
		t.Fatalf("guardedTargets() error = %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("guardedTargets() = %#v, want no sentry targets", targets)
	}
}

func TestGuardedTargetsRequireSentryComponentKeyTypeMetadata(t *testing.T) {
	sender := testAddress(1).String()
	sentryHex := testSentryPublicKeyHex(0xd6)
	s, sc := newGuardedTestSigner(t, sender, 1500, sentryHex)
	sc.SetSentryComponentKeyTypeForAddress(sender, "")
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")

	_, err := s.guardedTargets([]types.Transaction{txn})
	if err == nil || !strings.Contains(err.Error(), "missing sentry_component_key_type") {
		t.Fatalf("guardedTargets() error = %v, want missing sentry_component_key_type", err)
	}
}

func TestPlanGuardedGroupReturnsGroupedDummies(t *testing.T) {
	sender := testAddress(1).String()
	sentryHex := testSentryPublicKeyHex(0xd6)
	s, _ := newGuardedTestSigner(t, sender, 2500, sentryHex)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")
	targets := []guardedTarget{{
		Index:                  0,
		Sender:                 sender,
		Account:                sender,
		SentryComponentKeyType: keytypes.SentryComponentFalcon1024V1,
		SentryPublicKey:        sentryHex,
	}}

	planned, dummies, err := s.planGuardedGroup([]types.Transaction{txn}, targets, nil)
	if err != nil {
		t.Fatalf("planGuardedGroup() error = %v", err)
	}
	if len(planned) != 3 {
		t.Fatalf("len(planned) = %d, want 3", len(planned))
	}
	if len(dummies) != 2 {
		t.Fatalf("len(dummies) = %d, want 2", len(dummies))
	}
	if planned[0].Group == (types.Digest{}) {
		t.Fatal("planned group ID is empty")
	}
	for i := range planned {
		if planned[i].Group != planned[0].Group {
			t.Fatalf("planned[%d].Group = %x, want %x", i, planned[i].Group, planned[0].Group)
		}
	}
	for i := range dummies {
		if dummies[i].Group != planned[1+i].Group {
			t.Fatalf("dummy[%d].Group = %x, want grouped canonical dummy %x", i, dummies[i].Group, planned[1+i].Group)
		}
		if dummies[i].Fee != 0 {
			t.Fatalf("dummy[%d].Fee = %d, want 0", i, dummies[i].Fee)
		}
	}
	if planned[0].Fee != types.MicroAlgos(3000) {
		t.Fatalf("planned[0].Fee = %d, want 3000 after two dummy fees", planned[0].Fee)
	}
}

func TestCollectComponentSignaturesRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name        string
		resp        *signerapi.ComponentSignResponse
		wantMessage string
	}{
		{
			name:        "empty response",
			resp:        nil,
			wantMessage: "empty component sign response",
		},
		{
			name: "unexpected target index",
			resp: &signerapi.ComponentSignResponse{Signatures: []signerapi.ComponentSignature{{
				TargetIndex:     9,
				SignatureScheme: keytypes.SentryComponentFalcon1024V1,
				Signature:       "aa",
			}}},
			wantMessage: "unexpected signature for target index 9",
		},
		{
			name: "duplicate target index",
			resp: &signerapi.ComponentSignResponse{Signatures: []signerapi.ComponentSignature{{
				TargetIndex:     0,
				SignatureScheme: keytypes.SentryComponentFalcon1024V1,
				Signature:       "aa",
			}, {
				TargetIndex:     0,
				SignatureScheme: keytypes.SentryComponentFalcon1024V1,
				Signature:       "bb",
			}}},
			wantMessage: "duplicate signature for target index 0",
		},
		{
			name: "wrong scheme",
			resp: &signerapi.ComponentSignResponse{Signatures: []signerapi.ComponentSignature{{
				TargetIndex:     0,
				SignatureScheme: "aplane.sentry-unknown.v1",
				Signature:       "aa",
			}, {
				TargetIndex:     1,
				SignatureScheme: keytypes.SentryComponentFalcon1024V1,
				Signature:       "bb",
			}}},
			wantMessage: "signature for target index 0 used scheme",
		},
		{
			name: "missing target index",
			resp: &signerapi.ComponentSignResponse{Signatures: []signerapi.ComponentSignature{{
				TargetIndex:     0,
				SignatureScheme: keytypes.SentryComponentFalcon1024V1,
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
				keytypes.SentryComponentFalcon1024V1,
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

func TestRequestSentryComponentSignaturesUsesConfiguredHTTPEndpoint(t *testing.T) {
	publicKey, privateKey := testFalconSentryKeypair(t, 0x61)
	sentryHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")
	groupBytesHex := encodeGroupHex([]types.Transaction{txn})
	server := newSentryEndpointTestServer(t, sentryHex, privateKey, "sentry-token", nil)
	defer server.Close()
	tokenFile := writeSentryTokenFile(t, "sentry-token")
	s, _ := newGuardedTestSigner(t, txn.Sender.String(), 1500, sentryHex)
	s.sentryEndpoints = config.SentryEndpointConfigs{
		sentryHex: {URL: server.URL, TokenFile: tokenFile},
	}

	signatures, requestIDs, err := s.requestSentryComponentSignatures(
		context.Background(),
		groupBytesHex,
		[]guardedTarget{guardedTargetForTest(txn.Sender.String(), sentryHex)},
	)
	if err != nil {
		t.Fatalf("requestSentryComponentSignatures() error = %v", err)
	}
	if signatures[0] == "" {
		t.Fatal("signature for target 0 is empty")
	}
	if requestIDs[sentryRequestKey{ComponentKeyType: keytypes.SentryComponentFalcon1024V1, PublicKey: sentryHex}] == "" {
		t.Fatal("request ID for sentry is empty")
	}
}

func TestRequestSentryComponentSignaturesExplicitMismatchDoesNotFallback(t *testing.T) {
	publicKey, privateKey := testFalconSentryKeypair(t, 0x62)
	wrongPublicKey, wrongPrivateKey := testFalconSentryKeypair(t, 0x63)
	sentryHex := hex.EncodeToString(publicKey)
	wrongHex := hex.EncodeToString(wrongPublicKey)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")
	groupBytesHex := encodeGroupHex([]types.Transaction{txn})

	selfServer := newSentryEndpointTestServer(t, sentryHex, privateKey, "", nil)
	defer selfServer.Close()
	var wrongSignCalls atomic.Int32
	wrongServer := newSentryEndpointTestServer(t, wrongHex, wrongPrivateKey, "sentry-token", &wrongSignCalls)
	defer wrongServer.Close()
	tokenFile := writeSentryTokenFile(t, "sentry-token")

	s, _ := newGuardedTestSigner(t, txn.Sender.String(), 1500, sentryHex)
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(selfServer.URL, "")
	s.sentryEndpoints = config.SentryEndpointConfigs{
		sentryHex: {URL: wrongServer.URL, TokenFile: tokenFile},
	}

	_, _, err := s.requestSentryComponentSignatures(
		context.Background(),
		groupBytesHex,
		[]guardedTarget{guardedTargetForTest(txn.Sender.String(), sentryHex)},
	)
	if err == nil {
		t.Fatal("requestSentryComponentSignatures() error = nil, want explicit endpoint mismatch")
	}
	componentSelector, selectorErr := sentryComponentSelector(keytypes.SentryComponentFalcon1024V1, sentryHex)
	if selectorErr != nil {
		t.Fatalf("sentryComponentSelector() error = %v", selectorErr)
	}
	errText := err.Error()
	if !strings.Contains(errText, "did not advertise Sentry Key ID") || !strings.Contains(errText, componentSelector) {
		t.Fatalf("requestSentryComponentSignatures() error = %q, want endpoint mismatch with Sentry Key ID %s", err, componentSelector)
	}
	if strings.Contains(errText, sentryHex) {
		t.Fatalf("requestSentryComponentSignatures() error exposed raw sentry public key: %q", err)
	}
	if got := wrongSignCalls.Load(); got != 0 {
		t.Fatalf("wrong endpoint /sign/component calls = %d, want 0", got)
	}
}

func TestRequestSentryComponentSignaturesReportsLockedEndpoint(t *testing.T) {
	publicKey, _ := testFalconSentryKeypair(t, 0x64)
	sentryHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")
	groupBytesHex := encodeGroupHex([]types.Transaction{txn})

	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"signer is locked"}`, http.StatusForbidden)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	tokenFile := writeSentryTokenFile(t, "sentry-token")

	s, _ := newGuardedTestSigner(t, txn.Sender.String(), 1500, sentryHex)
	s.sentryEndpoints = config.SentryEndpointConfigs{
		sentryHex: {URL: server.URL, TokenFile: tokenFile},
	}

	_, _, err := s.requestSentryComponentSignatures(
		context.Background(),
		groupBytesHex,
		[]guardedTarget{guardedTargetForTest(txn.Sender.String(), sentryHex)},
	)
	if err == nil {
		t.Fatal("requestSentryComponentSignatures() error = nil, want locked endpoint")
	}
	if !errors.Is(err, ErrSentryDiscoveryLocked) {
		t.Fatalf("requestSentryComponentSignatures() error = %q, want ErrSentryDiscoveryLocked", err)
	}
	if err.Error() != server.URL+" is locked" {
		t.Fatalf("requestSentryComponentSignatures() error = %q, want locked endpoint", err)
	}
	if strings.Contains(err.Error(), "did not advertise sentry") {
		t.Fatalf("requestSentryComponentSignatures() error = %q, should not report missing sentry", err)
	}
}

func TestRequestSentryComponentSignaturesFallsBackToCurrentSigner(t *testing.T) {
	publicKey, privateKey := testFalconSentryKeypair(t, 0x65)
	sentryHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")
	groupBytesHex := encodeGroupHex([]types.Transaction{txn})
	server := newSentryEndpointTestServer(t, sentryHex, privateKey, "", nil)
	defer server.Close()
	s, _ := newGuardedTestSigner(t, txn.Sender.String(), 1500, sentryHex)
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")

	signatures, _, err := s.requestSentryComponentSignatures(
		context.Background(),
		groupBytesHex,
		[]guardedTarget{guardedTargetForTest(txn.Sender.String(), sentryHex)},
	)
	if err != nil {
		t.Fatalf("requestSentryComponentSignatures() error = %v", err)
	}
	if signatures[0] == "" {
		t.Fatal("signature for target 0 is empty")
	}
}

func TestDecodeGuardedSignedGroupReturnsSignedObjects(t *testing.T) {
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")
	signedHex := []string{hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn}))}

	signedBytes, signedObjects, txns, err := decodeGuardedSignedGroup(signedHex)
	if err != nil {
		t.Fatalf("decodeGuardedSignedGroup() error = %v", err)
	}
	if len(signedBytes) != 1 || len(signedObjects) != 1 || len(txns) != 1 {
		t.Fatalf("decoded lengths = %d/%d/%d, want 1/1/1", len(signedBytes), len(signedObjects), len(txns))
	}
	if signedObjects[0].Txn.Sender != txn.Sender || txns[0].Sender != txn.Sender {
		t.Fatalf("decoded sender = %s/%s, want %s", signedObjects[0].Txn.Sender, txns[0].Sender, txn.Sender)
	}
}

// testCacheView adapts a cache.SignerCache to SignerCacheView for tests.
type testCacheView struct{ c *cache.SignerCache }

func (v testCacheView) SigningFlow(address string) string { return v.c.SigningFlowForAddress(address) }
func (v testCacheView) SentryComponentKeyType(address string) (string, bool) {
	return v.c.SentryComponentKeyTypeForAddress(address)
}
func (v testCacheView) SentryPublicKey(address string) (string, bool) {
	return v.c.SentryPublicKeyForAddress(address)
}
func (v testCacheView) LsigSize(address string) int { return v.c.GetLsigSize(address) }

// newTestSigner builds a Signer over a populated signer cache, a fresh
// in-memory auth cache, and an unconnected connection state. Tests reach the
// auth cache, connection, and sentry endpoints directly through the Signer's
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

func newGuardedTestSigner(t *testing.T, sender string, lsigSize int, sentryPublicKey string) (*Signer, *cache.SignerCache) {
	t.Helper()
	return newGuardedTestSignerForKeyType(t, sender, keytypes.GuardedFalcon1024Sentry1024V1, lsigSize, sentryPublicKey)
}

func newGuardedTestSignerForKeyType(t *testing.T, sender, keyType string, lsigSize int, sentryPublicKey string) (*Signer, *cache.SignerCache) {
	t.Helper()
	return newTestSigner(t, func(signerCache *cache.SignerCache) {
		signerCache.AddAddress(sender, keyType)
		// Mirror the signing-flow metadata the daemon serves for guarded keys.
		if componentType, ok := keytypes.SentryComponentKeyTypeForGuardedAccount(keyType); ok {
			signerCache.SetSigningFlowForAddress(sender, signerapi.SigningFlowSentry1)
			signerCache.SetSentryComponentKeyTypeForAddress(sender, componentType)
		}
		if lsigSize > 0 {
			signerCache.SetLsigSize(sender, lsigSize)
		}
		if sentryPublicKey != "" {
			signerCache.SetSentryPublicKeyForAddress(sender, sentryPublicKey)
		}
	})
}

func testAddress(index int) types.Address {
	var addr types.Address
	addr[0] = byte(index)
	addr[1] = byte(index >> 8)
	return addr
}

// testPaymentTxn builds a minimal payment transaction for guarded planning
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

func testSentryPublicKeyHex(prefix byte) string {
	var publicKey [falconfamily.PublicKeySize]byte
	publicKey[0] = prefix
	return hex.EncodeToString(publicKey[:])
}

func testFalconSentryPublicKeyHex(prefix byte) string {
	publicKey := make([]byte, falconfamily.PublicKeySize)
	publicKey[0] = prefix
	return hex.EncodeToString(publicKey)
}

func guardedTargetForTest(account, sentryHex string) guardedTarget {
	return guardedTarget{
		Index:                  0,
		Sender:                 account,
		Account:                account,
		SentryComponentKeyType: keytypes.SentryComponentFalcon1024V1,
		SentryPublicKey:        sentryHex,
	}
}

func TestSentryComponentLabelUsesFalconSentryKeyID(t *testing.T) {
	sentryHex := testFalconSentryPublicKeyHex(0x0a)
	componentSelector, err := sentryComponentSelector(keytypes.SentryComponentFalcon1024V1, sentryHex)
	if err != nil {
		t.Fatalf("sentryComponentSelector() error = %v", err)
	}

	label := sentryComponentLabel(keytypes.SentryComponentFalcon1024V1, sentryHex)
	if !strings.Contains(label, componentSelector) || !strings.Contains(label, keytypes.SentryComponentFalcon1024V1) {
		t.Fatalf("sentryComponentLabel() = %q, want Sentry Key ID %s and key type", label, componentSelector)
	}
	if strings.Contains(label, sentryHex) {
		t.Fatalf("sentryComponentLabel() exposed raw Falcon sentry public key: %q", label)
	}
}

func newSentryEndpointTestServer(t *testing.T, publicKeyHex string, privateKey []byte, token string, signCalls *atomic.Int32) *httptest.Server {
	t.Helper()
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("decode sentry public key: %v", err)
	}
	componentSelector, err := keytypes.ComponentKeySelector(keytypes.SentryComponentFalcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("Sentry Key ID: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.Header.Get("Authorization") != "aplane "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{
			Count: 1,
			Keys: []signerapi.KeyInfo{{
				Address:        componentSelector,
				PublicKeyHex:   publicKeyHex,
				KeyType:        keytypes.SentryComponentFalcon1024V1,
				IsComponentKey: true,
			}},
		})
	})
	mux.HandleFunc("/sign/component", func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.Header.Get("Authorization") != "aplane "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if signCalls != nil {
			signCalls.Add(1)
		}
		var req signerapi.ComponentSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Role != signerapi.ComponentSignRoleSentry || req.ComponentKey != componentSelector {
			http.Error(w, "wrong Sentry Key ID", http.StatusBadRequest)
			return
		}
		group, err := canonical.DecodeGroupHex(req.GroupBytesHex)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := signerapi.ComponentSignResponse{
			RequestID:    req.RequestID,
			ComponentKey: req.ComponentKey,
			Signatures:   make([]signerapi.ComponentSignature, 0, len(req.TargetIndices)),
		}
		for _, index := range req.TargetIndices {
			msg := message.ComponentMessage(message.RoleSentry, group.Entries[index].TxID)
			signature, err := signerops.New(nil).Sign(privateKey, msg[:])
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			resp.Signatures = append(resp.Signatures, signerapi.ComponentSignature{
				TargetIndex:     index,
				SignatureScheme: keytypes.SentryComponentFalcon1024V1,
				Signature:       hex.EncodeToString(signature),
			})
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	return httptest.NewServer(mux)
}

func testFalconSentryKeypair(t *testing.T, fill byte) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{fill}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	return publicKey, privateKey
}

func writeSentryTokenFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aplane.token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

func TestVerifyAssembledAgainstFrozen(t *testing.T) {
	txnA := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")
	txnB := testPaymentTxn(t, testAddress(3), testAddress(4), "guarded")
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
