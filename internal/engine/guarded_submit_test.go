// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
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
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	sentryverify "github.com/aplane-algo/aplane/internal/sentry/verify"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

func TestGuardedTargetsNormalizeSentryPublicKey(t *testing.T) {
	sender := testAddress(1).String()
	sentryHex := testSentryPublicKeyHex(0xd6)
	eng := newGuardedSubmitTestEngine(t, sender, 1500, "0X"+strings.ToUpper(sentryHex))
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded", nil).Transaction

	if !eng.hasGuardedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasGuardedEffectiveSigner() = false, want true")
	}

	targets, err := eng.guardedTargets([]types.Transaction{txn})
	if err != nil {
		t.Fatalf("guardedTargets() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Index != 0 || targets[0].Sender != sender || targets[0].Account != sender {
		t.Fatalf("target = %+v, want index 0 sender/account %s", targets[0], sender)
	}
	if targets[0].SentryComponentKeyType != keytypes.SentryComponentEd25519V1 {
		t.Fatalf("sentry component key type = %q, want %q", targets[0].SentryComponentKeyType, keytypes.SentryComponentEd25519V1)
	}
	if targets[0].SentryPublicKey != sentryHex {
		t.Fatalf("sentry public key = %q, want %q", targets[0].SentryPublicKey, sentryHex)
	}
}

func TestGuardedTargetsUseEffectiveSigner(t *testing.T) {
	sender := testAddress(1).String()
	guarded := testAddress(3).String()
	sentryHex := testSentryPublicKeyHex(0xd6)
	eng := newGuardedSubmitTestEngine(t, guarded, 1500, sentryHex)
	eng.AuthCache.AuthAddresses = map[string]string{sender: guarded}
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded-authorizer", nil).Transaction

	if !eng.hasGuardedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasGuardedEffectiveSigner() = false, want true")
	}

	targets, err := eng.guardedTargets([]types.Transaction{txn})
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
	eng := newGuardedSubmitTestEngineForKeyType(t, sender, keytypes.GuardedFalcon1024SentryFalcon1024V1, 1500, "0X"+strings.ToUpper(sentryHex))
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded", nil).Transaction

	if !eng.hasGuardedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasGuardedEffectiveSigner() = false, want true")
	}

	targets, err := eng.guardedTargets([]types.Transaction{txn})
	if err != nil {
		t.Fatalf("guardedTargets() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].SentryComponentKeyType != keytypes.SentryComponentFalcon1024V1 {
		t.Fatalf("sentry component key type = %q, want %q", targets[0].SentryComponentKeyType, keytypes.SentryComponentFalcon1024V1)
	}
	if targets[0].SentryPublicKey != sentryHex {
		t.Fatalf("sentry public key = %q, want %q", targets[0].SentryPublicKey, sentryHex)
	}
}

func TestGuardedTargetsRequireSentryMetadata(t *testing.T) {
	sender := testAddress(1).String()
	eng := newGuardedSubmitTestEngine(t, sender, 1500, "")
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded", nil).Transaction

	_, err := eng.guardedTargets([]types.Transaction{txn})
	if err == nil || !strings.Contains(err.Error(), "missing sentry_public_key") {
		t.Fatalf("guardedTargets() error = %v, want missing sentry_public_key", err)
	}
}

func TestPlanGuardedGroupReturnsGroupedDummies(t *testing.T) {
	sender := testAddress(1).String()
	sentryHex := testSentryPublicKeyHex(0xd6)
	eng := newGuardedSubmitTestEngine(t, sender, 2500, sentryHex)
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded", nil).Transaction
	targets := []guardedTarget{{
		Index:                  0,
		Sender:                 sender,
		Account:                sender,
		SentryComponentKeyType: keytypes.SentryComponentEd25519V1,
		SentryPublicKey:        sentryHex,
	}}

	planned, dummies, err := eng.planGuardedGroup([]types.Transaction{txn}, targets, nil)
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

func TestVerifySentryComponentSignaturesUsesSharedMessage(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded", nil).Transaction
	group, err := sentryverify.DecodeCanonicalGroupHex(encodeGroupHex([]types.Transaction{txn}))
	if err != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", err)
	}

	msg := message.ComponentMessage(message.RoleSentry, group.Entries[0].TxID)
	signatures := map[int]string{0: hex.EncodeToString(ed25519.Sign(privateKey, msg[:]))}
	if err := verifySentryComponentSignatures(keytypes.SentryComponentEd25519V1, hex.EncodeToString(publicKey), group, []int{0}, signatures); err != nil {
		t.Fatalf("verifySentryComponentSignatures() error = %v", err)
	}

	wrongRoleMsg := message.ComponentMessage(message.RoleUser, group.Entries[0].TxID)
	signatures[0] = hex.EncodeToString(ed25519.Sign(privateKey, wrongRoleMsg[:]))
	if err := verifySentryComponentSignatures(keytypes.SentryComponentEd25519V1, hex.EncodeToString(publicKey), group, []int{0}, signatures); err == nil {
		t.Fatal("verifySentryComponentSignatures() accepted user-role signature for sentry role")
	}
}

func TestVerifySentryComponentSignaturesUsesFalcon1024Scheme(t *testing.T) {
	publicKey, privateKey, err := signerops.New(nil).GenerateKeypair(make([]byte, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded", nil).Transaction
	group, err := sentryverify.DecodeCanonicalGroupHex(encodeGroupHex([]types.Transaction{txn}))
	if err != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", err)
	}

	msg := message.ComponentMessage(message.RoleSentry, group.Entries[0].TxID)
	signature, err := signerops.New(nil).Sign(privateKey, msg[:])
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	signatures := map[int]string{0: hex.EncodeToString(signature)}
	if err := verifySentryComponentSignatures(keytypes.SentryComponentFalcon1024V1, hex.EncodeToString(publicKey), group, []int{0}, signatures); err != nil {
		t.Fatalf("verifySentryComponentSignatures() error = %v", err)
	}

	wrongRoleMsg := message.ComponentMessage(message.RoleUser, group.Entries[0].TxID)
	signature, err = signerops.New(nil).Sign(privateKey, wrongRoleMsg[:])
	if err != nil {
		t.Fatalf("Sign(wrong role) error = %v", err)
	}
	signatures[0] = hex.EncodeToString(signature)
	if err := verifySentryComponentSignatures(keytypes.SentryComponentFalcon1024V1, hex.EncodeToString(publicKey), group, []int{0}, signatures); err == nil {
		t.Fatal("verifySentryComponentSignatures() accepted user-role signature for sentry role")
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
				SignatureScheme: keytypes.SentryComponentEd25519V1,
				Signature:       "aa",
			}}},
			wantMessage: "unexpected signature for target index 9",
		},
		{
			name: "duplicate target index",
			resp: &signerapi.ComponentSignResponse{Signatures: []signerapi.ComponentSignature{{
				TargetIndex:     0,
				SignatureScheme: keytypes.SentryComponentEd25519V1,
				Signature:       "aa",
			}, {
				TargetIndex:     0,
				SignatureScheme: keytypes.SentryComponentEd25519V1,
				Signature:       "bb",
			}}},
			wantMessage: "duplicate signature for target index 0",
		},
		{
			name: "wrong scheme",
			resp: &signerapi.ComponentSignResponse{Signatures: []signerapi.ComponentSignature{{
				TargetIndex:     0,
				SignatureScheme: keytypes.SentryComponentFalcon1024V1,
				Signature:       "aa",
			}, {
				TargetIndex:     1,
				SignatureScheme: keytypes.SentryComponentEd25519V1,
				Signature:       "bb",
			}}},
			wantMessage: "signature for target index 0 used scheme",
		},
		{
			name: "missing target index",
			resp: &signerapi.ComponentSignResponse{Signatures: []signerapi.ComponentSignature{{
				TargetIndex:     0,
				SignatureScheme: keytypes.SentryComponentEd25519V1,
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
				keytypes.SentryComponentEd25519V1,
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
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	sentryHex := hex.EncodeToString(publicKey)
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded", nil).Transaction
	groupBytesHex := encodeGroupHex([]types.Transaction{txn})
	group, err := sentryverify.DecodeCanonicalGroupHex(groupBytesHex)
	if err != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", err)
	}
	server := newSentryEndpointTestServer(t, sentryHex, privateKey, "sentry-token", nil)
	defer server.Close()
	tokenFile := writeSentryTokenFile(t, "sentry-token")
	eng := newGuardedSubmitTestEngine(t, txn.Sender.String(), 1500, sentryHex)
	eng.SentryEndpoints = config.SentryEndpointConfigs{
		sentryHex: {URL: server.URL, TokenFile: tokenFile},
	}

	signatures, requestIDs, err := eng.requestSentryComponentSignatures(
		context.Background(),
		groupBytesHex,
		group,
		[]guardedTarget{ed25519GuardedTarget(txn.Sender.String(), sentryHex)},
	)
	if err != nil {
		t.Fatalf("requestSentryComponentSignatures() error = %v", err)
	}
	if signatures[0] == "" {
		t.Fatal("signature for target 0 is empty")
	}
	if requestIDs[ed25519SentryRequestKey(sentryHex)] == "" {
		t.Fatal("request ID for sentry is empty")
	}
}

func TestRequestSentryComponentSignaturesExplicitMismatchDoesNotFallback(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	wrongPublicKey, wrongPrivateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	sentryHex := hex.EncodeToString(publicKey)
	wrongHex := hex.EncodeToString(wrongPublicKey)
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded", nil).Transaction
	groupBytesHex := encodeGroupHex([]types.Transaction{txn})
	group, err := sentryverify.DecodeCanonicalGroupHex(groupBytesHex)
	if err != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", err)
	}

	selfServer := newSentryEndpointTestServer(t, sentryHex, privateKey, "", nil)
	defer selfServer.Close()
	var wrongSignCalls atomic.Int32
	wrongServer := newSentryEndpointTestServer(t, wrongHex, wrongPrivateKey, "sentry-token", &wrongSignCalls)
	defer wrongServer.Close()
	tokenFile := writeSentryTokenFile(t, "sentry-token")

	eng := newGuardedSubmitTestEngine(t, txn.Sender.String(), 1500, sentryHex)
	eng.Connection.SignerClient = signerclient.NewSignerClientWithToken(selfServer.URL, "")
	eng.SentryEndpoints = config.SentryEndpointConfigs{
		sentryHex: {URL: wrongServer.URL, TokenFile: tokenFile},
	}

	_, _, err = eng.requestSentryComponentSignatures(
		context.Background(),
		groupBytesHex,
		group,
		[]guardedTarget{ed25519GuardedTarget(txn.Sender.String(), sentryHex)},
	)
	if err == nil {
		t.Fatal("requestSentryComponentSignatures() error = nil, want explicit endpoint mismatch")
	}
	if !strings.Contains(err.Error(), "did not advertise sentry component public key") {
		t.Fatalf("requestSentryComponentSignatures() error = %q, want endpoint mismatch", err)
	}
	if got := wrongSignCalls.Load(); got != 0 {
		t.Fatalf("wrong endpoint /sign/component calls = %d, want 0", got)
	}
}

func TestRequestSentryComponentSignaturesReportsLockedEndpoint(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	sentryHex := hex.EncodeToString(publicKey)
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded", nil).Transaction
	groupBytesHex := encodeGroupHex([]types.Transaction{txn})
	group, err := sentryverify.DecodeCanonicalGroupHex(groupBytesHex)
	if err != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"signer is locked"}`, http.StatusForbidden)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	tokenFile := writeSentryTokenFile(t, "sentry-token")

	eng := newGuardedSubmitTestEngine(t, txn.Sender.String(), 1500, sentryHex)
	eng.SentryEndpoints = config.SentryEndpointConfigs{
		sentryHex: {URL: server.URL, TokenFile: tokenFile},
	}

	_, _, err = eng.requestSentryComponentSignatures(
		context.Background(),
		groupBytesHex,
		group,
		[]guardedTarget{ed25519GuardedTarget(txn.Sender.String(), sentryHex)},
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
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	sentryHex := hex.EncodeToString(publicKey)
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded", nil).Transaction
	groupBytesHex := encodeGroupHex([]types.Transaction{txn})
	group, err := sentryverify.DecodeCanonicalGroupHex(groupBytesHex)
	if err != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", err)
	}
	server := newSentryEndpointTestServer(t, sentryHex, privateKey, "", nil)
	defer server.Close()
	eng := newGuardedSubmitTestEngine(t, txn.Sender.String(), 1500, sentryHex)
	eng.Connection.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")

	signatures, _, err := eng.requestSentryComponentSignatures(
		context.Background(),
		groupBytesHex,
		group,
		[]guardedTarget{ed25519GuardedTarget(txn.Sender.String(), sentryHex)},
	)
	if err != nil {
		t.Fatalf("requestSentryComponentSignatures() error = %v", err)
	}
	if signatures[0] == "" {
		t.Fatal("signature for target 0 is empty")
	}
}

func TestDecodeGuardedSignedGroupReturnsSignedObjects(t *testing.T) {
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded", nil).Transaction
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

func newGuardedSubmitTestEngine(t *testing.T, sender string, lsigSize int, sentryPublicKey string) *Engine {
	t.Helper()
	return newGuardedSubmitTestEngineForKeyType(t, sender, keytypes.GuardedFalcon1024SentryEd25519V1, lsigSize, sentryPublicKey)
}

func newGuardedSubmitTestEngineForKeyType(t *testing.T, sender, keyType string, lsigSize int, sentryPublicKey string) *Engine {
	t.Helper()
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(sender, keyType)
	if lsigSize > 0 {
		signerCache.SetLsigSize(sender, lsigSize)
	}
	if sentryPublicKey != "" {
		signerCache.SetSentryPublicKeyForAddress(sender, sentryPublicKey)
	}
	eng, err := NewEngine("testnet",
		WithCacheStore(cache.NewStore(t.TempDir())),
		WithSignerCache(signerCache),
	)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return eng
}

func testSentryPublicKeyHex(prefix byte) string {
	var publicKey [ed25519.PublicKeySize]byte
	publicKey[0] = prefix
	return hex.EncodeToString(publicKey[:])
}

func testFalconSentryPublicKeyHex(prefix byte) string {
	publicKey := make([]byte, falconfamily.PublicKeySize)
	publicKey[0] = prefix
	return hex.EncodeToString(publicKey)
}

func ed25519GuardedTarget(account, sentryHex string) guardedTarget {
	return guardedTarget{
		Index:                  0,
		Sender:                 account,
		Account:                account,
		SentryComponentKeyType: keytypes.SentryComponentEd25519V1,
		SentryPublicKey:        sentryHex,
	}
}

func ed25519SentryRequestKey(sentryHex string) sentryRequestKey {
	return sentryRequestKey{
		ComponentKeyType: keytypes.SentryComponentEd25519V1,
		PublicKey:        sentryHex,
	}
}

func newSentryEndpointTestServer(t *testing.T, publicKeyHex string, privateKey ed25519.PrivateKey, token string, signCalls *atomic.Int32) *httptest.Server {
	t.Helper()
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("decode sentry public key: %v", err)
	}
	componentSelector, err := keytypes.ComponentKeySelector(keytypes.SentryComponentEd25519V1, publicKey)
	if err != nil {
		t.Fatalf("component selector: %v", err)
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
				KeyType:        keytypes.SentryComponentEd25519V1,
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
			http.Error(w, "wrong sentry component key", http.StatusBadRequest)
			return
		}
		group, err := sentryverify.DecodeCanonicalGroupHex(req.GroupBytesHex)
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
			resp.Signatures = append(resp.Signatures, signerapi.ComponentSignature{
				TargetIndex:     index,
				SignatureScheme: keytypes.SentryComponentEd25519V1,
				Signature:       hex.EncodeToString(ed25519.Sign(privateKey, msg[:])),
			})
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	return httptest.NewServer(mux)
}

func writeSentryTokenFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aplane.token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}
