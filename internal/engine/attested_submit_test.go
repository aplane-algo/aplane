// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/attestor/message"
	attestorverify "github.com/aplane-algo/aplane/internal/attestor/verify"
	"github.com/aplane-algo/aplane/internal/cache"
)

func TestAttestedOriginalTargetsNormalizeAttestorPublicKey(t *testing.T) {
	sender := testAddress(1).String()
	attestorHex := testAttestorPublicKeyHex(0xd6)
	eng := newAttestedSubmitTestEngine(t, sender, 1500, "0X"+strings.ToUpper(attestorHex))
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "attested", nil).Transaction

	if !eng.hasAttestedSender([]types.Transaction{txn}) {
		t.Fatal("hasAttestedSender() = false, want true")
	}

	targets, err := eng.attestedOriginalTargets([]types.Transaction{txn})
	if err != nil {
		t.Fatalf("attestedOriginalTargets() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Index != 0 || targets[0].Account != sender {
		t.Fatalf("target = %+v, want index 0 account %s", targets[0], sender)
	}
	if targets[0].AttestorPublicKey != attestorHex {
		t.Fatalf("attestor public key = %q, want %q", targets[0].AttestorPublicKey, attestorHex)
	}
}

func TestAttestedOriginalTargetsRequireAttestorMetadata(t *testing.T) {
	sender := testAddress(1).String()
	eng := newAttestedSubmitTestEngine(t, sender, 1500, "")
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "attested", nil).Transaction

	_, err := eng.attestedOriginalTargets([]types.Transaction{txn})
	if err == nil || !strings.Contains(err.Error(), "missing attestor_public_key") {
		t.Fatalf("attestedOriginalTargets() error = %v, want missing attestor_public_key", err)
	}
}

func TestPlanAttestedGroupReturnsGroupedDummies(t *testing.T) {
	sender := testAddress(1).String()
	attestorHex := testAttestorPublicKeyHex(0xd6)
	eng := newAttestedSubmitTestEngine(t, sender, 2500, attestorHex)
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "attested", nil).Transaction
	targets := []attestedOriginalTarget{{
		Index:             0,
		Account:           sender,
		AttestorPublicKey: attestorHex,
	}}

	planned, dummies, err := eng.planAttestedGroup([]types.Transaction{txn}, targets, nil)
	if err != nil {
		t.Fatalf("planAttestedGroup() error = %v", err)
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

func TestVerifyAttestorComponentSignaturesUsesSharedMessage(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "attested", nil).Transaction
	group, err := attestorverify.DecodeCanonicalGroupHex(encodeGroupHex([]types.Transaction{txn}))
	if err != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", err)
	}

	msg := message.ComponentMessage(message.RoleAttestor, group.Entries[0].TxID)
	signatures := map[int]string{0: hex.EncodeToString(ed25519.Sign(privateKey, msg[:]))}
	if err := verifyAttestorComponentSignatures(hex.EncodeToString(publicKey), group, []int{0}, signatures); err != nil {
		t.Fatalf("verifyAttestorComponentSignatures() error = %v", err)
	}

	wrongRoleMsg := message.ComponentMessage(message.RoleUser, group.Entries[0].TxID)
	signatures[0] = hex.EncodeToString(ed25519.Sign(privateKey, wrongRoleMsg[:]))
	if err := verifyAttestorComponentSignatures(hex.EncodeToString(publicKey), group, []int{0}, signatures); err == nil {
		t.Fatal("verifyAttestorComponentSignatures() accepted user-role signature for attestor role")
	}
}

func TestDecodeAttestedSignedGroupReturnsSignedObjects(t *testing.T) {
	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "attested", nil).Transaction
	signedHex := []string{hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn}))}

	signedBytes, signedObjects, txns, err := decodeAttestedSignedGroup(signedHex)
	if err != nil {
		t.Fatalf("decodeAttestedSignedGroup() error = %v", err)
	}
	if len(signedBytes) != 1 || len(signedObjects) != 1 || len(txns) != 1 {
		t.Fatalf("decoded lengths = %d/%d/%d, want 1/1/1", len(signedBytes), len(signedObjects), len(txns))
	}
	if signedObjects[0].Txn.Sender != txn.Sender || txns[0].Sender != txn.Sender {
		t.Fatalf("decoded sender = %s/%s, want %s", signedObjects[0].Txn.Sender, txns[0].Sender, txn.Sender)
	}
}

func newAttestedSubmitTestEngine(t *testing.T, sender string, lsigSize int, attestorPublicKey string) *Engine {
	t.Helper()
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(sender, keytypes.AttestedFalcon1024V1)
	if lsigSize > 0 {
		signerCache.SetLsigSize(sender, lsigSize)
	}
	if attestorPublicKey != "" {
		signerCache.SetAttestorPublicKeyForAddress(sender, attestorPublicKey)
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

func testAttestorPublicKeyHex(prefix byte) string {
	var publicKey [ed25519.PublicKeySize]byte
	publicKey[0] = prefix
	return hex.EncodeToString(publicKey[:])
}
