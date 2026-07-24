// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package merkleallowlist

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestMerkleAllowlistCompatibilityVector(t *testing.T) {
	low := types.Address{}
	high := types.Address{}
	for i := range low {
		low[i] = 0x11
		high[i] = 0x22
	}

	// Deliberately provide the larger public key first. Canonical construction
	// sorts raw public keys before assigning leaves.
	recipients := strings.Join([]string{high.String(), low.String()}, ",")
	root, err := RootFromRecipientsParam(recipients)
	if err != nil {
		t.Fatalf("RootFromRecipientsParam() error = %v", err)
	}
	const wantRootHex = "ea4421efa4bc1d9d5bfaf9d578e25655591bd27af8658bf94eee1687ec9c5d8d"
	if got := hex.EncodeToString(root[:]); got != wantRootHex {
		t.Fatalf("root = %s, want %s", got, wantRootHex)
	}

	proof, err := ProofForAddressParam(recipients, high)
	if err != nil {
		t.Fatalf("ProofForAddressParam() error = %v", err)
	}
	const wantProofHex = "" +
		"4635e1fa62a599a7880a8d14a56f720a1d40f6e5448ab5a5e39bedc8bd87fa8e" +
		"fe43d66afa4a9a5c4f9c9da89f4ffb52635c8f342e7ffb731d68e36c5982072a" +
		"deb82e155954d6be14592c66ccf7a1ece193eeebcdabaf747b91f44519f09f47" +
		"2960044c62f2354e945e8d78fdd220a05f2c0879f24df6f11ef5cc26b5270a0e" +
		"4cfabc48c6898a30b1b5d12dda8e09a96e9ea17e80f4b2a050b8a8b4803fbd43" +
		"7162ed848f19740e53766ce01ac099523b099d593e0782ddbc5296eece50ec50" +
		"2be3cf0551cc6936d461e3dc43f3c4bf50cbee1bc091925254e879f4e7665e94" +
		"12db5262a5500d2516b8f82362d2a87278d20f712ff1fce2019d42ecba17241d" +
		"1a1a9265f869676c206824aa7bfc2fe8c7fe34691dddfb35797b6a321f977dfc" +
		"6e0bb8243e268be3d2fa3ce83234b2f850c85162bd0fced30e919e069bd52df7" +
		"0162892fa669b555682d4c5666f42c98f230e76406d646e6dbbcefb5d311e047" +
		"fd5593f0bfde08caa41745a8a6b2d5dcaea03a5867e8432a995bea3a1fd4df56" +
		"7bbcd27ae0b8f5d7c013dc6d13a2e586b58f83eac62aa62aa56f332288ad8bf4" +
		"d6c82f90e341cc36aa0fb5f8d03bbb3e6d5148eb56fcf79eb415574aee7fa99a" +
		"e2b649c4fa703c323fc2c929ad269dfdd150bde6862d9bcebe966244b983f20f" +
		"48c12a8dd675e9dcd3c63141fbfde6d11056c392b4379c3bbdc79a8511d0e65b"
	if got := hex.EncodeToString(proof); got != wantProofHex {
		t.Fatalf("proof = %s, want %s", got, wantProofHex)
	}
	if len(proof) != ProofSize {
		t.Fatalf("proof length = %d, want %d", len(proof), ProofSize)
	}
	firstSibling := leaf(low)
	if !bytes.Equal(proof[:32], firstSibling[:]) {
		t.Fatalf("first proof sibling = %x, want leaf sibling %x", proof[:32], firstSibling)
	}
	emptyParent := node(emptyLeaf(), emptyLeaf())
	if !bytes.Equal(proof[32:64], emptyParent[:]) {
		t.Fatalf("second proof sibling = %x, want empty subtree %x", proof[32:64], emptyParent)
	}
	if !Verify(high, proof, root) {
		t.Fatal("frozen proof did not verify")
	}

	reordered := strings.Join([]string{low.String(), high.String()}, ",")
	reorderedRoot, err := RootFromRecipientsParam(reordered)
	if err != nil {
		t.Fatalf("RootFromRecipientsParam(reordered) error = %v", err)
	}
	reorderedProof, err := ProofForAddressParam(reordered, high)
	if err != nil {
		t.Fatalf("ProofForAddressParam(reordered) error = %v", err)
	}
	if !bytes.Equal(reorderedRoot[:], root[:]) || !bytes.Equal(reorderedProof, proof) {
		t.Fatal("root or proof changed when recipient input order changed")
	}
}

func TestMerkleAllowlistRejectsDuplicatePublicKeys(t *testing.T) {
	address := types.Address{1}.String()
	if _, err := RootFromRecipientsParam(address + "," + address); err == nil ||
		!strings.Contains(err.Error(), "duplicate allowlist address public key") {
		t.Fatalf("RootFromRecipientsParam(duplicate) error = %v, want duplicate rejection", err)
	}
}

func TestRootAndProofForAddressParam(t *testing.T) {
	accounts := []string{
		algocrypto.GenerateAccount().Address.String(),
		algocrypto.GenerateAccount().Address.String(),
		algocrypto.GenerateAccount().Address.String(),
	}
	root, err := RootFromRecipientsParam(strings.Join(accounts, ","))
	if err != nil {
		t.Fatalf("RootFromRecipientsParam() error = %v", err)
	}

	for _, address := range accounts {
		addr, err := types.DecodeAddress(address)
		if err != nil {
			t.Fatalf("DecodeAddress(%s) error = %v", address, err)
		}
		proof, err := ProofForAddressParam(strings.Join(accounts, ","), addr)
		if err != nil {
			t.Fatalf("ProofForAddressParam(%s) error = %v", address, err)
		}
		if len(proof) != ProofSize {
			t.Fatalf("proof length = %d, want %d", len(proof), ProofSize)
		}
		if !Verify(addr, proof, root) {
			t.Fatalf("proof for %s did not verify", address)
		}
	}

	outside := algocrypto.GenerateAccount().Address
	if _, err := ProofForAddressParam(strings.Join(accounts, ","), outside); err == nil {
		t.Fatal("ProofForAddressParam(outside) error = nil, want rejection")
	}
}

func TestRootCanonicalizesRecipientOrder(t *testing.T) {
	accounts := []string{
		algocrypto.GenerateAccount().Address.String(),
		algocrypto.GenerateAccount().Address.String(),
		algocrypto.GenerateAccount().Address.String(),
	}
	rootA, err := RootFromRecipientsParam(strings.Join(accounts, ","))
	if err != nil {
		t.Fatalf("RootFromRecipientsParam(order A) error = %v", err)
	}
	rootB, err := RootFromRecipientsParam(strings.Join([]string{accounts[2], accounts[0], accounts[1]}, ","))
	if err != nil {
		t.Fatalf("RootFromRecipientsParam(order B) error = %v", err)
	}
	if !bytes.Equal(rootA[:], rootB[:]) {
		t.Fatalf("roots differ for reordered recipients: %x != %x", rootA, rootB)
	}
}
