// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package merklewhitelist

import (
	"bytes"
	"strings"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

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
