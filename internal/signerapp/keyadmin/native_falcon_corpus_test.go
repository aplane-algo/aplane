// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	algomnemonic "github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/signing"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/signing/falcon1024/signerops"
	nativereg "github.com/aplane-algo/aplane/internal/signing/falcon1024/signerreg"
)

type nativeFalconCorpus struct {
	Source string `json:"source"`
	Keys   []struct {
		EntropyHex string `json:"entropy_hex"`
		Salt       byte   `json:"salt"`
		Address    string `json:"address"`
	} `json:"keys"`
}

// Each corpus key was written by mnemonic import before key files stopped
// storing pq_address_salt; the fixture records the salt and address they
// stored. Importing the same phrase now must give the same account, sign
// with the same salt, and export the same phrase.
func TestNativeFalconCorpusKeepsItsSaltAndAddressAndExports(t *testing.T) {
	nativereg.RegisterSigner()
	data, err := os.ReadFile("testdata/native_falcon_salt_corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus nativeFalconCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	salts := map[byte]bool{}
	for _, entry := range corpus.Keys {
		salts[entry.Salt] = true
	}
	if len(corpus.Keys) < 20 || len(salts) < 4 {
		t.Fatalf("corpus has %d keys over %d salts, want at least 20 over 4", len(corpus.Keys), len(salts))
	}

	ir := setupProductRuntime(t)
	svc := Service{Runtime: ir}
	provider, ok := signing.GetProvider(nativefalcon.KeyType).(signing.TransactionAuthorizer)
	if !ok {
		t.Fatal("native Falcon provider does not authorize transactions")
	}
	for _, entry := range corpus.Keys {
		entropy, err := hex.DecodeString(entry.EntropyHex)
		if err != nil {
			t.Fatal(err)
		}
		words, err := algomnemonic.FromKey(entropy)
		if err != nil {
			t.Fatal(err)
		}
		imported, importErr := svc.ImportKey(context.Background(), nativefalcon.KeyType, []byte(words), nil)
		if importErr != nil {
			t.Fatal(importErr)
		}
		if imported.Address != entry.Address {
			t.Fatalf("import derived %s, the stored key was %s", imported.Address, entry.Address)
		}

		material, err := ir.KeyStore().Get(context.Background(), entry.Address)
		if err != nil {
			t.Fatal(err)
		}
		address, err := types.DecodeAddress(entry.Address)
		if err != nil {
			t.Fatal(err)
		}
		txn := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: address}}
		stxn, err := provider.AuthorizeTransaction(material, txn, address)
		signing.GetProvider(nativefalcon.KeyType).ZeroKey(material)
		if err != nil {
			t.Fatal(err)
		}
		if byte(stxn.PQsig.Salt) != entry.Salt {
			t.Fatalf("%s signed with salt %d, the stored salt was %d", entry.Address, stxn.PQsig.Salt, entry.Salt)
		}
		if err := signerops.ValidateTransaction(stxn, txn, address); err != nil {
			t.Fatalf("%s: %v", entry.Address, err)
		}

		result, exported := exportWith(svc, context.Background(), entry.Address, bytes.Clone(testPassphrase))
		if !result.Success {
			t.Fatalf("export of %s failed: %s %s", entry.Address, result.Code, result.Error)
		}
		if string(exported.mnemonic) != words {
			t.Fatalf("export of %s returned another phrase", entry.Address)
		}
		crypto.ZeroBytes(exported.mnemonic)
	}
}
