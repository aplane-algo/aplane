// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerops owns signer-only native Falcon transaction operations.
// It intentionally links the CGo-backed Falcon implementation; client-safe
// metadata and address derivation remain in the parent package.
package signerops

import (
	"bytes"
	"fmt"

	"github.com/algorand/falcon"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

var scheme = types.PQScheme{'f', '1'}

// AuthorizeTransaction constructs a native Falcon authorization envelope.
func AuthorizeTransaction(privateKey *falcon.PrivateKey, publicKey []byte, salt byte, txn types.Transaction, authorizer types.Address) (types.SignedTxn, error) {
	if privateKey == nil {
		return types.SignedTxn{}, fmt.Errorf("native Falcon private key is nil")
	}
	if len(publicKey) != nativefalcon.PublicKeySize {
		return types.SignedTxn{}, fmt.Errorf("native Falcon public key length %d, want %d", len(publicKey), nativefalcon.PublicKeySize)
	}
	derived, err := nativefalcon.Address(salt, publicKey)
	if err != nil {
		return types.SignedTxn{}, err
	}
	if derived != authorizer {
		return types.SignedTxn{}, fmt.Errorf("native Falcon key derives %s, not requested authorizer %s", derived, authorizer)
	}
	message := txnutil.EncodeWithPrefix(txn)
	defer securecrypto.ZeroBytes(message)
	signature, err := privateKey.SignCompressed(message)
	if err != nil {
		return types.SignedTxn{}, fmt.Errorf("sign native Falcon transaction: %w", err)
	}
	stxn := types.SignedTxn{
		Txn: txn,
		PQsig: types.PQSig{
			Scheme:    scheme,
			Salt:      types.PQAddressSalt(salt),
			PublicKey: append([]byte(nil), publicKey...),
			Signature: signature,
		},
	}
	if txn.Sender != authorizer {
		stxn.AuthAddr = authorizer
	}
	return stxn, nil
}

// ValidateTransaction independently validates the structured native Falcon
// proof returned by a provider before the signer exposes it to a client.
func ValidateTransaction(stxn types.SignedTxn, expectedTxn types.Transaction, authorizer types.Address) error {
	if !bytes.Equal(msgpack.Encode(stxn.Txn), msgpack.Encode(expectedTxn)) {
		return fmt.Errorf("native Falcon provider changed the transaction")
	}
	if stxn.Sig != (types.Signature{}) || !stxn.Msig.Blank() || !logicSigBlank(stxn.Lsig) {
		return fmt.Errorf("native Falcon transaction carries multiple authorization mechanisms")
	}
	proof := stxn.PQsig
	if proof.Blank() {
		return fmt.Errorf("native Falcon transaction is missing PQ authorization")
	}
	if proof.Scheme != scheme {
		return fmt.Errorf("native Falcon transaction scheme is %q, want %q", proof.Scheme, scheme)
	}
	if len(proof.PublicKey) != nativefalcon.PublicKeySize {
		return fmt.Errorf("native Falcon public key length %d, want %d", len(proof.PublicKey), nativefalcon.PublicKeySize)
	}
	if len(proof.Signature) == 0 || len(proof.Signature) > nativefalcon.MaxSignatureSize {
		return fmt.Errorf("native Falcon signature length %d is outside 1..%d", len(proof.Signature), nativefalcon.MaxSignatureSize)
	}
	derived, err := nativefalcon.Address(byte(proof.Salt), proof.PublicKey)
	if err != nil {
		return err
	}
	if derived != authorizer {
		return fmt.Errorf("native Falcon proof derives %s, not requested authorizer %s", derived, authorizer)
	}
	wantAuthAddr := types.Address{}
	if expectedTxn.Sender != authorizer {
		wantAuthAddr = authorizer
	}
	if stxn.AuthAddr != wantAuthAddr {
		return fmt.Errorf("native Falcon AuthAddr is %s, want %s", stxn.AuthAddr, wantAuthAddr)
	}
	var publicKey falcon.PublicKey
	copy(publicKey[:], proof.PublicKey)
	message := txnutil.EncodeWithPrefix(expectedTxn)
	defer securecrypto.ZeroBytes(message)
	if err := publicKey.Verify(proof.Signature, message); err != nil {
		return fmt.Errorf("verify native Falcon transaction signature: %w", err)
	}
	return nil
}

// The upstream LogicSig.Blank method predates the PQsig field and does not
// currently inspect it, so native-PQ-aware callers must include it explicitly.
func logicSigBlank(lsig types.LogicSig) bool {
	return len(lsig.Logic) == 0 && lsig.Args == nil && lsig.Sig == (types.Signature{}) &&
		lsig.Msig.Blank() && lsig.LMsig.Blank() && lsig.PQsig.Blank()
}
