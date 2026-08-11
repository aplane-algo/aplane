// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestSignedTxnHasSignatureRecognizesPQAuthorization(t *testing.T) {
	proof := types.PQSig{Scheme: types.PQScheme{'f', '1'}, PublicKey: []byte{1}, Signature: []byte{2}}
	if !signedTxnHasSignature(types.SignedTxn{PQsig: proof}) {
		t.Fatal("top-level PQ authorization was treated as unsigned")
	}
	if !signedTxnHasSignature(types.SignedTxn{Lsig: types.LogicSig{PQsig: proof}}) {
		t.Fatal("delegated LogicSig PQ authorization was treated as unsigned")
	}
}
