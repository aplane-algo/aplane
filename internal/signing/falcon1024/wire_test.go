// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falcon1024

import (
	"bytes"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestSDKPQAuthorizationWireRoundTrip(t *testing.T) {
	scheme := types.PQScheme{'f', '1'}
	for _, original := range []types.SignedTxn{
		{
			Txn: types.Transaction{Type: types.PaymentTx},
			PQsig: types.PQSig{
				Scheme: scheme, Salt: 3,
				PublicKey: []byte{1, 2, 3}, Signature: []byte{4, 5, 6},
			},
		},
		{
			Txn: types.Transaction{Type: types.PaymentTx},
			Lsig: types.LogicSig{
				Logic: []byte{1},
				PQsig: types.PQSig{
					Scheme: scheme, Salt: 7,
					PublicKey: []byte{8, 9}, Signature: []byte{10, 11},
				},
			},
		},
	} {
		encoded := msgpack.Encode(original)
		var decoded types.SignedTxn
		if err := msgpack.Decode(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		reencoded := msgpack.Encode(decoded)
		if !bytes.Equal(reencoded, encoded) {
			t.Fatal("PQ authorization did not round-trip canonically")
		}
		if decoded.PQsig.Blank() && decoded.Lsig.PQsig.Blank() {
			t.Fatal("PQ authorization disappeared during SDK decode")
		}
	}
}
