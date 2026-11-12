// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"bytes"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
)

// valid_rekey_target is part of the aplane key record: the codec writes it
// and reads it back unchanged, so every path that carries an existing record
// (backup restore, copy, import of a record) keeps the value the key recorded
// when it was created.
func TestPayloadCarriesValidRekeyTarget(t *testing.T) {
	account := crypto.GenerateAccount()
	for _, valid := range []bool{true, false} {
		payload := NewEd25519Payload(account.PublicKey, account.PrivateKey)
		payload.ValidRekeyTarget = valid
		encoded, err := MarshalPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		if got := bytes.Contains(encoded, []byte(`"valid_rekey_target": true`)); got != valid {
			t.Fatalf("valid_rekey_target %v: encoded record carries the field = %v\n%s", valid, got, encoded)
		}
		parsed, err := ParsePayload(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.ValidRekeyTarget != valid || parsed.Metadata().ValidRekeyTarget != valid {
			t.Fatalf("parsed valid_rekey_target = %v, metadata %v; want %v", parsed.ValidRekeyTarget, parsed.Metadata().ValidRekeyTarget, valid)
		}
		parsed.ZeroSecrets()
		payload.ZeroSecrets()
	}
}
