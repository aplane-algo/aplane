// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keystest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/algorand/falcon"
	"github.com/aplane-algo/aplane/internal/keys"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

// PreChangeNativeFalconKeyJSON rebuilds the earlier encoder's bytes from the
// current ones: the digests are the ones keys' golden test pinned for that
// encoder's two native Falcon formats, on the same payload. A native Falcon
// file in the current shape differs from it only by pq_scheme and
// pq_address_salt, and for format 1 by recovery_entropy.
func TestPreChangeNativeFalconKeyJSONIsTheEarlierEncoding(t *testing.T) {
	// The golden pair does not derive from the entropy, so accept any pair.
	keys.RegisterNativePQKeyPairValidator(nativefalcon.Scheme, func(_, _, _ []byte) error { return nil })
	publicKey, privateKey, err := falcon.GenerateKey(bytes.Repeat([]byte{0x21}, 32))
	if err != nil {
		t.Fatal(err)
	}
	payload := keys.NewNativeFalconPayload(publicKey[:], privateKey[:], bytes.Repeat([]byte{0x22}, nativefalcon.RecoveryEntropySize))
	defer payload.ZeroSecrets()
	payload.CreatedAt = time.Date(2026, 7, 10, 12, 34, 56, 0, time.UTC)
	current := marshal(t, payload, "native_pq")
	for _, tc := range []struct {
		name     string
		recovery bool
		digest   string
	}{
		{"format 2 with recovery entropy", true, "0e2ae0dde698b9c1b4469e11de9bf757934c9d8fa18bd3aaa66d64b92f7a6b1e"},
		{"format 1 without recovery entropy", false, "edfaac7e7dd8f9d165400b125d003c75b5d687b86e4d295d11cbf3292832fb31"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sum := sha256.Sum256(PreChangeNativeFalconKeyJSON(t, current, tc.recovery))
			if got := hex.EncodeToString(sum[:]); got != tc.digest {
				t.Fatalf("pre-change digest = %s, want %s", got, tc.digest)
			}
		})
	}
}
