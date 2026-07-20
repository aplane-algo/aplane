// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedmeta

import (
	"encoding/hex"
	"testing"
)

func TestCanonicalEncodingPrimitives(t *testing.T) {
	var encoded []byte
	encoded = AppendUint32(encoded, 0x01020304)
	encoded = AppendUint64(encoded, 0x05060708090a0b0c)
	encoded = AppendField(encoded, []byte{0xaa, 0xbb})
	const want = "0102030405060708090a0b0c00000002aabb"
	if got := hex.EncodeToString(encoded); got != want {
		t.Fatalf("canonical encoding = %s, want %s", got, want)
	}
}
