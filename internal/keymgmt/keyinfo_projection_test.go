// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keymgmt

import (
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/aplane-algo/aplane/internal/keys/keystest"
)

// parseKeyFileInfo projects the payload's non-secret fields.
func TestParseKeyFileInfoProjectsPayloadFields(t *testing.T) {
	_, ed25519JSON := keystest.Ed25519KeyJSON(t)
	var ed25519Fields struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(ed25519JSON, &ed25519Fields); err != nil {
		t.Fatal(err)
	}
	if _, err := hex.DecodeString(ed25519Fields.PublicKey); err != nil || ed25519Fields.PublicKey == "" {
		t.Fatalf("ed25519 fixture public key %q: %v", ed25519Fields.PublicKey, err)
	}
	for _, tc := range []struct {
		data []byte
		want KeyFileInfo
	}{
		{
			data: canonicalDSAKeyJSON(t, "test.dsa.v1", []byte{0xaa, 0xbb, 0xcc, 0xdd}),
			want: KeyFileInfo{Type: "test.dsa.v1", PublicKeyHex: "aabbccdd"},
		},
		{
			data: canonicalGenericKeyJSON(t, "test.timed-policy.v1", map[string]string{"recipients": "ADDR1"}, ""),
			want: KeyFileInfo{Type: "test.timed-policy.v1", Parameters: map[string]string{"recipients": "ADDR1"}},
		},
		{
			data: ed25519JSON,
			want: KeyFileInfo{Type: "ed25519", PublicKeyHex: ed25519Fields.PublicKey},
		},
	} {
		info, err := parseKeyFileInfo(tc.data)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(*info, tc.want) {
			t.Fatalf("parseKeyFileInfo() = %#v, want %#v", *info, tc.want)
		}
	}
}
