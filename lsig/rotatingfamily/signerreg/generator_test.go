// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"encoding/base64"
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

func TestGenesisHashParameter(t *testing.T) {
	for hash, token := range apconfig.BuiltinGenesisHashNetworks() {
		got, err := GenesisHashParameter(map[string]string{"network": token})
		if err != nil {
			t.Fatalf("%s: %v", token, err)
		}
		if base64.StdEncoding.EncodeToString(got[:]) != hash {
			t.Fatalf("%s resolved to %x, want %s", token, got, hash)
		}
	}
	custom := make([]byte, 32)
	custom[0] = 7
	got, err := GenesisHashParameter(map[string]string{"network": " " + base64.StdEncoding.EncodeToString(custom) + " "})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 7 {
		t.Fatalf("custom genesis hash resolved to %x", got)
	}

	for _, tt := range []struct {
		name   string
		params map[string]string
		want   string
	}{
		{"missing", map[string]string{}, "is required"},
		{"blank", map[string]string{"network": "  "}, "is required"},
		{"unknown name", map[string]string{"network": "notanetwork"}, "not a network"},
		{"short hash", map[string]string{"network": base64.StdEncoding.EncodeToString(custom[:31])}, "not a network"},
		{"other parameter", map[string]string{"network": "testnet", "height": "22"}, "unknown parameter"},
	} {
		if _, err := GenesisHashParameter(tt.params); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.want)
		}
	}
}

func TestRegisterRefusesAnIncompleteDescriptor(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Register accepted a descriptor with no payload builder")
		}
	}()
	Register(Descriptor{KeyType: "aplane.rotating-test.v1", Family: "aplane.rotating-test"})
}
