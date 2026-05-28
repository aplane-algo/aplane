// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package addressderive

import (
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

type stubDeriver struct {
	address string
	err     error
}

func (d stubDeriver) DeriveAddress(publicKeyHex string, params map[string]string) (string, error) {
	if d.err != nil {
		return "", d.err
	}
	return d.address + ":" + publicKeyHex + ":" + params["network"], nil
}

func TestRegisterAndGet(t *testing.T) {
	t.Cleanup(func() {
		globalRegistry = &registry{derivers: map[string]Deriver{}}
	})
	globalRegistry = &registry{derivers: map[string]Deriver{}}

	Register("stub", stubDeriver{address: "ADDR"})

	got, err := Get("stub")
	if err != nil {
		t.Fatalf("Get(stub) error = %v", err)
	}

	addr, err := got.DeriveAddress("abcd", map[string]string{"network": "testnet"})
	if err != nil {
		t.Fatalf("DeriveAddress() error = %v", err)
	}
	if addr != "ADDR:abcd:testnet" {
		t.Fatalf("DeriveAddress() = %q", addr)
	}
}

func TestGetMissingDeriver(t *testing.T) {
	t.Cleanup(func() {
		globalRegistry = &registry{derivers: map[string]Deriver{}}
	})
	globalRegistry = &registry{derivers: map[string]Deriver{}}

	_, err := Get("missing")
	if err == nil || !strings.Contains(err.Error(), "no address deriver registered") {
		t.Fatalf("Get(missing) error = %v, want missing-deriver error", err)
	}
}

func TestEd25519DeriverDeriveAddress(t *testing.T) {
	var addr types.Address
	for i := range addr {
		addr[i] = byte(i + 1)
	}

	got, err := GetEd25519().DeriveAddress(hex.EncodeToString(addr[:]), map[string]string{"ignored": "value"})
	if err != nil {
		t.Fatalf("DeriveAddress() error = %v", err)
	}
	if got != addr.String() {
		t.Fatalf("DeriveAddress() = %q, want %q", got, addr.String())
	}
}

func TestEd25519DeriverRejectsInvalidHex(t *testing.T) {
	_, err := GetEd25519().DeriveAddress("not-hex", nil)
	if err == nil || !strings.Contains(err.Error(), "failed to decode public key") {
		t.Fatalf("DeriveAddress(invalid) error = %v, want decode failure", err)
	}
}

func TestEd25519DeriverRejectsInvalidLength(t *testing.T) {
	for _, tt := range []struct {
		name string
		key  []byte
	}{
		{name: "short", key: make([]byte, 31)},
		{name: "long", key: make([]byte, 33)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetEd25519().DeriveAddress(hex.EncodeToString(tt.key), nil)
			if err == nil || !strings.Contains(err.Error(), "public key length") {
				t.Fatalf("DeriveAddress() error = %v, want length failure", err)
			}
		})
	}
}

func TestRegisterEd25519(t *testing.T) {
	t.Cleanup(func() {
		globalRegistry = &registry{derivers: map[string]Deriver{}}
		registerEd25519Once = sync.Once{}
	})
	globalRegistry = &registry{derivers: map[string]Deriver{}}
	registerEd25519Once = sync.Once{}

	RegisterEd25519()
	RegisterEd25519()

	got, err := Get("ed25519")
	if err != nil {
		t.Fatalf("Get(ed25519) error = %v", err)
	}
	if _, ok := got.(*Ed25519Deriver); !ok {
		t.Fatalf("Get(ed25519) type = %T, want *Ed25519Deriver", got)
	}
}
