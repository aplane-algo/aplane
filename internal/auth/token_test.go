// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestTokenAuthenticatorGenerationIncrementsOnUpdate(t *testing.T) {
	ta := NewTokenAuthenticator("old-token")

	gen, ok := ta.ValidateTokenGeneration("old-token")
	if !ok {
		t.Fatal("old token did not validate")
	}
	if gen != 1 {
		t.Fatalf("initial generation = %d, want 1", gen)
	}

	ta.UpdateToken("new-token")

	if _, ok := ta.ValidateTokenGeneration("old-token"); ok {
		t.Fatal("old token validated after update")
	}
	gen, ok = ta.ValidateTokenGeneration("new-token")
	if !ok {
		t.Fatal("new token did not validate")
	}
	if gen != 2 {
		t.Fatalf("generation after update = %d, want 2", gen)
	}
	if ta.Generation() != 2 {
		t.Fatalf("Generation() = %d, want 2", ta.Generation())
	}
}

func TestTokenAuthenticatorComputeHMACPairUsesOneGeneration(t *testing.T) {
	ta := NewTokenAuthenticator("proof-token")
	firstMessage := []byte("server-input")
	secondMessage := []byte("client-input")

	first, second, generation, ok := ta.ComputeHMACPair(firstMessage, secondMessage)
	if !ok {
		t.Fatal("ComputeHMACPair() rejected a configured token")
	}
	if generation != 1 {
		t.Fatalf("generation = %d, want 1", generation)
	}
	if want := testHMAC("proof-token", firstMessage); !bytes.Equal(first, want) {
		t.Fatalf("first MAC = %x, want %x", first, want)
	}
	if want := testHMAC("proof-token", secondMessage); !bytes.Equal(second, want) {
		t.Fatalf("second MAC = %x, want %x", second, want)
	}

	ta.UpdateToken("rotated-token")
	rotatedFirst, rotatedSecond, generation, ok := ta.ComputeHMACPair(firstMessage, secondMessage)
	if !ok {
		t.Fatal("ComputeHMACPair() rejected the rotated token")
	}
	if generation != 2 {
		t.Fatalf("rotated generation = %d, want 2", generation)
	}
	if bytes.Equal(first, rotatedFirst) || bytes.Equal(second, rotatedSecond) {
		t.Fatal("token rotation did not change both MACs")
	}
}

func TestTokenAuthenticatorComputeHMACPairRejectsMissingInputs(t *testing.T) {
	tests := []struct {
		name          string
		authenticator *TokenAuthenticator
		first         []byte
		second        []byte
	}{
		{name: "empty token", authenticator: NewTokenAuthenticator(""), first: []byte("a"), second: []byte("b")},
		{name: "empty first", authenticator: NewTokenAuthenticator("token"), second: []byte("b")},
		{name: "empty second", authenticator: NewTokenAuthenticator("token"), first: []byte("a")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first, second, generation, ok := test.authenticator.ComputeHMACPair(test.first, test.second)
			if ok || first != nil || second != nil || generation != 0 {
				t.Fatalf("ComputeHMACPair() = (%x, %x, %d, %v), want rejected zero result", first, second, generation, ok)
			}
		})
	}
}

func testHMAC(token string, message []byte) []byte {
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}
