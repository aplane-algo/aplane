// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypes

import (
	"crypto/sha512"
	"encoding/base32"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestSentryKeyTypeClassifiers(t *testing.T) {
	if !IsSentryComponentKeyType(SentryComponentEd25519V1) {
		t.Fatal("Ed25519 sentry key type was not classified as component")
	}
	if !IsSentryComponentKeyType(SentryComponentFalcon1024V1) {
		t.Fatal("Falcon sentry key type was not classified as component")
	}
	if !IsGuardedAccountKeyType(GuardedFalcon1024SentryEd25519V1) {
		t.Fatal("guarded Falcon account key type was not classified as guarded")
	}
	if !IsGuardedAccountKeyType(GuardedFalcon1024SentryFalcon1024V1) {
		t.Fatal("Falcon-guarded Falcon account key type was not classified as guarded")
	}
	if !IsGuardedAccountKeyType(CorridorV1) {
		t.Fatal("corridor account key type was not classified as guarded")
	}
	if IsSentryKeyType("aplane.falcon1024.v1") {
		t.Fatal("ordinary Falcon key type classified as sentry key type")
	}
	if IsSentryKeyType("aplane.future-att-future.v1") {
		t.Fatal("deferred future guarded key type classified as sentry key type")
	}
}

func TestSentryComponentKeyTypeForGuardedAccount(t *testing.T) {
	tests := []struct {
		keyType string
		want    string
		ok      bool
	}{
		{GuardedFalcon1024SentryEd25519V1, SentryComponentEd25519V1, true},
		{GuardedFalcon1024SentryFalcon1024V1, SentryComponentFalcon1024V1, true},
		{CorridorV1, SentryComponentFalcon1024V1, true},
		{SentryComponentEd25519V1, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			got, ok := SentryComponentKeyTypeForGuardedAccount(tt.keyType)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("SentryComponentKeyTypeForGuardedAccount() = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestComponentKeySelectorKnownVector(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}

	got, err := ComponentKeySelector(SentryComponentEd25519V1, pub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	want := expectedComponentSelector(SentryComponentEd25519V1, pub)
	if got != want {
		t.Fatalf("ComponentKeySelector() = %q, want %q", got, want)
	}
	if len(got) != ComponentKeySelectorLength {
		t.Fatalf("ComponentKeySelector() length = %d, want %d", len(got), ComponentKeySelectorLength)
	}
	if !IsComponentKeySelector(got) {
		t.Fatalf("IsComponentKeySelector(%q) = false, want true", got)
	}
	if _, err := types.DecodeAddress(got); err == nil {
		t.Fatalf("ComponentKeySelector() = %q decoded as an Algorand address", got)
	}
}

func TestFalconComponentKeySelectorKnownVector(t *testing.T) {
	pub := make([]byte, falconfamily.PublicKeySize)
	for i := range pub {
		pub[i] = byte(i)
	}

	got, err := ComponentKeySelector(SentryComponentFalcon1024V1, pub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	want := expectedComponentSelector(SentryComponentFalcon1024V1, pub)
	if got != want {
		t.Fatalf("ComponentKeySelector() = %q, want %q", got, want)
	}
	if len(got) != ComponentKeySelectorLength {
		t.Fatalf("ComponentKeySelector() length = %d, want %d", len(got), ComponentKeySelectorLength)
	}
	if !IsComponentKeySelector(got) {
		t.Fatalf("IsComponentKeySelector(%q) = false, want true", got)
	}
}

func TestComponentKeySelectorRejectsNonComponentKeyType(t *testing.T) {
	_, err := ComponentKeySelector(GuardedFalcon1024SentryEd25519V1, make([]byte, 32))
	if err == nil {
		t.Fatal("ComponentKeySelector() accepted guarded account key type")
	}
}

func TestNormalizeComponentKeySelector(t *testing.T) {
	const want = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	got, err := NormalizeComponentKeySelector(" " + want + " ")
	if err != nil {
		t.Fatalf("NormalizeComponentKeySelector() error = %v", err)
	}
	if got != want {
		t.Fatalf("NormalizeComponentKeySelector() = %q, want %q", got, want)
	}
}

func TestIsComponentKeySelectorRejectsInvalidValues(t *testing.T) {
	tests := []string{
		"",
		"not-an-address",
		"zzzz",
		"a_",
		"a_" + strings.Repeat("00", 32),
		"apc_" + strings.Repeat("00", 32),
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		"0X000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		strings.Repeat("A", ComponentKeySelectorLength-1),
		strings.Repeat("A", ComponentKeySelectorLength+1),
		strings.Repeat("A", 58),
		strings.ToLower(strings.Repeat("A", ComponentKeySelectorLength)),
		strings.Repeat("A", ComponentKeySelectorLength-1) + "=",
		strings.Repeat("0", ComponentKeySelectorLength),
		strings.Repeat("00", falconfamily.PublicKeySize),
	}
	for _, id := range tests {
		t.Run(id, func(t *testing.T) {
			if IsComponentKeySelector(id) {
				t.Fatalf("IsComponentKeySelector(%q) = true, want false", id)
			}
		})
	}
}

func expectedComponentSelector(keyType string, publicKey []byte) string {
	h := sha512.New512_256()
	_, _ = h.Write([]byte(componentKeySelectorDomain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(keyType))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(publicKey)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h.Sum(nil))
}
