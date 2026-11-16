// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package addressdisplay

import "testing"

type testAliases map[string]string

func (a testAliases) GetAliasForAddress(address string) string {
	return a[address]
}

type testSigner map[string]string

func (s testSigner) HasAddress(address string) bool {
	_, ok := s[address]
	return ok
}

func (s testSigner) GetKeyType(address string) string {
	return s[address]
}

func (s testSigner) IsRotating(string) bool { return false }

// rotatingSigner holds the rotating accounts in rotating too.
type rotatingSigner struct {
	testSigner
	rotating map[string]bool
}

func (s rotatingSigner) IsRotating(address string) bool { return s.rotating[address] }

type testAuth map[string]string

func (a testAuth) GetAuthAddress(address string) (string, bool) {
	auth, ok := a[address]
	return auth, ok
}

func TestFormatAddressUsesAliasAndSignerColor(t *testing.T) {
	SetColorSupported(true)
	defer ResetColorSupport()

	got := FormatAddress(
		"ADDR1",
		testAliases{"ADDR1": "alice"},
		testSigner{"AUTH1": "falcon"},
		testAuth{"ADDR1": "AUTH1"},
		"",
		func(keyType string) string {
			if keyType != "falcon" {
				t.Fatalf("color formatter key type = %q, want falcon", keyType)
			}
			return "33"
		},
	)
	want := "\033[33mADDR1 (alice)\033[0m"
	if got != want {
		t.Fatalf("FormatAddress() = %q, want %q", got, want)
	}
}

func TestFormatAddressMarksSignableWithoutColorFormatter(t *testing.T) {
	SetColorSupported(false)
	defer ResetColorSupport()

	got := FormatAddress("ADDR1", nil, testSigner{"ADDR1": "ed25519"}, nil, "", nil)
	if got != "ADDR1 @" {
		t.Fatalf("FormatAddress() = %q, want signable marker", got)
	}
}

func TestFormatAddressMarksSignableWhenColorUnsupported(t *testing.T) {
	SetColorSupported(false)
	defer ResetColorSupport()

	// Formatter present (the normal production wiring) but terminal has no
	// color support: the plain-text marker must still appear.
	got := FormatAddress("ADDR1", nil, testSigner{"ADDR1": "ed25519"}, nil, "",
		func(string) string { return "33" })
	if got != "ADDR1 @" {
		t.Fatalf("FormatAddress() = %q, want signable marker", got)
	}
}

func TestFormatAddressMarksSignableForUnregisteredKeyType(t *testing.T) {
	SetColorSupported(true)
	defer ResetColorSupport()

	// Color supported, but the key type has no registered color: fall back
	// to the plain-text marker rather than rendering indistinguishably.
	got := FormatAddress("ADDR1", nil, testSigner{"ADDR1": "mystery"}, nil, "",
		func(string) string { return "" })
	if got != "ADDR1 @" {
		t.Fatalf("FormatAddress() = %q, want signable marker", got)
	}
}

func TestFormatAddressNoMarkerForUnsignableAccount(t *testing.T) {
	SetColorSupported(false)
	defer ResetColorSupport()

	got := FormatAddress("ADDR1", nil, testSigner{}, nil, "", nil)
	if got != "ADDR1" {
		t.Fatalf("FormatAddress() = %q, want plain address without marker", got)
	}
}

// A rotating account the signer holds is signable whatever the auth cache
// shows: its current stage authorizes it, and the stage is in no cache. It is
// coloured by its own key type, and marked where there is no colour.
func TestFormatAddressMarksARotatingAccountAtAnyStage(t *testing.T) {
	signer := rotatingSigner{testSigner{"ROT": "rotating"}, map[string]bool{"ROT": true}}
	auth := testAuth{"ROT": "STAGE7"}

	SetColorSupported(true)
	got := FormatAddress("ROT", nil, signer, auth, "", func(keyType string) string {
		if keyType != "rotating" {
			t.Fatalf("color formatter key type = %q, want the account's own", keyType)
		}
		return "33"
	})
	ResetColorSupport()
	if got != "\033[33mROT\033[0m" {
		t.Fatalf("FormatAddress() = %q, want the account coloured", got)
	}

	SetColorSupported(false)
	defer ResetColorSupport()
	if got := FormatAddress("ROT", nil, signer, auth, "", nil); got != "ROT @" {
		t.Fatalf("FormatAddress() = %q, want the signable marker", got)
	}
	// The same account held as an ordinary key, rekeyed to a stage it does
	// not hold, is not signable.
	if got := FormatAddress("ROT", nil, signer.testSigner, auth, "", nil); got != "ROT" {
		t.Fatalf("FormatAddress() = %q, want no marker", got)
	}
}
