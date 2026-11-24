// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package addressdisplay

import "testing"

type testAliases map[string]string

func (a testAliases) GetAliasForAddress(address string) string {
	return a[address]
}

func TestFormatAddressUsesAliasAndSignerColor(t *testing.T) {
	SetColorSupported(true)
	defer ResetColorSupport()

	got := FormatAddress(
		"ADDR1",
		testAliases{"ADDR1": "alice"},
		"falcon",
		true,
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

	got := FormatAddress("ADDR1", nil, "ed25519", true, nil)
	if got != "ADDR1 @" {
		t.Fatalf("FormatAddress() = %q, want signable marker", got)
	}
}

func TestFormatAddressMarksSignableWhenColorUnsupported(t *testing.T) {
	SetColorSupported(false)
	defer ResetColorSupport()

	// Formatter present (the normal production wiring) but terminal has no
	// color support: the plain-text marker must still appear.
	got := FormatAddress("ADDR1", nil, "ed25519", true,
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
	got := FormatAddress("ADDR1", nil, "mystery", true,
		func(string) string { return "" })
	if got != "ADDR1 @" {
		t.Fatalf("FormatAddress() = %q, want signable marker", got)
	}
}

func TestFormatAddressNoMarkerForUnsignableAccount(t *testing.T) {
	SetColorSupported(false)
	defer ResetColorSupport()

	got := FormatAddress("ADDR1", nil, "", false, nil)
	if got != "ADDR1" {
		t.Fatalf("FormatAddress() = %q, want plain address without marker", got)
	}
}
