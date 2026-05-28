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
