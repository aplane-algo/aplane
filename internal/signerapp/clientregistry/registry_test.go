// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientregistry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func keyLine(key ssh.PublicKey, comment string) string {
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(key)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return line + "\n"
}

func TestParseAcceptsOptionFreeLinesCommentsAndLabels(t *testing.T) {
	a, b := testKey(t), testKey(t)
	data := "# enrolled clients\n\n" + keyLine(a, "laptop") + "\r\n" + keyLine(b, "")
	reg, err := Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if reg.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", reg.Len())
	}
	entry, ok := reg.Lookup(a)
	if !ok || entry.Label != "laptop" || entry.Fingerprint != ssh.FingerprintSHA256(a) {
		t.Fatalf("Lookup(a) = %+v, %v", entry, ok)
	}
	if entry, ok := reg.LookupFingerprint(ssh.FingerprintSHA256(b)); !ok || entry.Label != "" {
		t.Fatalf("LookupFingerprint(b) = %+v, %v", entry, ok)
	}
	if !reg.Has(b) || reg.Has(testKey(t)) {
		t.Fatal("Has() does not match enrollment")
	}
}

func TestParseRejectsOptionsMalformedAndDuplicates(t *testing.T) {
	a := testKey(t)
	tests := []struct {
		name     string
		data     string
		wantLine int
		wantText string
	}{
		{name: "openssh option", data: "restrict " + keyLine(a, ""), wantLine: 1, wantText: `option "restrict" is not implemented`},
		{name: "reserved prefix option", data: "# c\n" + `aplane-role="admin" ` + keyLine(a, ""), wantLine: 2, wantText: `option "aplane-role=\"admin\"" is not implemented`},
		{name: "malformed", data: keyLine(a, "") + "ssh-ed25519 not-base64\n", wantLine: 2, wantText: "malformed"},
		{name: "duplicate", data: keyLine(a, "one") + "\n" + keyLine(a, "two"), wantLine: 3, wantText: "duplicate of the key on line 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.data))
			var perr *Error
			if !errors.As(err, &perr) {
				t.Fatalf("Parse() error = %v, want *Error", err)
			}
			if perr.Line != tt.wantLine || !strings.Contains(perr.Reason, tt.wantText) {
				t.Fatalf("Parse() error = %q, want line %d containing %q", perr, tt.wantLine, tt.wantText)
			}
		})
	}
}

func TestParseEmptyAndNilRegistry(t *testing.T) {
	reg, err := Parse(nil)
	if err != nil || reg.Len() != 0 {
		t.Fatalf("Parse(nil) = %v, %v", reg, err)
	}
	var none *Registry
	if none.Len() != 0 || none.Has(testKey(t)) || none.Marshal() != nil {
		t.Fatal("nil registry is not empty")
	}
}

func TestWithKeyIsIdempotentAndMarshalRoundTrips(t *testing.T) {
	a, b := testKey(t), testKey(t)
	reg, _ := Parse(nil)
	reg, added := reg.WithKey(a, "laptop")
	if !added || reg.Len() != 1 {
		t.Fatalf("WithKey(a) added=%v len=%d", added, reg.Len())
	}
	again, added := reg.WithKey(a, "other label")
	if added || again.Len() != 1 || !bytes.Equal(again.Marshal(), reg.Marshal()) {
		t.Fatal("re-adding an enrolled key must change nothing")
	}
	reg, _ = reg.WithKey(b, "")

	parsed, err := Parse(reg.Marshal())
	if err != nil {
		t.Fatalf("Parse(Marshal()) error = %v", err)
	}
	if !bytes.Equal(parsed.Marshal(), reg.Marshal()) || parsed.Len() != 2 {
		t.Fatalf("round trip changed the registry:\n%s\n%s", reg.Marshal(), parsed.Marshal())
	}
	if want := keyLine(a, "laptop") + keyLine(b, ""); string(reg.Marshal()) != want {
		t.Fatalf("Marshal() =\n%s\nwant\n%s", reg.Marshal(), want)
	}
}

func TestWithoutFingerprint(t *testing.T) {
	a, b := testKey(t), testKey(t)
	reg, _ := Parse(nil)
	reg, _ = reg.WithKey(a, "a")
	reg, _ = reg.WithKey(b, "b")

	removed, err := reg.WithoutFingerprint(ssh.FingerprintSHA256(a))
	if err != nil || removed.Len() != 1 || removed.Has(a) || !removed.Has(b) {
		t.Fatalf("WithoutFingerprint(a) = %v, %v", removed, err)
	}
	if reg.Len() != 2 {
		t.Fatal("WithoutFingerprint mutated the receiver")
	}
	if _, err := reg.WithoutFingerprint("SHA256:nope"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("WithoutFingerprint(unknown) error = %v, want ErrNotEnrolled", err)
	}
}
