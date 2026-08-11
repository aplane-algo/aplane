// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falcon1024guarded

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestProviderValidateCreationParams(t *testing.T) {
	p := NewProviderV1()
	valid := strings.Repeat("01", family.PublicKeySize)

	if err := p.ValidateCreationParams(map[string]string{ParamSentryPublicKey: valid}); err != nil {
		t.Fatalf("ValidateCreationParams(valid) error = %v", err)
	}
	if err := p.ValidateCreationParams(map[string]string{ParamSentryPublicKey: "0x" + valid}); err != nil {
		t.Fatalf("ValidateCreationParams(0x valid) error = %v", err)
	}

	tests := []struct {
		name   string
		params map[string]string
		want   string
	}{
		{name: "missing", params: nil, want: "missing required parameter"},
		{name: "short", params: map[string]string{ParamSentryPublicKey: "01"}, want: "expected 1793 bytes"},
		{name: "bad hex", params: map[string]string{ParamSentryPublicKey: "not-hex"}, want: "invalid hex"},
		{name: "unknown", params: map[string]string{ParamSentryPublicKey: valid, "extra": "1"}, want: "unknown parameter"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.ValidateCreationParams(tt.params)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateCreationParams() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestGenerateTEALBuildsRoleSeparatedVerifier(t *testing.T) {
	p := NewProviderV1()
	userPublicKey := bytes.Repeat([]byte{0xa1}, family.PublicKeySize)
	sentryPublicKeyHex := strings.Repeat("b2", family.PublicKeySize)

	teal, err := p.GenerateTEAL(userPublicKey, map[string]string{ParamSentryPublicKey: sentryPublicKeyHex})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}

	checks := []string{
		"#pragma version 12",
		"byte 0x" + lsigsalt.PushbytesSaltMarkerHex(0),
		"sha512_256",
		"arg 0",
		"falcon_verify",
		"assert",
		"arg 1",
		"pushbytes 0x" + strings.Repeat("a1", family.PublicKeySize),
		"pushbytes 0x" + sentryPublicKeyHex,
		"pushbytes 0x" + bytesToHex([]byte(message.DomainTagV1)),
		"pushbytes 0x01",
		"pushbytes 0x02",
	}
	for _, want := range checks {
		if !strings.Contains(teal, want) {
			t.Fatalf("GenerateTEAL() missing %q:\n%s", want, teal)
		}
	}

	if strings.Index(teal, "arg 0") > strings.Index(teal, "arg 1") {
		t.Fatalf("user signature arg must precede sentry arg:\n%s", teal)
	}
	if strings.Count(teal, "falcon_verify") != 2 {
		t.Fatalf("GenerateTEAL() falcon_verify count = %d, want 2:\n%s", strings.Count(teal, "falcon_verify"), teal)
	}
	if strings.Contains(teal, "ed25519verify_bare") {
		t.Fatalf("GenerateTEAL() unexpectedly includes ed25519 verifier:\n%s", teal)
	}
	if strings.Index(teal, "arg 0") > strings.Index(teal, "arg 1") {
		t.Fatalf("user signature arg must precede sentry arg:\n%s", teal)
	}
	if strings.Count(teal, "txn TxID") != 2 {
		t.Fatalf("GenerateTEAL() txn TxID count = %d, want 2:\n%s", strings.Count(teal, "txn TxID"), teal)
	}
}

func TestBuildArgsUnpacksComponentSignatures(t *testing.T) {
	p := NewProviderV1()
	userSig := bytes.Repeat([]byte{0x11}, 100)
	sentrySig := bytes.Repeat([]byte{0x22}, 200)

	packed, err := PackComponentSignatures(userSig, sentrySig)
	if err != nil {
		t.Fatalf("PackComponentSignatures() error = %v", err)
	}
	args, err := p.BuildArgs(packed, nil)
	if err != nil {
		t.Fatalf("BuildArgs() error = %v", err)
	}
	if len(args) != 2 {
		t.Fatalf("BuildArgs() len = %d, want 2", len(args))
	}
	if !bytes.Equal(args[0], userSig) || !bytes.Equal(args[1], sentrySig) {
		t.Fatalf("BuildArgs() = %x/%x, want %x/%x", args[0], args[1], userSig, sentrySig)
	}
}

func TestComponentSignaturePackingUsesCompressedMaximum(t *testing.T) {
	for _, size := range []int{1281, family.MaxSignatureSize} {
		userSig := bytes.Repeat([]byte{0x11}, size)
		sentrySig := bytes.Repeat([]byte{0x22}, size)
		packed, err := PackComponentSignatures(userSig, sentrySig)
		if err != nil {
			t.Fatalf("PackComponentSignatures(%d) error = %v", size, err)
		}
		gotUser, gotSentry, err := UnpackComponentSignaturesForKeyType(KeyTypeV1, packed)
		if err != nil {
			t.Fatalf("UnpackComponentSignaturesForKeyType(%d) error = %v", size, err)
		}
		if !bytes.Equal(gotUser, userSig) || !bytes.Equal(gotSentry, sentrySig) {
			t.Fatalf("signature round trip at %d bytes did not preserve components", size)
		}
	}

	tooLarge := bytes.Repeat([]byte{0x33}, family.MaxSignatureSize+1)
	if _, err := PackComponentSignatures(tooLarge, []byte{1}); err == nil {
		t.Fatalf("PackComponentSignatures accepted %d-byte user signature", len(tooLarge))
	}
	if _, err := PackComponentSignatures([]byte{1}, tooLarge); err == nil {
		t.Fatalf("PackComponentSignatures accepted %d-byte sentry signature", len(tooLarge))
	}
}

func TestBuildArgsRejectsMalformedSignatureBlob(t *testing.T) {
	p := NewProviderV1()
	_, err := p.BuildArgs([]byte{0, 1, 2}, nil)
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("BuildArgs(short) error = %v, want too short", err)
	}
	_, err = PackComponentSignaturesForKeyType(KeyTypeV1, []byte{1}, nil)
	if err == nil || !strings.Contains(err.Error(), "sentry Falcon signature length") {
		t.Fatalf("PackComponentSignaturesForKeyType(bad sentry) error = %v, want length error", err)
	}
	_, err = p.BuildArgs([]byte{0, 1, 1, 0, 0}, nil)
	if err == nil || !strings.Contains(err.Error(), "sentry Falcon signature length") {
		t.Fatalf("BuildArgs(bad sentry length) error = %v, want length error", err)
	}
	_, err = p.BuildArgs([]byte{0, 1, 1, 2}, map[string][]byte{"extra": {1}})
	if err == nil || !strings.Contains(err.Error(), "unknown arg") {
		t.Fatalf("BuildArgs(runtime args) error = %v, want unknown arg", err)
	}
}

func bytesToHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0f]
	}
	return string(out)
}
