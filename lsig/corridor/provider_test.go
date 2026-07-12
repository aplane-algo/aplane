// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package corridor

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/merkleallowlist"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestProviderValidateCreationParams(t *testing.T) {
	p := NewProviderV1()
	recipient := types.Address{1}.String()
	valid := map[string]string{
		ParamRecipients:      recipient,
		ParamSentryPublicKey: strings.Repeat("01", family.PublicKeySize),
	}

	if err := p.ValidateCreationParams(valid); err != nil {
		t.Fatalf("ValidateCreationParams(valid) error = %v", err)
	}
	withPrefix := map[string]string{
		ParamRecipients:      recipient,
		ParamSentryPublicKey: "0x" + valid[ParamSentryPublicKey],
	}
	if err := p.ValidateCreationParams(withPrefix); err != nil {
		t.Fatalf("ValidateCreationParams(0x public key) error = %v", err)
	}

	tests := []struct {
		name   string
		params map[string]string
		want   string
	}{
		{name: "missing recipients", params: map[string]string{ParamSentryPublicKey: valid[ParamSentryPublicKey]}, want: "missing required parameter: recipients"},
		{name: "missing sentry", params: map[string]string{ParamRecipients: recipient}, want: "missing required parameter: sentry_public_key"},
		{name: "bad recipient", params: map[string]string{ParamRecipients: "NOTADDR", ParamSentryPublicKey: valid[ParamSentryPublicKey]}, want: "invalid recipients"},
		{name: "bad sentry hex", params: map[string]string{ParamRecipients: recipient, ParamSentryPublicKey: "not-hex"}, want: "invalid hex"},
		{name: "short sentry", params: map[string]string{ParamRecipients: recipient, ParamSentryPublicKey: "01"}, want: "expected 1793 bytes"},
		{name: "unknown", params: map[string]string{ParamRecipients: recipient, ParamSentryPublicKey: valid[ParamSentryPublicKey], "extra": "1"}, want: "unknown parameter"},
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

func TestGenerateTEALBuildsCorridorVerifier(t *testing.T) {
	p := NewProviderV1()
	userPublicKey := bytes.Repeat([]byte{0xa1}, family.PublicKeySize)
	sentryPublicKeyHex := strings.Repeat("b2", family.PublicKeySize)
	recipients := strings.Join([]string{types.Address{1}.String(), types.Address{2}.String()}, ",")
	root, err := merkleallowlist.RootFromRecipientsParam(recipients)
	if err != nil {
		t.Fatalf("RootFromRecipientsParam() error = %v", err)
	}

	teal, err := p.GenerateTEAL(userPublicKey, map[string]string{
		ParamRecipients:      recipients,
		ParamSentryPublicKey: sentryPublicKeyHex,
	})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}

	checks := []string{
		"#pragma version 12",
		"byte 0x" + lsigsalt.PushbytesSaltMarkerHex(0),
		"arg 0",
		"arg 1",
		"arg 2",
		"falcon_verify",
		"corridor_verify_member",
		"txn RekeyTo",
		"txn Amount",
		"txn AssetReceiver",
		"pushbytes 0x" + strings.Repeat("a1", family.PublicKeySize),
		"pushbytes 0x" + sentryPublicKeyHex,
		"pushbytes 0x" + hex.EncodeToString([]byte(message.DomainTagV1)),
		"pushbytes 0x01",
		"pushbytes 0x02",
		"pushbytes 0x" + hex.EncodeToString(root[:]),
	}
	for _, want := range checks {
		if !strings.Contains(teal, want) {
			t.Fatalf("GenerateTEAL() missing %q:\n%s", want, teal)
		}
	}
	if strings.Count(teal, "falcon_verify") != 2 {
		t.Fatalf("GenerateTEAL() falcon_verify count = %d, want 2", strings.Count(teal, "falcon_verify"))
	}
	if strings.Index(teal, "arg 0") > strings.Index(teal, "arg 1") {
		t.Fatalf("user signature arg must precede sentry arg:\n%s", teal)
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

func TestBuildArgsRejectsMalformedSignatureBlob(t *testing.T) {
	p := NewProviderV1()
	_, err := p.BuildArgs([]byte{0, 1, 2}, nil)
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("BuildArgs(short) error = %v, want too short", err)
	}
	_, err = PackComponentSignatures([]byte{1}, nil)
	if err == nil || !strings.Contains(err.Error(), "sentry Falcon signature length") {
		t.Fatalf("PackComponentSignatures(bad sentry) error = %v, want length error", err)
	}
	_, err = p.BuildArgs([]byte{0, 1, 1, 0, 0}, nil)
	if err == nil || !strings.Contains(err.Error(), "sentry Falcon signature length") {
		t.Fatalf("BuildArgs(bad sentry length) error = %v, want length error", err)
	}
	_, err = p.BuildArgs([]byte{0, 1, 1, 0, 1, 2}, map[string][]byte{"extra": {1}})
	if err == nil || !strings.Contains(err.Error(), "unknown arg") {
		t.Fatalf("BuildArgs(runtime args) error = %v, want unknown arg", err)
	}
}

func TestAssemblyExtraArgsBuildsCorridorProof(t *testing.T) {
	p := NewProviderV1()
	sender := types.Address{1}
	recipient := types.Address{2}
	recipients := strings.Join([]string{recipient.String(), types.Address{3}.String()}, ",")
	root, err := merkleallowlist.RootFromRecipientsParam(recipients)
	if err != nil {
		t.Fatalf("RootFromRecipientsParam() error = %v", err)
	}

	args, err := p.AssemblyExtraArgs(types.Transaction{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: sender},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: recipient,
		},
	}, map[string]string{ParamRecipients: recipients})
	if err != nil {
		t.Fatalf("AssemblyExtraArgs() error = %v", err)
	}
	if len(args) != 1 {
		t.Fatalf("AssemblyExtraArgs() len = %d, want 1", len(args))
	}
	if !merkleallowlist.Verify(recipient, args[0], root) {
		t.Fatal("AssemblyExtraArgs() returned proof that does not verify")
	}
}

func TestAssemblyExtraArgsRejectsNonMember(t *testing.T) {
	p := NewProviderV1()
	sender := types.Address{1}
	recipient := types.Address{2}

	_, err := p.AssemblyExtraArgs(types.Transaction{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: sender},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: recipient,
		},
	}, map[string]string{ParamRecipients: types.Address{3}.String()})
	if err == nil || !strings.Contains(err.Error(), "corridor proof generation failed") || !strings.Contains(err.Error(), "not in allowlist") {
		t.Fatalf("AssemblyExtraArgs(non-member) error = %v, want corridor allowlist error", err)
	}
}

func TestAssemblyExtraArgsSkipsSelfTransfer(t *testing.T) {
	p := NewProviderV1()
	sender := types.Address{1}

	args, err := p.AssemblyExtraArgs(types.Transaction{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: sender},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: sender,
		},
	}, map[string]string{ParamRecipients: sender.String()})
	if err != nil {
		t.Fatalf("AssemblyExtraArgs(self) error = %v", err)
	}
	if args != nil {
		t.Fatalf("AssemblyExtraArgs(self) = %#v, want nil", args)
	}
}
