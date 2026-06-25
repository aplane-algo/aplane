// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sentryaccount

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

func TestMetaDefaults(t *testing.T) {
	meta := Meta{
		KeyTypeName:            "aplane.example.v1",
		BaseKeyTypeName:        "aplane.falcon1024.v1",
		FamilyName:             "aplane.example",
		DisplayNameText:        "Example",
		DescriptionText:        "example description",
		Color:                  "#123456",
		SignatureSizeBytes:     42,
		MnemonicSchemeName:     "bip39",
		MnemonicWordCountValue: 24,
	}

	if got := meta.KeyType(); got != "aplane.example.v1" {
		t.Fatalf("KeyType() = %q", got)
	}
	if got := meta.BaseKeyType(); got != "aplane.falcon1024.v1" {
		t.Fatalf("BaseKeyType() = %q", got)
	}
	if got := meta.RoutingFamily(); got != "aplane.example" {
		t.Fatalf("RoutingFamily() = %q", got)
	}
	if got := meta.Version(); got != 1 {
		t.Fatalf("Version() = %d, want 1", got)
	}
	if got := meta.Category(); got != lsigprovider.CategoryDSALsig {
		t.Fatalf("Category() = %q, want %q", got, lsigprovider.CategoryDSALsig)
	}
	if got := meta.CryptoSignatureSize(); got != 42 {
		t.Fatalf("CryptoSignatureSize() = %d, want 42", got)
	}
	if meta.SupportsMnemonicImport() {
		t.Fatalf("SupportsMnemonicImport() = true, want false")
	}
	if args := meta.RuntimeArgs(); args != nil {
		t.Fatalf("RuntimeArgs() = %#v, want nil", args)
	}
}

func TestNewAlgorithmMetadata(t *testing.T) {
	meta := NewAlgorithmMetadata("aplane.example", 99, "bip39", 24, "#123456")

	if got := meta.RoutingFamily(); got != "aplane.example" {
		t.Fatalf("RoutingFamily() = %q", got)
	}
	if got := meta.CryptoSignatureSize(); got != 99 {
		t.Fatalf("CryptoSignatureSize() = %d, want 99", got)
	}
	if got := meta.MnemonicScheme(); got != "bip39" {
		t.Fatalf("MnemonicScheme() = %q", got)
	}
	if got := meta.MnemonicWordCount(); got != 24 {
		t.Fatalf("MnemonicWordCount() = %d, want 24", got)
	}
	if !meta.RequiresLogicSig() {
		t.Fatalf("RequiresLogicSig() = false, want true")
	}
	if meta.SupportsMnemonicImport() {
		t.Fatalf("SupportsMnemonicImport() = true, want false")
	}
}

func TestAlgodHolderRejectsUnsetClient(t *testing.T) {
	var holder AlgodHolder
	_, err := holder.AlgodClient()
	if err == nil || !strings.Contains(err.Error(), "algod client not set") {
		t.Fatalf("AlgodClient() error = %v, want unset client error", err)
	}
}

func TestComponentCodecVariableSentryRoundTrip(t *testing.T) {
	codec := ComponentCodec{
		UserLabel:   "user Falcon",
		UserMaxSize: 4,
		SentryLabel: "sentry Falcon",
		SentrySize:  VariableSentrySize(5),
		BlobLabel:   "corridor",
	}
	user := []byte{1, 2, 3}
	sentry := []byte{4, 5, 6, 7}

	packed, err := codec.Pack(user, sentry)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	gotUser, gotSentry, err := codec.Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}
	if !bytes.Equal(gotUser, user) || !bytes.Equal(gotSentry, sentry) {
		t.Fatalf("Unpack() = %v/%v, want %v/%v", gotUser, gotSentry, user, sentry)
	}

	_, err = codec.Pack(nil, sentry)
	if err == nil || !strings.Contains(err.Error(), "user Falcon signature length") {
		t.Fatalf("Pack(nil user) error = %v, want user length error", err)
	}
	_, _, err = codec.Unpack([]byte{0, 1, 0})
	if err == nil || !strings.Contains(err.Error(), "corridor signature blob is too short") {
		t.Fatalf("Unpack(short) error = %v, want short blob error", err)
	}
}

func TestComponentCodecFixedSentryRoundTrip(t *testing.T) {
	codec := ComponentCodec{
		UserMaxSize: 4,
		SentrySize:  FixedSentrySize(2),
	}
	user := []byte{1, 2, 3}
	sentry := []byte{4, 5}

	packed, err := codec.Pack(user, sentry)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	gotUser, gotSentry, err := codec.Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}
	if !bytes.Equal(gotUser, user) || !bytes.Equal(gotSentry, sentry) {
		t.Fatalf("Unpack() = %v/%v, want %v/%v", gotUser, gotSentry, user, sentry)
	}

	_, err = codec.Pack(user, []byte{9})
	if err == nil || !strings.Contains(err.Error(), "sentry signature length 1 invalid") {
		t.Fatalf("Pack(short sentry) error = %v, want fixed-length error", err)
	}
}

func TestDecodeSentryPublicKey(t *testing.T) {
	got, err := DecodeSentryPublicKey("0x0102", 2)
	if err != nil {
		t.Fatalf("DecodeSentryPublicKey() error = %v", err)
	}
	if !bytes.Equal(got, []byte{1, 2}) {
		t.Fatalf("DecodeSentryPublicKey() = %x, want 0102", got)
	}

	_, err = DecodeSentryPublicKey("zz", 1)
	if err == nil || !strings.Contains(err.Error(), "must be hex") {
		t.Fatalf("DecodeSentryPublicKey(bad hex) error = %v, want hex error", err)
	}
	_, err = DecodeSentryPublicKey("0102", 1)
	if err == nil || !strings.Contains(err.Error(), "expected 1 bytes") {
		t.Fatalf("DecodeSentryPublicKey(bad length) error = %v, want length error", err)
	}
}

func TestRejectRuntimeArgs(t *testing.T) {
	if err := RejectRuntimeArgs(nil); err != nil {
		t.Fatalf("RejectRuntimeArgs(nil) error = %v", err)
	}
	err := RejectRuntimeArgs(map[string][]byte{"extra": {1}})
	if err == nil || !strings.Contains(err.Error(), "unknown arg: extra") {
		t.Fatalf("RejectRuntimeArgs(extra) error = %v, want unknown arg", err)
	}
}
