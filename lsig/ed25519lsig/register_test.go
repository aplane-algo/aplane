// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package ed25519lsig

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

func TestRegisterClientRegistersEd25519LogicSigBase(t *testing.T) {
	RegisterClient()

	if !composeddsa.IsBaseRegistered(KeyTypeV1) {
		t.Fatalf("composed base %q is not registered", KeyTypeV1)
	}
	if dsa := logicsigdsa.Get(KeyTypeV1); dsa == nil {
		t.Fatalf("logicsigdsa.Get(%q) = nil", KeyTypeV1)
	}
	provider := lsigprovider.Get(KeyTypeV1)
	if provider == nil {
		t.Fatalf("lsigprovider.Get(%q) = nil", KeyTypeV1)
	}
	mnemonicProvider, ok := provider.(lsigprovider.MnemonicProvider)
	if !ok {
		t.Fatalf("provider %T does not implement MnemonicProvider", provider)
	}
	if !mnemonicProvider.SupportsMnemonicImport() {
		t.Fatalf("provider %T does not support mnemonic import", provider)
	}
	if got := mnemonicProvider.MnemonicScheme(); got != "algorand" {
		t.Fatalf("MnemonicScheme() = %q, want algorand", got)
	}
}

func TestEd25519LogicSigBaseAcceptsComposedTemplateShape(t *testing.T) {
	RegisterClient()

	spec, err := composeddsa.ParseTemplateSpec([]byte(`
schema_version: 1
derivation_version: 3
template_type: composed
base_key_type: aplane.ed25519.v1
template_mode: generated
publisher: makman
family: demo-v2-test
version: 1
display_name: "Makman Demo V2 Test"
max_opcode_cost: 20000
teal: |
  int 1
  assert
`))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if err := composeddsa.ValidateTemplateSpec(spec); err != nil {
		t.Fatalf("ValidateTemplateSpec() error = %v", err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	if got := provider.KeyType(); got != "makman.demo-v2-test.v1" {
		t.Fatalf("KeyType() = %q, want makman.demo-v2-test.v1", got)
	}

	publicKey := bytes.Repeat([]byte{0x42}, 32)
	teal, err := provider.GenerateTEAL(publicKey, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	if !strings.Contains(teal, "ed25519verify_bare") {
		t.Fatalf("GenerateTEAL() did not contain ed25519verify_bare:\n%s", teal)
	}
	if !strings.Contains(teal, "pushbytes 0x424242") {
		t.Fatalf("GenerateTEAL() did not embed the public key:\n%s", teal)
	}
}

func TestEd25519LogicSigProviderBuildArgs(t *testing.T) {
	RegisterClient()

	provider := lsigprovider.Get(KeyTypeV1)
	if provider == nil {
		t.Fatalf("lsigprovider.Get(%q) = nil", KeyTypeV1)
	}
	signature := bytes.Repeat([]byte{0x11}, 64)
	args, err := provider.BuildArgs(signature, nil)
	if err != nil {
		t.Fatalf("BuildArgs() error = %v", err)
	}
	if len(args) != 1 || !bytes.Equal(args[0], signature) {
		t.Fatalf("BuildArgs() = %#v, want one signature arg", args)
	}
	if _, err := provider.BuildArgs(signature[:63], nil); err == nil {
		t.Fatal("BuildArgs() accepted short Ed25519 signature")
	}
}
