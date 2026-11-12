// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestBoundedCosignerCompilerGolden(t *testing.T) {
	falcon1024.RegisterClient()
	spec, err := composeddsa.ParseTemplateSpec([]byte(`
schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: aplane
family: bounded-cosigner-compiler-test
version: 1
display_name: Bounded Cosigner Compiler Test
valid_rekey_target: true
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  rekey: refused
  cosigner:
    contract: cosigner1
    required_on: [spend]
teal: |
  pushint 1
  assert
`))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	spendingKey := bytes.Repeat([]byte{0x11}, falconfamily.PublicKeySize)
	cosignerKey := bytes.Repeat([]byte{0x22}, boundedmeta.CosignerPublicKeySizeV1)
	params := map[string]string{
		composeddsa.BoundedCosignerPublicKeyParameter: hex.EncodeToString(cosignerKey),
	}
	teal, err := provider.GenerateTEAL(spendingKey, params)
	if err != nil {
		t.Fatal(err)
	}
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := client.TealCompile([]byte(teal)).Do(context.Background())
	if err != nil {
		t.Fatalf("TealCompile() error = %v", err)
	}
	bytecode, err := base64.StdEncoding.DecodeString(compiled.Result)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := provider.BuildBoundedAuthorizationMetadata(spendingKey, params, bytecode)
	if err != nil {
		t.Fatal(err)
	}
	// Golden moved when derivation_version 2 was retired: under the v13
	// auto-salt contract finishSaltedTEAL appends no counter-byte trailer, so
	// the emitted TEAL loses exactly the trailing comment and `bytecblock 0x00`.
	// It moved again when the contract-admin key was removed: this profile now
	// refuses rekeys instead of carrying an admin-key rekey path. It moved once
	// more when bounded2 replaced bounded1, which renamed the envelope comment,
	// and again when the cosigner check became one subroutine every cosigned
	// path calls.
	hash := sha256.Sum256([]byte(teal))
	if got, want := hex.EncodeToString(hash[:]), "286a1655aea0ffee8c64dda26398f35e543a32139b7fa02dd8ab9c9766cbc054"; got != want {
		t.Fatalf("TEAL SHA-256 = %s, want %s", got, want)
	}
	// Pin the deployed compiler output separately from the source hash so
	// compiler-toolchain drift remains visible even when the TEAL is unchanged.
	if got, want := len(bytecode), 3_726; got != want {
		t.Fatalf("compiled bytecode size = %d, want %d; TEAL SHA-256 %x", got, want, hash)
	}
	if got, want := metadata.ArgumentBytesForPath(boundedmeta.PathSpend), 2_846; got != want {
		t.Fatalf("spend argument bytes = %d, want %d", got, want)
	}
}
