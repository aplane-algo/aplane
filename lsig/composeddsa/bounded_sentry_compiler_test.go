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
	boundedprogram "github.com/aplane-algo/aplane/internal/boundedadmin/program"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestBoundedSentryCompilerGolden(t *testing.T) {
	falcon1024.RegisterClient()
	spec, err := composeddsa.ParseTemplateSpec([]byte(`
schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: aplane
family: bounded-sentry-compiler-test
version: 1
display_name: Bounded Sentry Compiler Test
max_opcode_cost: 20000
bounded:
  contract: bounded1
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  admin_operations:
    - kind: rekey
      authorization: admin_key
      policy_gate: none
  sentry:
    contract: sentry1
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
	sentryKey := bytes.Repeat([]byte{0x22}, boundedmeta.SentryPublicKeySizeV1)
	adminKey := bytes.Repeat([]byte{0x33}, boundedmeta.FalconAdminPublicKeySize)
	params := map[string]string{
		composeddsa.BoundedSentryPublicKeyParameter: hex.EncodeToString(sentryKey),
		composeddsa.BoundedAdminPublicKeyParameter:  hex.EncodeToString(adminKey),
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
	binding, err := hex.DecodeString(metadata.ProgramBindingHex)
	if err != nil {
		t.Fatal(err)
	}
	if err := boundedprogram.Validate(bytecode, boundedprogram.Expected{
		SpendingPublicKey: spendingKey,
		SentryPublicKey:   sentryKey,
		AdminPublicKey:    adminKey,
		ProgramBinding:    binding,
		BaseArgCount:      1,
		SentryArgIndex:    1,
		AdminArgIndex:     2,
		MaxFee:            10_000,
		SpendEffects:      []string{"pay", "axfer", "asset_opt_in"},
	}); err != nil {
		t.Fatalf("Validate(compiled bounded sentry) error = %v", err)
	}
	// Golden moved when derivation_version 2 was retired: under the v13
	// auto-salt contract finishSaltedTEAL appends no counter-byte trailer, so
	// the emitted TEAL loses exactly the trailing comment and `bytecblock 0x00`.
	hash := sha256.Sum256([]byte(teal))
	if got, want := hex.EncodeToString(hash[:]), "b747f4a983896901af9ac8229263407e4790516e38a7cae00afa7d5877c2ba0b"; got != want {
		t.Fatalf("TEAL SHA-256 = %s, want %s", got, want)
	}
	// 4 bytes smaller than the retired v2 golden: bytecblock opcode, element
	// count, element length, and the single salt byte.
	if got, want := len(bytecode), 5_669; got != want {
		t.Fatalf("compiled bytecode size = %d, want %d; TEAL SHA-256 %x", got, want, hash)
	}
	if got, want := metadata.ArgumentBytesForPath(boundedmeta.PathSpend), 2_846; got != want {
		t.Fatalf("spend argument bytes = %d, want %d", got, want)
	}
	if got, want := metadata.ArgumentBytesForPath(boundedmeta.PathAdminRekey), 2_846; got != want {
		t.Fatalf("admin-rekey argument bytes = %d, want %d", got, want)
	}
}
