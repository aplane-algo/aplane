// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/algo"
	boundedprogram "github.com/aplane-algo/aplane/internal/boundedadmin/program"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

const validatorMutationTemplate = `
schema_version: 2
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: validator-mutation
version: 1
display_name: Validator Mutation
max_opcode_cost: 20000
bounded:
  contract: bounded1
  spend_effects: [pay]
  max_fee: 10000
  admin_operations:
    - kind: rekey
      authorization: admin_key
      policy_gate: none
  cosigner:
    contract: cosigner1
    required_on: [spend]
teal: |
  pushint 1
  assert
`

func compileForValidator(t *testing.T, client *algod.Client, teal string) []byte {
	t.Helper()
	compiled, err := client.TealCompile([]byte(teal)).Do(context.Background())
	if err != nil {
		t.Fatalf("TealCompile() error = %v", err)
	}
	bytecode, err := base64.StdEncoding.DecodeString(compiled.Result)
	if err != nil {
		t.Fatal(err)
	}
	return bytecode
}

// The adversarial cases in internal/boundedadmin/program build programs by hand. These
// start from what the renderer really emits, so they also prove the validator still
// accepts that output and that each mutation changes it. The validator is the
// independent Falcon check on the admin path: every mutant here is a program that
// should never reach a contract-admin signature.
func TestExternalAdminValidatorRefusesMutatedRendererOutput(t *testing.T) {
	falcon.RegisterClient()
	spec, err := composeddsa.ParseTemplateSpec([]byte(validatorMutationTemplate))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	spendingKey := bytes.Repeat([]byte{0x11}, falconfamily.PublicKeySize)
	cosignerKey := bytes.Repeat([]byte{0x22}, boundedmeta.CosignerPublicKeySizeV1)
	adminKey := bytes.Repeat([]byte{0x33}, boundedmeta.FalconAdminPublicKeySize)
	params := map[string]string{
		composeddsa.BoundedCosignerPublicKeyParameter: hex.EncodeToString(cosignerKey),
		composeddsa.BoundedAdminPublicKeyParameter:    hex.EncodeToString(adminKey),
	}
	teal, err := provider.GenerateTEAL(spendingKey, params)
	if err != nil {
		t.Fatal(err)
	}
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), algo.ResolveTEALCompileAlgodToken())
	if err != nil {
		t.Fatal(err)
	}
	bytecode := compileForValidator(t, client, teal)
	metadata, err := provider.BuildBoundedAuthorizationMetadata(spendingKey, params, bytecode)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := hex.DecodeString(metadata.ProgramBindingHex)
	if err != nil {
		t.Fatal(err)
	}
	expected := boundedprogram.Expected{
		SpendingPublicKey: spendingKey, CosignerPublicKey: cosignerKey, AdminPublicKey: adminKey,
		ProgramBinding: binding, BaseArgCount: 1, CosignerArgIndex: 1, AdminArgIndex: 2,
		MaxFee: 10_000, SpendEffects: []string{"pay"},
	}
	if err := boundedprogram.Validate(bytecode, expected); err != nil {
		t.Fatalf("Validate(unmutated) error = %v", err)
	}

	const (
		pragma   = "#pragma version 13\n"
		rekey    = "__aplane_bounded1_rekey:\n"
		spend    = "__aplane_bounded1_spend:\n"
		dispatch = "txn RekeyTo\nglobal ZeroAddress\n!=\nbnz __aplane_bounded1_rekey\n"
		fee      = "txn Fee\npushint 10000\n<=\nassert\n"
		accept   = "b __aplane_bounded1_accept\n"
	)
	verify := func(index string, key []byte) string {
		return "arg " + index + "\npushbytes 0x" + hex.EncodeToString(key) + "\nfalcon_verify\n"
	}
	spendingVerify := "txn TxID\n" + verify("0", spendingKey)
	adminVerify := verify("2", adminKey)
	cosignerVerify := verify("1", cosignerKey)

	for name, mutation := range map[string][2]string{
		"spending authentication removed":   {spendingVerify + "assert\n", ""},
		"spending assertion removed":        {spendingVerify + "assert\n", spendingVerify + "pop\n"},
		"instruction before authentication": {pragma, pragma + "pushint 1\nassert\n"},
		"return before authentication":      {pragma, pragma + "pushint 1\nreturn\n"},
		"fee gate separated":                {fee, "pushint 1\npop\n" + fee},
		"fee gate removed":                  {fee, ""},
		"fee ceiling raised":                {fee, "txn Fee\npushint 10001\n<=\nassert\n"},
		"return before the envelope":        {dispatch, "pushint 1\nreturn\n" + dispatch},
		"branch past the envelope":          {dispatch, accept + dispatch},
		"rekey dispatch removed":            {dispatch, ""},
		"return before the rekey checks":    {rekey, rekey + "pushint 1\nreturn\n"},
		"admin authentication bypassed":     {rekey, rekey + accept},
		"admin verification removed":        {adminVerify + "assert\n", "pop\n"},
		"admin assertion removed":           {adminVerify + "assert\n", adminVerify + "pop\n"},
		"admin key replaced":                {adminVerify, verify("2", spendingKey)},
		"admin slot changed":                {adminVerify, strings.Replace(adminVerify, "arg 2", "arg 1", 1)},
		"branch into admin authentication":  {adminVerify + "assert\n", adminVerify + "assert\n__aplane_mutation:\n"},
		"cosigner authentication bypassed":  {spend, spend + "b __aplane_bounded1_layer3\n"},
		"cosigner verification removed":     {cosignerVerify + "assert\n", "pop\n"},
		"cosigner assertion removed":        {cosignerVerify + "assert\n", cosignerVerify + "pop\n"},
		"cosigner key replaced":             {cosignerVerify, verify("1", adminKey)},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(teal, mutation[0]) {
				t.Fatalf("rendered program no longer contains %q", mutation[0])
			}
			mutated := strings.Replace(teal, mutation[0], mutation[1], 1)
			if name == "branch into admin authentication" {
				mutated = strings.Replace(mutated, rekey, rekey+"b __aplane_mutation\n", 1)
			}
			if err := boundedprogram.Validate(compileForValidator(t, client, mutated), expected); err == nil {
				t.Fatal("the validator accepted a mutated program")
			}
		})
	}
}
