// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/algo"
	boundedprogram "github.com/aplane-algo/aplane/internal/boundedadmin/program"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/library/templates"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestBundledFalconAdminAllowlistV1Contract(t *testing.T) {
	falcon1024.RegisterClient()
	data, err := templates.ReadFile("aplane.falcon1024-allowlist-alock.v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := composeddsa.ParseTemplateSpec(data)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	if provider.KeyType() != "aplane.falcon1024-allowlist-alock.v1" {
		t.Fatalf("KeyType() = %q", provider.KeyType())
	}
	params := provider.CreationParams()
	if len(params) != 5 || params[0].Name != "recipients" || params[1].Name != "asset_ids" || params[2].Name != "max_payment_amount" || params[3].Name != "max_asset_amount" || params[4].Name != boundedmeta.AdminPublicKeyParameter || params[0].MaxItems != composeddsa.BoundedInlineListMax || params[1].MaxItems != composeddsa.BoundedInlineListMax {
		t.Fatalf("CreationParams() = %#v", params)
	}
	if provider.Layer3PolicyName() != boundedmeta.Layer3PolicyFixedAllowlist {
		t.Fatalf("Layer3PolicyName() = %q", provider.Layer3PolicyName())
	}
	profile := provider.BoundedAuthorizationProfile()
	if profile == nil || profile.Contract != boundedmeta.ContractV1 || profile.MaxFee != 10_000 || len(profile.SpendEffects) != 3 || len(profile.AdminOperations) != 1 || profile.AdminOperations[0].Authorization != composeddsa.AdminAuthorizationAdminKey {
		t.Fatalf("BoundedAuthorizationProfile() = %#v", profile)
	}
	inventoryMetadata := provider.BoundedAuthorizationMetadata()
	if inventoryMetadata == nil || inventoryMetadata.Contract != boundedmeta.ContractV1 || inventoryMetadata.MaxFee != 10_000 || inventoryMetadata.BaseSignatureArgLayout.Count != 1 || inventoryMetadata.Layer3Policy != boundedmeta.Layer3PolicyFixedAllowlist {
		t.Fatalf("BoundedAuthorizationMetadata() = %#v", inventoryMetadata)
	}
	if len(inventoryMetadata.ArgumentLayout) != 2 || inventoryMetadata.ArgumentLayout[1].Source != boundedmeta.ArgSourceAdmin || inventoryMetadata.ArgumentLayout[1].Paths.Spend != boundedmeta.ArgForbidden || inventoryMetadata.ArgumentLayout[1].Paths.AdminRekey != boundedmeta.ArgRequired {
		t.Fatalf("admin argument layout = %#v", inventoryMetadata.ArgumentLayout)
	}
	if inventoryMetadata.AdminKeyID != "" || inventoryMetadata.ProgramBindingHex != "" || inventoryMetadata.PostSigningLogicSigSize != 0 {
		t.Fatalf("template inventory contains instance metadata: %#v", inventoryMetadata)
	}

	spendingKey := bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	adminKey := bytes.Repeat([]byte{0x31}, composeddsa.BoundedAdminPublicKeySize)
	recipient := types.Address{1}
	values := map[string]string{
		"recipients":         recipient.String(),
		"asset_ids":          "7,11",
		"max_payment_amount": "1000000",
		"max_asset_amount":   "250",
		composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(adminKey),
	}
	teal, err := provider.GenerateTEAL(spendingKey, values)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	for _, want := range []string{
		"txn Fee\npushint 10000\n<=\nassert",
		"txn RekeyTo\nglobal ZeroAddress\n!=\nbnz __aplane_bounded1_rekey",
		"arg 1\nlen\npushint 1423\n<=\nassert",
		hex.EncodeToString(adminKey),
		hex.EncodeToString(recipient[:]),
		"// === framework-owned fixed allowlist ===",
		"txn Receiver\ncallsub __aplane_bounded1_layer3_recipient_allowed",
		"txn AssetReceiver\ncallsub __aplane_bounded1_layer3_recipient_allowed",
		"txn XferAsset\ncallsub __aplane_bounded1_layer3_asset_allowed",
		"txn Amount\npushint 1000000\n<=\nassert",
		"txn AssetAmount\npushint 250\n<=\nassert",
	} {
		if !strings.Contains(teal, want) {
			t.Fatalf("GenerateTEAL() missing %q:\n%s", want, teal)
		}
	}
	if strings.Count(teal, "falcon_verify") != 2 {
		t.Fatalf("GenerateTEAL() Falcon verifier count = %d, want 2", strings.Count(teal, "falcon_verify"))
	}

	metadata, err := provider.BuildBoundedAuthorizationMetadata(spendingKey, values, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("BoundedAuthorizationMetadata() error = %v", err)
	}
	if metadata == nil || metadata.Contract != boundedmeta.ContractV1 || metadata.AdminKeyID == "" || metadata.AdminPublicKeyHex != hex.EncodeToString(adminKey) || metadata.ProgramBindingHex == "" || len(metadata.DerivedArgs) != 0 || metadata.Layer3Policy != boundedmeta.Layer3PolicyFixedAllowlist {
		t.Fatalf("BoundedAuthorizationMetadata() = %#v", metadata)
	}
	if got, want := metadata.LogicSigSizeForPath(boundedmeta.PathSpend), 3+falconfamily.MaxSignatureSize; got != want {
		t.Fatalf("spend LogicSig size = %d, want %d", got, want)
	}
	if got, want := metadata.LogicSigSizeForPath(boundedmeta.PathAdminRekey), 3+falconfamily.MaxSignatureSize+boundedmeta.FalconAdminSignatureSize; got != want {
		t.Fatalf("admin LogicSig size = %d, want %d", got, want)
	}
	if got, want := provider.CompatibilityFingerprint(), "1:03da87e5491d266432cba9472eaf067639a362543ec50be941295eec4aaee399"; got != want {
		t.Fatalf("CompatibilityFingerprint() = %q, want %q", got, want)
	}

	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
	if err != nil {
		t.Fatalf("create TEAL compiler client: %v", err)
	}
	compiledResult, err := client.TealCompile([]byte(teal)).Do(context.Background())
	if err != nil {
		t.Fatalf("TealCompile() error = %v", err)
	}
	bytecode, err := base64.StdEncoding.DecodeString(compiledResult.Result)
	if err != nil {
		t.Fatalf("decode compiled program: %v", err)
	}
	metadata, err = provider.BuildBoundedAuthorizationMetadata(spendingKey, values, bytecode)
	if err != nil {
		t.Fatalf("BoundedAuthorizationMetadata(compiled) error = %v", err)
	}
	binding, err := hex.DecodeString(metadata.ProgramBindingHex)
	if err != nil {
		t.Fatal(err)
	}
	if err := boundedprogram.Validate(bytecode, boundedprogram.Expected{
		SpendingPublicKey: spendingKey,
		AdminPublicKey:    adminKey,
		ProgramBinding:    binding,
		BaseArgCount:      1,
		AdminArgIndex:     1,
		MaxFee:            10_000,
		SpendEffects:      []string{"pay", "axfer", "asset_opt_in"},
	}); err != nil {
		t.Fatalf("Validate(compiled bounded1 program) error = %v", err)
	}
}

func TestBundledFalconAdminAllowlistV1AllowsOmittedOptionalConstraints(t *testing.T) {
	falcon1024.RegisterClient()
	data, err := templates.ReadFile("aplane.falcon1024-allowlist-alock.v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := composeddsa.ParseTemplateSpec(data)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}

	spendingKey := bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	adminKey := bytes.Repeat([]byte{0x31}, composeddsa.BoundedAdminPublicKeySize)
	baseValues := map[string]string{
		"recipients": types.Address{1}.String(),
		composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(adminKey),
	}
	for _, test := range []struct {
		name   string
		values map[string]string
	}{
		{name: "omitted", values: baseValues},
		{name: "explicit empty", values: map[string]string{
			"recipients": types.Address{1}.String(), "asset_ids": "",
			"max_payment_amount": "", "max_asset_amount": "",
			composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(adminKey),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			teal, err := provider.GenerateTEAL(spendingKey, test.values)
			if err != nil {
				t.Fatalf("GenerateTEAL() error = %v", err)
			}
			metadata, err := provider.BuildBoundedAuthorizationMetadata(spendingKey, test.values, []byte(teal))
			if err != nil {
				t.Fatalf("BuildBoundedAuthorizationMetadata() error = %v", err)
			}
			if metadata.ProgramBindingHex == "" || metadata.AdminKeyID == "" {
				t.Fatalf("missing contract-admin identity metadata: %#v", metadata)
			}
		})
	}
}

func TestBundledFalconAdminAllowlistRejectsSpendingKeyAsAdminWitness(t *testing.T) {
	falcon1024.RegisterClient()
	data, err := templates.ReadFile("aplane.falcon1024-allowlist-alock.v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := composeddsa.ParseTemplateSpec(data)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}

	publicKey := bytes.Repeat([]byte{0x41}, falconfamily.PublicKeySize)
	values := map[string]string{
		"recipients": types.Address{1}.String(),
		composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(publicKey),
	}
	if _, err := provider.GenerateTEAL(publicKey, values); err == nil || !strings.Contains(err.Error(), "must differ from the spending key") {
		t.Fatalf("GenerateTEAL() error = %v, want key distinctness rejection", err)
	}
	if _, err := provider.BuildBoundedAuthorizationMetadata(publicKey, values, []byte{1}); err == nil || !strings.Contains(err.Error(), "must differ from the spending key") {
		t.Fatalf("BuildBoundedAuthorizationMetadata() error = %v, want key distinctness rejection", err)
	}
}

func TestBundledFalconAdminAllowlistV1MaximumBudget(t *testing.T) {
	falcon1024.RegisterClient()
	data, err := templates.ReadFile("aplane.falcon1024-allowlist-alock.v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := composeddsa.ParseTemplateSpec(data)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatal(err)
	}

	recipients := make([]string, composeddsa.BoundedInlineListMax)
	assetIDs := make([]string, composeddsa.BoundedInlineListMax)
	for i := range recipients {
		address := types.Address{}
		address[0] = byte(i + 1)
		recipients[i] = address.String()
		assetIDs[i] = fmt.Sprintf("%d", i+1)
	}
	spendingKey := bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	adminKey := bytes.Repeat([]byte{0x31}, composeddsa.BoundedAdminPublicKeySize)
	values := map[string]string{
		"recipients":         strings.Join(recipients, ","),
		"asset_ids":          strings.Join(assetIDs, ","),
		"max_payment_amount": "18446744073709551615",
		"max_asset_amount":   "18446744073709551615",
		composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(adminKey),
	}
	teal, err := provider.GenerateTEAL(spendingKey, values)
	if err != nil {
		t.Fatal(err)
	}
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := client.TealCompile([]byte(teal)).Do(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	bytecode, err := base64.StdEncoding.DecodeString(compiled.Result)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := provider.BuildBoundedAuthorizationMetadata(spendingKey, values, bytecode)
	if err != nil {
		t.Fatal(err)
	}
	groupSize := (metadata.PostSigningLogicSigSize + 999) / 1000
	if len(bytecode) != 5308 || metadata.PostSigningLogicSigSize != 8154 || groupSize != 9 {
		t.Fatalf("maximum budget = bytecode %d, post-signing %d, group %d; want 5308/8154/9", len(bytecode), metadata.PostSigningLogicSigSize, groupSize)
	}
	feeTests := []struct {
		minFee uint64
		viable bool
	}{
		{minFee: 1_000, viable: true},
		{minFee: 1_111, viable: true},
		{minFee: 1_112, viable: false},
	}
	for _, test := range feeTests {
		requiredFee := uint64(groupSize) * test.minFee
		if got := requiredFee <= metadata.MaxFee; got != test.viable {
			t.Fatalf("minimum fee %d viability = %v (required %d, ceiling %d), want %v", test.minFee, got, requiredFee, metadata.MaxFee, test.viable)
		}
	}
}
