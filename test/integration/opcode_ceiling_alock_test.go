// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/library/templates"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/test/integration/harness"

	sdkalgod "github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestALockDeclaredOpcodeCeilings(t *testing.T) {
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to integration algod: %v", err)
	}
	compileAlgod := matrixCompileAlgod(t, network)
	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("load funding account: %v", err)
	}
	assetID := createCorridorTestAsset(t, network, funder)
	account := newALockOpcodeAccount(t, compileAlgod, funder.GetAddress(), assetID)
	if err := funder.FundMicroAlgosAndWait(account.address, 500_000); err != nil {
		t.Fatalf("fund ALock opcode-validation account: %v", err)
	}
	cleanupAuthority := algocrypto.GenerateAccount()
	t.Cleanup(func() {
		bestEffortBoundedAdminRekey(t, network, account, cleanupAuthority.Address)
		bestEffortCloseBoundedAsset(t, network, account.address, funder.GetAddress(), assetID, cleanupAuthority.PrivateKey)
		bestEffortCloseRekeyedAccount(t, network, account.address, funder.GetAddress(), cleanupAuthority.PrivateKey)
	})

	optIn := corridorAssetTransferTxn(
		t, mustSuggestedParams(t, network), account.address, account.address, 0, assetID, "alock-opcode-asset-optin",
	)
	rawOptIn, optInID := account.signGroup(t, optIn, false)
	submitCorridorGroupExpectSuccess(t, network, rawOptIn, optInID)
	sendAssetFromFunder(t, network, funder, account.address, assetID, 2)

	sp := mustSuggestedParams(t, network)
	spendTxn := corridorAssetTransferTxn(
		t, sp, account.address, funder.GetAddress(), 1, assetID, "alock-opcode-maximum-spend",
	)
	spendGroup, _ := account.signedGroup(t, spendTxn, false)
	rekeyTxn := boundedPaymentTxn(t, sp, account.address, account.address, 0, "alock-opcode-admin-rekey")
	rekeyTxn.RekeyTo = cleanupAuthority.Address
	adminGroup, _ := account.signedGroup(t, rekeyTxn, true)

	profile := account.provider.LogicSigOpcodeProfile()
	report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), compileAlgod, harness.OpcodeCeilingValidation{
		Name:         "aplane.falcon1024-allowlist-alock.v1",
		FinalProgram: account.bytecode,
		Profile:      profile,
		Bounded:      true,
		RequiredPaths: []lsigresource.AuthorizationPath{
			lsigresource.PathSpend,
			lsigresource.PathAdminRekey,
		},
		Vectors: []harness.OpcodeCeilingVector{
			{Name: "maximum-asset-spend", Path: lsigresource.PathSpend, SignedTxns: spendGroup, LSigIndex: 0},
			{Name: "maximum-admin-rekey", Path: lsigresource.PathAdminRekey, SignedTxns: adminGroup, LSigIndex: 0},
		},
	})
	if err != nil {
		t.Fatalf("validate ALock opcode ceilings: %v", err)
	}
	for path, observed := range report.Paths {
		t.Logf("ALock path %d opcode cost: %d observed / %d declared", path, observed.MaximumObserved, observed.DeclaredCeiling)
	}
}

func newALockOpcodeAccount(
	t *testing.T,
	compileAlgod *sdkalgod.Client,
	recipient string,
	assetID uint64,
) boundedExecutionAccount {
	t.Helper()
	falcon1024.RegisterClient()
	data, err := templates.ReadFile("aplane.falcon1024-allowlist-alock.v1.yaml")
	if err != nil {
		t.Fatalf("read ALock template: %v", err)
	}
	spec, err := composeddsa.ParseTemplateSpec(data)
	if err != nil {
		t.Fatalf("parse ALock template: %v", err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("build ALock provider: %v", err)
	}
	provider.SetAlgodClient(compileAlgod)

	ops := signerops.New(nil)
	spendingPublicKey, spendingPrivateKey, err := ops.GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate ALock spending key: %v", err)
	}
	adminPublicKey, adminPrivateKey, err := ops.GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate ALock admin key: %v", err)
	}
	params := map[string]string{
		"recipients":         matrixMaximumRecipients(recipient),
		"asset_ids":          matrixMaximumAssetIDsEndingWith(assetID),
		"max_payment_amount": "18446744073709551615",
		"max_asset_amount":   "18446744073709551615",
		composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(adminPublicKey),
	}
	derived, err := provider.DeriveLsigWithSalt(context.Background(), spendingPublicKey, params)
	if err != nil {
		t.Fatalf("derive ALock LogicSig: %v", err)
	}
	metadata, err := provider.BuildBoundedAuthorizationMetadata(spendingPublicKey, params, derived.Bytecode)
	if err != nil {
		t.Fatalf("build ALock metadata: %v", err)
	}
	return boundedExecutionAccount{
		address: derived.Address.String(), bytecode: append([]byte(nil), derived.Bytecode...),
		spendingPublicKey: append([]byte(nil), spendingPublicKey...), spendingPrivateKey: append([]byte(nil), spendingPrivateKey...),
		adminPublicKey: append([]byte(nil), adminPublicKey...), adminPrivateKey: append([]byte(nil), adminPrivateKey...),
		provider: provider, metadata: metadata,
	}
}

func matrixMaximumAssetIDsEndingWith(assetID uint64) string {
	return matrixAssetIDsEndingWith(assetID, 30)
}

func matrixAssetIDsEndingWith(assetID uint64, count int) string {
	ids := make([]string, 0, count)
	for candidate := uint64(1); len(ids) < count-1; candidate++ {
		if candidate != assetID {
			ids = append(ids, fmt.Sprintf("%d", candidate))
		}
	}
	ids = append(ids, fmt.Sprintf("%d", assetID))
	return strings.Join(ids, ",")
}

func bestEffortBoundedAdminRekey(
	t *testing.T,
	network *harness.TestnetConfig,
	account boundedExecutionAccount,
	target types.Address,
) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Logf("cleanup: ALock contract-admin rekey skipped after panic: %v", recovered)
		}
	}()
	txn := boundedPaymentTxn(t, mustSuggestedParams(t, network), account.address, account.address, 0, "alock-cleanup-admin-rekey")
	txn.RekeyTo = target
	rawGroup, txid := account.signGroup(t, txn, true)
	if _, err := network.Client.SendRawTransaction(rawGroup).Do(context.Background()); err != nil {
		t.Logf("cleanup: ALock contract-admin rekey submit failed: %v", err)
		return
	}
	if _, err := network.WaitForConfirmation(txid, 10); err != nil {
		t.Logf("cleanup: ALock contract-admin rekey confirmation failed: %v", err)
	}
}
