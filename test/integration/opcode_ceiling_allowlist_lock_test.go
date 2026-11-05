// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"encoding/hex"
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

func TestAllowlistLockDeclaredOpcodeCeilings(t *testing.T) {
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to integration algod: %v", err)
	}
	compileAlgod := matrixCompileAlgod(t, network)
	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("load funding account: %v", err)
	}
	assetID := corridorTestAssetID(t, network, funder)
	account := newAllowlistLockOpcodeAccount(t, compileAlgod, funder.GetAddress())
	if err := funder.FundMicroAlgosAndWait(account.address, 500_000); err != nil {
		t.Fatalf("fund allowlist-lock opcode-validation account: %v", err)
	}
	cleanupAuthority := algocrypto.GenerateAccount()
	t.Cleanup(func() {
		bestEffortBoundedAdminRekey(t, network, account, cleanupAuthority.Address)
		bestEffortCloseBoundedAsset(t, network, account.address, funder.GetAddress(), assetID, cleanupAuthority.PrivateKey)
		bestEffortCloseRekeyedAccount(t, network, account.address, funder.GetAddress(), cleanupAuthority.PrivateKey)
	})

	optIn := corridorAssetTransferTxn(
		t, mustSuggestedParams(t, network), account.address, account.address, 0, assetID, "allowlist-lock-opcode-asset-optin",
	)
	rawOptIn, optInID := account.signGroup(t, optIn, false)
	submitCorridorGroupExpectSuccess(t, network, rawOptIn, optInID)
	sendAssetFromFunder(t, network, funder, account.address, assetID, 2)

	sp := mustSuggestedParams(t, network)
	spendTxn := corridorAssetTransferTxn(
		t, sp, account.address, funder.GetAddress(), 1, assetID, "allowlist-lock-opcode-maximum-spend",
	)
	spendGroup, _ := account.signedGroup(t, spendTxn, false)
	rekeyTxn := boundedPaymentTxn(t, sp, account.address, account.address, 0, "allowlist-lock-opcode-admin-rekey")
	rekeyTxn.RekeyTo = cleanupAuthority.Address
	adminGroup, _ := account.signedGroup(t, rekeyTxn, true)

	profile := account.provider.LogicSigOpcodeProfile()
	report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), compileAlgod, harness.OpcodeCeilingValidation{
		Name:         "aplane.falcon1024-allowlist-lock.v1",
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
		t.Fatalf("validate allowlist-lock opcode ceilings: %v", err)
	}
	for path, observed := range report.Paths {
		t.Logf("allowlist-lock path %d opcode cost: %d observed / %d declared", path, observed.MaximumObserved, observed.DeclaredCeiling)
	}
}

func newAllowlistLockOpcodeAccount(
	t *testing.T,
	compileAlgod *sdkalgod.Client,
	recipient string,
) boundedExecutionAccount {
	t.Helper()
	falcon1024.RegisterClient()
	data, err := templates.ReadFile("aplane.falcon1024-allowlist-lock.v1.yaml")
	if err != nil {
		t.Fatalf("read allowlist-lock template: %v", err)
	}
	spec, err := composeddsa.ParseTemplateSpec(data)
	if err != nil {
		t.Fatalf("parse allowlist-lock template: %v", err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("build allowlist-lock provider: %v", err)
	}
	provider.SetAlgodClient(compileAlgod)

	ops := signerops.New(nil)
	spendingPublicKey, spendingPrivateKey, err := ops.GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate allowlist-lock spending key: %v", err)
	}
	adminPublicKey, adminPrivateKey, err := ops.GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate allowlist-lock admin key: %v", err)
	}
	params := map[string]string{
		"recipients": matrixMaximumRecipients(recipient),
		composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(adminPublicKey),
	}
	derived, err := provider.DeriveLsigWithSalt(context.Background(), spendingPublicKey, params)
	if err != nil {
		t.Fatalf("derive allowlist-lock LogicSig: %v", err)
	}
	metadata, err := provider.BuildBoundedAuthorizationMetadata(spendingPublicKey, params, derived.Bytecode)
	if err != nil {
		t.Fatalf("build allowlist-lock metadata: %v", err)
	}
	return boundedExecutionAccount{
		address: derived.Address.String(), bytecode: append([]byte(nil), derived.Bytecode...),
		spendingPublicKey: append([]byte(nil), spendingPublicKey...), spendingPrivateKey: append([]byte(nil), spendingPrivateKey...),
		adminPublicKey: append([]byte(nil), adminPublicKey...), adminPrivateKey: append([]byte(nil), adminPrivateKey...),
		provider: provider, metadata: metadata,
	}
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
			t.Logf("cleanup: allowlist-lock contract-admin rekey skipped after panic: %v", recovered)
		}
	}()
	txn := boundedPaymentTxn(t, mustSuggestedParams(t, network), account.address, account.address, 0, "allowlist-lock-cleanup-admin-rekey")
	txn.RekeyTo = target
	rawGroup, txid := account.signGroup(t, txn, true)
	if _, err := network.Client.SendRawTransaction(rawGroup).Do(context.Background()); err != nil {
		t.Logf("cleanup: allowlist-lock contract-admin rekey submit failed: %v", err)
		return
	}
	if _, err := network.WaitForConfirmation(txid, 10); err != nil {
		t.Logf("cleanup: allowlist-lock contract-admin rekey confirmation failed: %v", err)
	}
}
