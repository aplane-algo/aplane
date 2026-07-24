// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	stded25519 "crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/merkleallowlist"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/library/templates"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/test/integration/harness"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const corridorExecutionGroupSize = 10

func TestCorridorLogicSigExecutionMatrixLocalnet(t *testing.T) {
	if harness.IntegrationNetwork() != harness.IntegrationNetworkLocalnet {
		t.Skip("corridor LogicSig execution matrix requires localnet")
	}

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to localnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	allowedAccount := algocrypto.GenerateAccount()
	allowed := allowedAccount.Address
	outside := algocrypto.GenerateAccount().Address
	funderAddress := mustDecodeAddress(t, funder.GetAddress())
	transferAccount := newCorridorExecutionAccount(t, testnet, []types.Address{allowed, funderAddress})
	if err := funder.FundMicroAlgosAndWait(transferAccount.address, 500_000); err != nil {
		t.Fatalf("failed to fund corridor transfer account %s: %v", transferAccount.address, err)
	}
	if err := funder.FundMicroAlgosAndWait(allowed.String(), 300_000); err != nil {
		t.Fatalf("failed to fund corridor allowed recipient %s: %v", allowed.String(), err)
	}

	assetID := createCorridorTestAsset(t, testnet, funder)
	submitEd25519TxnExpectSuccess(t, testnet, allowedAccount.PrivateKey,
		corridorAssetTransferTxn(t, mustSuggestedParams(t, testnet), allowed.String(), allowed.String(), 0, assetID, "corridor-allowed-asset-optin"))
	bestEffortSubmitCorridorCase(t, testnet, transferAccount, func(sp types.SuggestedParams) types.Transaction {
		return corridorAssetTransferTxn(t, sp, transferAccount.address, transferAccount.address, 0, assetID, "corridor-self-asset-optin")
	}, nil)
	sendAssetFromFunder(t, testnet, funder, transferAccount.address, assetID, 2)
	cleanupAuthority := algocrypto.GenerateAccount()
	t.Cleanup(func() {
		bestEffortCorridorAdminRekey(t, testnet, transferAccount, cleanupAuthority.Address)
		bestEffortCloseBoundedAsset(t, testnet, transferAccount.address, funder.GetAddress(), assetID, cleanupAuthority.PrivateKey)
		bestEffortCloseRekeyedAccount(t, testnet, transferAccount.address, funder.GetAddress(), cleanupAuthority.PrivateKey)
		bestEffortCloseBoundedAsset(t, testnet, allowed.String(), funder.GetAddress(), assetID, allowedAccount.PrivateKey)
		bestEffortCloseRekeyedAccount(t, testnet, allowed.String(), funder.GetAddress(), allowedAccount.PrivateKey)
	})

	t.Run("payment to allowlisted recipient with proof succeeds", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), transferAccount.address, allowed.String(), 0, "corridor-allow")
		rawGroup, txid := transferAccount.signGroup(t, txn, transferAccount.proofFor(t, allowed), nil)
		submitCorridorGroupExpectSuccess(t, testnet, rawGroup, txid)
	})

	t.Run("payment to allowlisted recipient without proof fails", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), transferAccount.address, allowed.String(), 0, "corridor-deny-missing-proof")
		rawGroup, _ := transferAccount.signGroup(t, txn, nil, nil)
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})

	t.Run("self payment without proof succeeds", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), transferAccount.address, transferAccount.address, 0, "corridor-self")
		rawGroup, txid := transferAccount.signGroup(t, txn, nil, nil)
		submitCorridorGroupExpectSuccess(t, testnet, rawGroup, txid)
	})

	t.Run("asset transfer to allowlisted recipient with proof succeeds", func(t *testing.T) {
		txn := corridorAssetTransferTxn(t, mustSuggestedParams(t, testnet), transferAccount.address, allowed.String(), 1, assetID, "corridor-asset-allow")
		rawGroup, txid := transferAccount.signGroup(t, txn, transferAccount.proofFor(t, allowed), nil)
		submitCorridorGroupExpectSuccess(t, testnet, rawGroup, txid)
	})

	t.Run("payment to non-allowlisted recipient fails", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), transferAccount.address, outside.String(), 0, "corridor-deny-outside")
		rawGroup, _ := transferAccount.signGroup(t, txn, transferAccount.proofFor(t, allowed), nil)
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})

	t.Run("corrupted proof fails", func(t *testing.T) {
		proof := transferAccount.proofFor(t, allowed)
		proof[17] ^= 0xff
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), transferAccount.address, allowed.String(), 0, "corridor-deny-proof")
		rawGroup, _ := transferAccount.signGroup(t, txn, proof, nil)
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})

	_, wrongSentryPrivateKey, err := signerops.New(nil).GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("failed to generate wrong sentry keypair: %v", err)
	}
	sentrySlot := transferAccount.argumentIndex(t, boundedmeta.ArgSourceSentry)
	t.Run("empty sentry slot fails", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), transferAccount.address, transferAccount.address, 0, "corridor-deny-empty-sentry")
		rawGroup, _ := transferAccount.signGroup(t, txn, nil, func(_ types.Digest, args [][]byte) [][]byte {
			args[sentrySlot] = []byte{}
			return args
		})
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})
	t.Run("signature from wrong sentry key fails", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), transferAccount.address, transferAccount.address, 0, "corridor-deny-wrong-sentry")
		rawGroup, _ := transferAccount.signGroup(t, txn, nil, func(txid types.Digest, args [][]byte) [][]byte {
			args[sentrySlot] = transferAccount.signComponent(t, message.RoleSentry, txid, wrongSentryPrivateKey)
			return args
		})
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})
	t.Run("user-role sentry signature fails", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), transferAccount.address, transferAccount.address, 0, "corridor-deny-wrong-role")
		rawGroup, _ := transferAccount.signGroup(t, txn, nil, func(txid types.Digest, args [][]byte) [][]byte {
			args[sentrySlot] = transferAccount.signComponent(t, message.RoleUser, txid, transferAccount.sentryPrivateKey)
			return args
		})
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})
	t.Run("sentry signature over wrong transaction ID fails", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), transferAccount.address, transferAccount.address, 0, "corridor-deny-wrong-txid")
		rawGroup, _ := transferAccount.signGroup(t, txn, nil, func(txid types.Digest, args [][]byte) [][]byte {
			txid[0] ^= 0xff
			args[sentrySlot] = transferAccount.signComponent(t, message.RoleSentry, txid, transferAccount.sentryPrivateKey)
			return args
		})
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})

	rekeyTarget := algocrypto.GenerateAccount()
	rekeyAccount := newCorridorExecutionAccount(t, testnet, []types.Address{allowed})
	if err := funder.FundMicroAlgosAndWait(rekeyAccount.address, 200_000); err != nil {
		t.Fatalf("failed to fund corridor rekey account %s: %v", rekeyAccount.address, err)
	}

	t.Run("malformed rekey with nonzero amount fails", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), rekeyAccount.address, rekeyAccount.address, 1, "corridor-deny-rekey-amount")
		txn.RekeyTo = rekeyTarget.Address
		rawGroup, _ := rekeyAccount.signGroup(t, txn, nil, nil)
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})

	t.Run("malformed rekey with non-self receiver fails", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), rekeyAccount.address, allowed.String(), 0, "corridor-deny-rekey-receiver")
		txn.RekeyTo = rekeyTarget.Address
		rawGroup, _ := rekeyAccount.signGroup(t, txn, nil, nil)
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})

	t.Run("malformed rekey with close remainder fails", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), rekeyAccount.address, rekeyAccount.address, 0, "corridor-deny-rekey-close")
		txn.RekeyTo = rekeyTarget.Address
		mustSetAddress(t, &txn.CloseRemainderTo, funder.GetAddress())
		rawGroup, _ := rekeyAccount.signGroup(t, txn, nil, nil)
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})

	t.Run("pure rekey without contract-admin proof fails", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), rekeyAccount.address, rekeyAccount.address, 0, "corridor-allow-rekey")
		txn.RekeyTo = rekeyTarget.Address
		rawGroup, _ := rekeyAccount.signGroup(t, txn, nil, nil)
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})

	t.Run("pure rekey with contract-admin proof succeeds", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), rekeyAccount.address, rekeyAccount.address, 0, "corridor-admin-rekey")
		txn.RekeyTo = rekeyTarget.Address
		rawGroup, txid := rekeyAccount.signGroup(t, txn, nil, func(txid types.Digest, args [][]byte) [][]byte {
			return rekeyAccount.adminRekeyArgs(t, args[0], txid)
		})
		submitCorridorGroupExpectSuccess(t, testnet, rawGroup, txid)
		accountInfo, err := testnet.Client.AccountInformation(rekeyAccount.address).Do(context.Background())
		if err != nil {
			t.Fatalf("read rekeyed Corridor account: %v", err)
		}
		if accountInfo.AuthAddr != rekeyTarget.Address.String() {
			t.Fatalf("Corridor auth address = %q, want %q", accountInfo.AuthAddr, rekeyTarget.Address.String())
		}
		t.Cleanup(func() {
			bestEffortCloseRekeyedAccount(t, testnet, rekeyAccount.address, funder.GetAddress(), rekeyTarget.PrivateKey)
		})
	})
}

type corridorExecutionAccount struct {
	address          string
	bytecode         []byte
	recipientsParam  string
	userPrivateKey   []byte
	sentryPrivateKey []byte
	adminPrivateKey  []byte
	metadata         *boundedmeta.Metadata
}

func newCorridorExecutionAccount(t *testing.T, testnet *harness.TestnetConfig, recipients []types.Address) corridorExecutionAccount {
	t.Helper()
	if len(recipients) == 0 {
		t.Fatal("corridor execution account requires at least one recipient")
	}

	ops := signerops.New(nil)
	userPublicKey, userPrivateKey, err := ops.GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("failed to generate corridor user keypair: %v", err)
	}
	sentryPublicKey, sentryPrivateKey, err := ops.GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("failed to generate corridor sentry keypair: %v", err)
	}
	adminPublicKey, adminPrivateKey, err := ops.GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("failed to generate corridor admin keypair: %v", err)
	}

	recipientStrings := make([]string, len(recipients))
	for i, recipient := range recipients {
		recipientStrings[i] = recipient.String()
	}
	recipientsParam := strings.Join(recipientStrings, ",")
	falcon1024.RegisterClient()
	templateData, err := templates.ReadFile("aplane.corridor.v1.yaml")
	if err != nil {
		t.Fatalf("failed to read Corridor template: %v", err)
	}
	spec, err := composeddsa.ParseTemplateSpec(templateData)
	if err != nil {
		t.Fatalf("failed to parse Corridor template: %v", err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("failed to build Corridor provider: %v", err)
	}
	provider.SetAlgodClient(testnet.Client)
	params := map[string]string{
		"recipients": recipientsParam,
		composeddsa.BoundedSentryPublicKeyParameter: hex.EncodeToString(sentryPublicKey),
		composeddsa.BoundedAdminPublicKeyParameter:  hex.EncodeToString(adminPublicKey),
	}
	derived, err := provider.DeriveLsigWithSalt(context.Background(), userPublicKey, params)
	if err != nil {
		t.Fatalf("failed to derive corridor LogicSig: %v", err)
	}
	metadata, err := provider.BuildBoundedAuthorizationMetadata(userPublicKey, params, derived.Bytecode)
	if err != nil {
		t.Fatalf("failed to build Corridor bounded metadata: %v", err)
	}

	return corridorExecutionAccount{
		address:          derived.Address.String(),
		bytecode:         derived.Bytecode,
		recipientsParam:  recipientsParam,
		userPrivateKey:   userPrivateKey,
		sentryPrivateKey: sentryPrivateKey,
		adminPrivateKey:  adminPrivateKey,
		metadata:         metadata,
	}
}

func (a corridorExecutionAccount) proofFor(t *testing.T, recipient types.Address) []byte {
	t.Helper()
	proof, err := merkleallowlist.ProofForAddressParam(a.recipientsParam, recipient)
	if err != nil {
		t.Fatalf("failed to build corridor proof for %s: %v", recipient, err)
	}
	return proof
}

func (a corridorExecutionAccount) signGroup(t *testing.T, targetTxn types.Transaction, proof []byte, mutateArgs func(types.Digest, [][]byte) [][]byte) ([]byte, string) {
	t.Helper()

	minFee := uint64(1_000)
	if targetTxn.Fee > 0 {
		minFee = uint64(targetTxn.Fee)
	}
	targetTxn.Fee = types.MicroAlgos(uint64(corridorExecutionGroupSize) * minFee)

	dummySP := types.SuggestedParams{
		Fee:             types.MicroAlgos(minFee),
		GenesisID:       targetTxn.GenesisID,
		GenesisHash:     targetTxn.GenesisHash[:],
		FirstRoundValid: targetTxn.FirstValid,
		LastRoundValid:  targetTxn.LastValid,
		FlatFee:         true,
	}
	dummies, err := signing.CreateDummyTransactions(corridorExecutionGroupSize-1, dummySP)
	if err != nil {
		t.Fatalf("failed to build corridor dummy transactions: %v", err)
	}
	allTxns := make([]types.Transaction, 0, 1+len(dummies))
	allTxns = append(allTxns, targetTxn)
	allTxns = append(allTxns, dummies...)
	groupID, err := algocrypto.ComputeGroupID(allTxns)
	if err != nil {
		t.Fatalf("failed to compute corridor group ID: %v", err)
	}
	targetTxn.Group = groupID
	for i := range dummies {
		dummies[i].Group = groupID
	}

	txidBytes := algocrypto.TransactionID(targetTxn)
	var txid types.Digest
	if len(txidBytes) != len(txid) {
		t.Fatalf("corridor transaction ID length %d, want %d", len(txidBytes), len(txid))
	}
	copy(txid[:], txidBytes)
	userSignature, err := signerops.New(nil).Sign(a.userPrivateKey, txid[:])
	if err != nil {
		t.Fatalf("failed to sign corridor base message: %v", err)
	}
	sentrySignature := a.signComponent(t, message.RoleSentry, txid, a.sentryPrivateKey)
	args := a.spendArgs(t, userSignature, proof, sentrySignature)
	if mutateArgs != nil {
		args = mutateArgs(txid, args)
	}

	lsigAccount := algocrypto.LogicSigAccount{Lsig: types.LogicSig{
		Logic: append([]byte(nil), a.bytecode...),
		Args:  args,
	}}
	_, signedTarget, err := algocrypto.SignLogicSigAccountTransaction(lsigAccount, targetTxn)
	if err != nil {
		t.Fatalf("failed to sign corridor target transaction: %v", err)
	}
	signedDummies, err := signing.SignDummyTransactions(dummies)
	if err != nil {
		t.Fatalf("failed to sign corridor dummy transactions: %v", err)
	}

	rawGroup := make([]byte, 0, len(signedTarget)+len(signedDummies)*len(signedDummies[0]))
	rawGroup = append(rawGroup, signedTarget...)
	for _, signedDummy := range signedDummies {
		rawGroup = append(rawGroup, signedDummy...)
	}
	return rawGroup, algocrypto.GetTxID(targetTxn)
}

func (a corridorExecutionAccount) argumentIndex(t *testing.T, source string) int {
	t.Helper()
	if a.metadata == nil {
		t.Fatal("Corridor bounded metadata is missing")
	}
	for _, slot := range a.metadata.ArgumentLayout {
		if slot.Source == source {
			return slot.Index
		}
	}
	t.Fatalf("Corridor argument layout has no %q source", source)
	return -1
}

func (a corridorExecutionAccount) adminRekeyArgs(t *testing.T, baseSignature []byte, txid types.Digest) [][]byte {
	t.Helper()
	if a.metadata == nil {
		t.Fatal("Corridor bounded metadata is missing")
	}
	binding, err := hex.DecodeString(a.metadata.ProgramBindingHex)
	if err != nil {
		t.Fatalf("decode Corridor program binding: %v", err)
	}
	var bindingDigest [32]byte
	if len(binding) != len(bindingDigest) {
		t.Fatalf("Corridor program binding length = %d, want %d", len(binding), len(bindingDigest))
	}
	copy(bindingDigest[:], binding)
	adminMessage, err := composeddsa.BoundedAdminMessage(composeddsa.AdminOperationRekey, bindingDigest, txid[:])
	if err != nil {
		t.Fatalf("build Corridor admin message: %v", err)
	}
	adminSignature, err := signerops.New(nil).Sign(a.adminPrivateKey, adminMessage[:])
	if err != nil {
		t.Fatalf("sign Corridor admin message: %v", err)
	}
	args := make([][]byte, len(a.metadata.ArgumentLayout))
	for _, slot := range a.metadata.ArgumentLayout {
		switch slot.Source {
		case boundedmeta.ArgSourceBaseSignature:
			args[slot.Index] = append([]byte(nil), baseSignature...)
		case boundedmeta.ArgSourceAdmin:
			args[slot.Index] = append([]byte(nil), adminSignature...)
		default:
			args[slot.Index] = []byte{}
		}
	}
	return args
}

func (a corridorExecutionAccount) spendArgs(t *testing.T, baseSignature, proof, sentrySignature []byte) [][]byte {
	t.Helper()
	if a.metadata == nil {
		t.Fatal("Corridor bounded metadata is missing")
	}
	args := make([][]byte, len(a.metadata.ArgumentLayout))
	baseIndex, derivedIndex := 0, 0
	baseValues := [][]byte{baseSignature}
	derivedValues := [][]byte{proof}
	for _, slot := range a.metadata.ArgumentLayout {
		var value []byte
		switch slot.Source {
		case boundedmeta.ArgSourceBaseSignature:
			if baseIndex >= len(baseValues) {
				t.Fatalf("Corridor base slot %q has no test value", slot.Name)
			}
			value = baseValues[baseIndex]
			baseIndex++
		case boundedmeta.ArgSourceDerived:
			if derivedIndex >= len(derivedValues) {
				t.Fatalf("Corridor derived slot %q has no test value", slot.Name)
			}
			value = derivedValues[derivedIndex]
			derivedIndex++
		case boundedmeta.ArgSourceSentry:
			value = sentrySignature
		case boundedmeta.ArgSourceAdmin:
			value = nil
		default:
			t.Fatalf("Corridor test does not support argument source %q", slot.Source)
		}
		if value == nil {
			value = []byte{}
		}
		args[slot.Index] = append([]byte(nil), value...)
	}
	if baseIndex != len(baseValues) || derivedIndex != len(derivedValues) {
		t.Fatalf("Corridor argument layout consumed base/derived values %d/%d and %d/%d",
			baseIndex, len(baseValues), derivedIndex, len(derivedValues))
	}
	for len(args) > 0 && len(args[len(args)-1]) == 0 {
		args = args[:len(args)-1]
	}
	return args
}

func (a corridorExecutionAccount) signComponent(t *testing.T, role message.Role, txid types.Digest, privateKey []byte) []byte {
	t.Helper()
	msg := message.ComponentMessage(role, txid)
	signature, err := signerops.New(nil).Sign(privateKey, msg[:])
	if err != nil {
		t.Fatalf("failed to sign corridor %s component message: %v", role, err)
	}
	return signature
}

func corridorPaymentTxn(t *testing.T, sp types.SuggestedParams, from, to string, amount uint64, note string) types.Transaction {
	t.Helper()
	txn, err := transaction.MakePaymentTxn(from, to, amount, []byte(note), "", sp)
	if err != nil {
		t.Fatalf("failed to build corridor payment transaction: %v", err)
	}
	if txn.Fee == 0 {
		txn.Fee = types.MicroAlgos(sp.MinFee)
	}
	if txn.Fee == 0 {
		txn.Fee = 1_000
	}
	return txn
}

func corridorAssetTransferTxn(t *testing.T, sp types.SuggestedParams, from, to string, amount, assetID uint64, note string) types.Transaction {
	t.Helper()
	txn, err := transaction.MakeAssetTransferTxn(from, to, amount, []byte(note), sp, "", assetID)
	if err != nil {
		t.Fatalf("failed to build corridor asset transfer transaction: %v", err)
	}
	if txn.Fee == 0 {
		txn.Fee = types.MicroAlgos(sp.MinFee)
	}
	if txn.Fee == 0 {
		txn.Fee = 1_000
	}
	return txn
}

func createCorridorTestAsset(t *testing.T, testnet *harness.TestnetConfig, funder *harness.FundTestAccount) uint64 {
	t.Helper()
	txn, err := transaction.MakeAssetCreateTxn(
		funder.GetAddress(),
		[]byte("corridor-asset-create"),
		mustSuggestedParams(t, testnet),
		10,
		0,
		false,
		"",
		"",
		"",
		"",
		"CORR",
		"Corridor Test Asset",
		"",
		"",
	)
	if err != nil {
		t.Fatalf("failed to build corridor test asset creation transaction: %v", err)
	}
	txid := submitEd25519TxnExpectSuccess(t, testnet, funder.GetPrivateKey(), txn)
	info, _, err := testnet.Client.PendingTransactionInformation(txid).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to read corridor test asset creation transaction %s: %v", txid, err)
	}
	if info.AssetIndex == 0 {
		t.Fatalf("corridor test asset creation transaction %s did not return an asset index", txid)
	}
	return info.AssetIndex
}

func sendAssetFromFunder(t *testing.T, testnet *harness.TestnetConfig, funder *harness.FundTestAccount, to string, assetID, amount uint64) {
	t.Helper()
	txn := corridorAssetTransferTxn(t, mustSuggestedParams(t, testnet), funder.GetAddress(), to, amount, assetID, "corridor-asset-fund")
	submitEd25519TxnExpectSuccess(t, testnet, funder.GetPrivateKey(), txn)
}

func submitEd25519TxnExpectSuccess(t *testing.T, testnet *harness.TestnetConfig, privateKey stded25519.PrivateKey, txn types.Transaction) string {
	t.Helper()
	txid, signedBytes, err := algocrypto.SignTransaction(privateKey, txn)
	if err != nil {
		t.Fatalf("failed to sign corridor setup transaction: %v", err)
	}
	if _, err := testnet.Client.SendRawTransaction(signedBytes).Do(context.Background()); err != nil {
		t.Fatalf("corridor setup transaction %s failed to submit: %v", txid, err)
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("corridor setup transaction %s failed to confirm: %v", txid, err)
	}
	return txid
}

func submitCorridorGroupExpectSuccess(t *testing.T, testnet *harness.TestnetConfig, rawGroup []byte, txid string) {
	t.Helper()
	if _, err := testnet.Client.SendRawTransaction(rawGroup).Do(context.Background()); err != nil {
		t.Fatalf("corridor group submission failed: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("corridor transaction %s failed to confirm: %v", txid, err)
	}
}

func submitCorridorGroupExpectFailure(t *testing.T, testnet *harness.TestnetConfig, rawGroup []byte) {
	t.Helper()
	_, err := testnet.Client.SendRawTransaction(rawGroup).Do(context.Background())
	if err == nil {
		t.Fatal("corridor group unexpectedly submitted successfully")
	}
	lower := strings.ToLower(err.Error())
	if !strings.Contains(lower, "rejected by logic") && !strings.Contains(lower, "logic eval") {
		t.Fatalf("corridor group failed for a non-LogicSig reason: %v", err)
	}
}

func bestEffortSubmitCorridorCase(
	t *testing.T,
	testnet *harness.TestnetConfig,
	account corridorExecutionAccount,
	buildTxn func(types.SuggestedParams) types.Transaction,
	proof []byte,
) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Logf("cleanup: corridor LogicSig close skipped after panic: %v", r)
		}
	}()
	txn := buildTxn(mustSuggestedParams(t, testnet))
	rawGroup, txid := account.signGroup(t, txn, proof, nil)
	if _, err := testnet.Client.SendRawTransaction(rawGroup).Do(context.Background()); err != nil {
		t.Logf("cleanup: corridor LogicSig close submit failed: %v", err)
		return
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Logf("cleanup: corridor LogicSig close confirmation failed: %v", err)
	}
}

func bestEffortCorridorAdminRekey(
	t *testing.T,
	testnet *harness.TestnetConfig,
	account corridorExecutionAccount,
	target types.Address,
) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Logf("cleanup: Corridor contract-admin rekey skipped after panic: %v", r)
		}
	}()
	txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), account.address, account.address, 0, "corridor-cleanup-admin-rekey")
	txn.RekeyTo = target
	rawGroup, txid := account.signGroup(t, txn, nil, func(txid types.Digest, args [][]byte) [][]byte {
		return account.adminRekeyArgs(t, args[0], txid)
	})
	if _, err := testnet.Client.SendRawTransaction(rawGroup).Do(context.Background()); err != nil {
		t.Logf("cleanup: Corridor contract-admin rekey submit failed: %v", err)
		return
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Logf("cleanup: Corridor contract-admin rekey confirmation failed: %v", err)
	}
}

func bestEffortCloseRekeyedAccount(t *testing.T, testnet *harness.TestnetConfig, account, destination string, authPrivateKey stded25519.PrivateKey) {
	t.Helper()
	sp := mustSuggestedParams(t, testnet)
	txn := corridorPaymentTxn(t, sp, account, destination, 0, "corridor-cleanup-rekeyed")
	mustSetAddress(t, &txn.CloseRemainderTo, destination)
	_, signedBytes, err := algocrypto.SignTransaction(authPrivateKey, txn)
	if err != nil {
		t.Logf("cleanup: failed to sign rekeyed corridor close: %v", err)
		return
	}
	txid, err := testnet.Client.SendRawTransaction(signedBytes).Do(context.Background())
	if err != nil {
		t.Logf("cleanup: rekeyed corridor close submit failed: %v", err)
		return
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Logf("cleanup: rekeyed corridor close confirmation failed: %v", err)
	}
}

func randomFalconSeed(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, 64)
	if _, err := cryptorand.Read(seed); err != nil {
		t.Fatalf("failed to read Falcon seed randomness: %v", err)
	}
	return seed
}

func mustSuggestedParams(t *testing.T, testnet *harness.TestnetConfig) types.SuggestedParams {
	t.Helper()
	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}
	return sp
}

func mustSetAddress(t *testing.T, dst *types.Address, address string) {
	t.Helper()
	decoded, err := types.DecodeAddress(address)
	if err != nil {
		t.Fatalf("failed to decode address %s: %v", address, err)
	}
	*dst = decoded
}

func mustDecodeAddress(t *testing.T, address string) types.Address {
	t.Helper()
	addr, err := types.DecodeAddress(address)
	if err != nil {
		t.Fatalf("failed to decode address %s: %v", address, err)
	}
	return addr
}
