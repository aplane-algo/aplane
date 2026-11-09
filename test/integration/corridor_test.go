// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	stded25519 "crypto/ed25519"
	cryptorand "crypto/rand"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/merkleallowlist"
	"github.com/aplane-algo/aplane/internal/rekeylist"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/boundedaccount"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/test/integration/harness"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const corridorExecutionGroupSize = 10

// A Corridor account refuses rekeys, so its spend is the only path to measure.
func TestCorridorDeclaredOpcodeCeilings(t *testing.T) {
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to integration algod: %v", err)
	}
	compileAlgod := matrixCompileAlgod(t, network)
	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("load funding account: %v", err)
	}
	funderAddress := mustDecodeAddress(t, funder.GetAddress())
	provider := newGeneralProvider(t, network)
	account := newCorridorExecutionAccount(t, provider, funderAddress)
	proof := account.proofFor(t, funderAddress)
	if err := funder.FundMicroAlgosAndWait(account.address, 500_000); err != nil {
		t.Fatalf("fund Corridor opcode-validation account: %v", err)
	}
	// It can never close, so its minimum balance stays behind: 0.1 ALGO per run on
	// a public network.
	t.Cleanup(func() { sweepRefusedAccount(t, network, account, funder.GetAddress(), proof) })

	sp := mustSuggestedParams(t, network)
	spendTxn := corridorPaymentTxn(t, sp, account.address, funder.GetAddress(), 0, "corridor-opcode-spend")
	spendGroup, _ := account.signedGroup(t, spendTxn, proof, nil)

	report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), compileAlgod, harness.OpcodeCeilingValidation{
		Name:          "Corridor " + corridorShape().Descriptor(),
		FinalProgram:  account.bytecode,
		Profile:       provider.LogicSigOpcodeProfile(),
		Bounded:       true,
		RequiredPaths: []lsigresource.AuthorizationPath{lsigresource.PathSpend},
		Vectors: []harness.OpcodeCeilingVector{
			{Name: "maximum-spend", Path: lsigresource.PathSpend, SignedTxns: spendGroup, LSigIndex: 0},
		},
	})
	if err != nil {
		t.Fatalf("validate Corridor opcode ceilings: %v", err)
	}
	for path, observed := range report.Paths {
		t.Logf("Corridor path %d opcode cost: %d observed / %d declared", path, observed.MaximumObserved, observed.DeclaredCeiling)
	}
}

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
	provider := newGeneralProvider(t, testnet)
	transferAccount := newCorridorExecutionAccount(t, provider, allowed, funderAddress)
	funderProof := transferAccount.proofFor(t, funderAddress)
	if err := funder.FundMicroAlgosAndWait(transferAccount.address, 500_000); err != nil {
		t.Fatalf("failed to fund corridor transfer account %s: %v", transferAccount.address, err)
	}
	if err := funder.FundMicroAlgosAndWait(allowed.String(), 300_000); err != nil {
		t.Fatalf("failed to fund corridor allowed recipient %s: %v", allowed.String(), err)
	}

	assetID := corridorTestAssetID(t, testnet, funder)
	submitEd25519TxnExpectSuccess(t, testnet, allowedAccount.PrivateKey,
		corridorAssetTransferTxn(t, mustSuggestedParams(t, testnet), allowed.String(), allowed.String(), 0, assetID, "corridor-allowed-asset-optin"))
	bestEffortSubmitCorridorCase(t, testnet, transferAccount, func(sp types.SuggestedParams) types.Transaction {
		return corridorAssetTransferTxn(t, sp, transferAccount.address, transferAccount.address, 0, assetID, "corridor-self-asset-optin")
	}, nil)
	// Cleanups run last first, so every Corridor account pays out before the
	// allowed recipient closes to the funder.
	t.Cleanup(func() {
		bestEffortCloseBoundedAsset(t, testnet, allowed.String(), funder.GetAddress(), assetID, allowedAccount.PrivateKey)
		bestEffortCloseRekeyedAccount(t, testnet, allowed.String(), funder.GetAddress(), allowedAccount.PrivateKey)
	})
	// A Corridor account can neither close nor be rekeyed. What it holds goes back
	// to the funder, a listed recipient, and its minimum balance stays.
	t.Cleanup(func() {
		returnCorridorAsset(t, testnet, transferAccount, funder.GetAddress(), funderProof, assetID)
		sweepRefusedAccount(t, testnet, transferAccount, funder.GetAddress(), funderProof)
	})
	sendAssetFromFunder(t, testnet, funder, transferAccount.address, assetID, 2)

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

	_, wrongCosignerPrivateKey, err := signerops.New(nil).GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("failed to generate wrong cosigner keypair: %v", err)
	}
	cosignerSlot := transferAccount.argumentIndex(t, boundedmeta.ArgSourceCosigner)
	t.Run("empty cosigner slot fails", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), transferAccount.address, transferAccount.address, 0, "corridor-deny-empty-cosigner")
		rawGroup, _ := transferAccount.signGroup(t, txn, nil, func(_ types.Digest, args [][]byte) [][]byte {
			args[cosignerSlot] = []byte{}
			return args
		})
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})
	t.Run("signature from wrong cosigner key fails", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), transferAccount.address, transferAccount.address, 0, "corridor-deny-wrong-cosigner")
		rawGroup, _ := transferAccount.signGroup(t, txn, nil, func(txid types.Digest, args [][]byte) [][]byte {
			args[cosignerSlot] = transferAccount.signComponent(t, message.RoleCosigner, txid, wrongCosignerPrivateKey)
			return args
		})
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})
	t.Run("user-role cosigner signature fails", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), transferAccount.address, transferAccount.address, 0, "corridor-deny-wrong-role")
		rawGroup, _ := transferAccount.signGroup(t, txn, nil, func(txid types.Digest, args [][]byte) [][]byte {
			args[cosignerSlot] = transferAccount.signComponent(t, message.RoleUser, txid, transferAccount.cosignerPrivateKey)
			return args
		})
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})
	t.Run("cosigner signature over wrong transaction ID fails", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), transferAccount.address, transferAccount.address, 0, "corridor-deny-wrong-txid")
		rawGroup, _ := transferAccount.signGroup(t, txn, nil, func(txid types.Digest, args [][]byte) [][]byte {
			txid[0] ^= 0xff
			args[cosignerSlot] = transferAccount.signComponent(t, message.RoleCosigner, txid, transferAccount.cosignerPrivateKey)
			return args
		})
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
	})

	rekeyTarget := algocrypto.GenerateAccount()
	rekeyAccount := newCorridorExecutionAccount(t, provider, allowed)
	allowedProof := rekeyAccount.proofFor(t, allowed)
	if err := funder.FundMicroAlgosAndWait(rekeyAccount.address, 200_000); err != nil {
		t.Fatalf("failed to fund corridor rekey account %s: %v", rekeyAccount.address, err)
	}
	t.Cleanup(func() { sweepRefusedAccount(t, testnet, rekeyAccount, allowed.String(), allowedProof) })

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

	// No rekey path exists, so a well-formed rekey with both signatures fails too.
	t.Run("pure rekey is refused", func(t *testing.T) {
		txn := corridorPaymentTxn(t, mustSuggestedParams(t, testnet), rekeyAccount.address, rekeyAccount.address, 0, "corridor-allow-rekey")
		txn.RekeyTo = rekeyTarget.Address
		rawGroup, _ := rekeyAccount.signGroup(t, txn, nil, nil)
		submitCorridorGroupExpectFailure(t, testnet, rawGroup)
		accountInfo, err := testnet.Client.AccountInformation(rekeyAccount.address).Do(context.Background())
		if err != nil {
			t.Fatalf("read Corridor account: %v", err)
		}
		if accountInfo.AuthAddr != "" {
			t.Fatalf("Corridor account was rekeyed to %s", accountInfo.AuthAddr)
		}
	})
}

type corridorExecutionAccount struct {
	address            string
	bytecode           []byte
	recipientsParam    string
	userPrivateKey     []byte
	cosignerPrivateKey []byte
	metadata           *boundedmeta.Metadata
	// rekeyList is an only-these account's rekey-to list, rebuilt from its
	// spending key as the signer does.
	rekeyList *rekeylist.List
}

// corridorShape is the general bounded type's Corridor preset
// (internal/boundary/preset.go): every transfer kind, a Merkle list, a cosigner on
// every spend, and no rekey path.
func corridorShape() boundedaccount.Shape {
	return boundedaccount.Shape{
		Spend:    []txeffects.SpendEffect{txeffects.SpendEffectPay, txeffects.SpendEffectAxfer, txeffects.SpendEffectAssetOptIn},
		Encoding: boundedaccount.EncodingMerkle,
		Rekey:    boundedaccount.RekeyRefused,
		Cosigner: true,
	}
}

func newCorridorExecutionAccount(t *testing.T, provider *boundedaccount.Provider, recipients ...types.Address) corridorExecutionAccount {
	t.Helper()
	if len(recipients) == 0 {
		t.Fatal("corridor execution account requires at least one recipient")
	}
	recipientStrings := make([]string, len(recipients))
	for i, recipient := range recipients {
		recipientStrings[i] = recipient.String()
	}
	account := newGeneralAccount(t, provider, corridorShape(), recipientStrings, 0, nil)
	if account.metadata.Layer3Policy != boundedmeta.Layer3PolicyMerkleAllowlist || account.metadata.Cosigner == nil || account.metadata.Rekey != boundedmeta.RekeyRefused {
		t.Fatalf("account is not a Corridor: layer3_policy=%q cosigner=%v rekey=%q",
			account.metadata.Layer3Policy, account.metadata.Cosigner != nil, account.metadata.Rekey)
	}
	return account
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
	signed, txid := a.signedGroup(t, targetTxn, proof, mutateArgs)
	rawGroup := make([]byte, 0)
	for _, stxn := range signed {
		rawGroup = append(rawGroup, msgpack.Encode(stxn)...)
	}
	return rawGroup, txid
}

func (a corridorExecutionAccount) signedGroup(t *testing.T, targetTxn types.Transaction, proof []byte, mutateArgs func(types.Digest, [][]byte) [][]byte) ([]types.SignedTxn, string) {
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
	cosignerSignature := a.signComponent(t, message.RoleCosigner, txid, a.cosignerPrivateKey)
	args := a.spendArgs(t, userSignature, proof, a.listProof(targetTxn.RekeyTo), cosignerSignature)
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

	group := make([]types.SignedTxn, 0, 1+len(signedDummies))
	var target types.SignedTxn
	if err := msgpack.Decode(signedTarget, &target); err != nil {
		t.Fatalf("decode signed corridor target: %v", err)
	}
	group = append(group, target)
	for _, signedDummy := range signedDummies {
		var dummy types.SignedTxn
		if err := msgpack.Decode(signedDummy, &dummy); err != nil {
			t.Fatalf("decode signed corridor dummy: %v", err)
		}
		group = append(group, dummy)
	}
	return group, algocrypto.GetTxID(targetTxn)
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

// listProof is a rekey target's list proof, or nil when the target is not listed.
func (a corridorExecutionAccount) listProof(target types.Address) []byte {
	if a.rekeyList == nil || target.IsZero() {
		return nil
	}
	proof, listed := a.rekeyList.Proof(target)
	if !listed {
		return nil
	}
	return proof
}

// listProofIndex is the argument slot carrying a listed rekey's proof.
func (a corridorExecutionAccount) listProofIndex(t *testing.T) int {
	t.Helper()
	return a.derivedIndex(t, boundedmeta.DerivedArgRekeyListProof)
}

func (a corridorExecutionAccount) derivedIndex(t *testing.T, kind string) int {
	t.Helper()
	if a.metadata == nil {
		t.Fatal("bounded metadata is missing")
	}
	for _, arg := range a.metadata.DerivedArgs {
		if arg.Kind != kind {
			continue
		}
		for _, slot := range a.metadata.ArgumentLayout {
			if slot.Source == boundedmeta.ArgSourceDerived && slot.Name == arg.Name {
				return slot.Index
			}
		}
	}
	t.Fatalf("argument layout has no %q slot", kind)
	return -1
}

func (a corridorExecutionAccount) spendArgs(t *testing.T, baseSignature, proof, listProof, cosignerSignature []byte) [][]byte {
	t.Helper()
	if a.metadata == nil {
		t.Fatal("Corridor bounded metadata is missing")
	}
	derivedKinds := make(map[string]string, len(a.metadata.DerivedArgs))
	for _, arg := range a.metadata.DerivedArgs {
		derivedKinds[arg.Name] = arg.Kind
	}
	args := make([][]byte, len(a.metadata.ArgumentLayout))
	baseIndex := 0
	baseValues := [][]byte{baseSignature}
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
			switch derivedKinds[slot.Name] {
			case boundedmeta.DerivedArgMerkleProof:
				value = proof
			case boundedmeta.DerivedArgRekeyListProof:
				value = listProof
			default:
				t.Fatalf("Corridor derived slot %q has no test value", slot.Name)
			}
		case boundedmeta.ArgSourceCosigner:
			value = cosignerSignature
		default:
			t.Fatalf("Corridor test does not support argument source %q", slot.Source)
		}
		if value == nil {
			value = []byte{}
		}
		args[slot.Index] = append([]byte(nil), value...)
	}
	if baseIndex != len(baseValues) {
		t.Fatalf("Corridor argument layout consumed %d/%d base values", baseIndex, len(baseValues))
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

const (
	corridorTestAssetName  = "Corridor Test Asset"
	corridorTestAssetUnit  = "CORR"
	corridorTestAssetTotal = uint64(10)
)

var corridorTestAssetMu sync.Mutex

// corridorTestAssetID reuses a clean asset already created by the funding
// account. If no compatible asset exists, it creates one fixture on the
// selected network. An existing but depleted fixture is never replaced: that
// state signals failed cleanup and must be repaired rather than accumulating
// another durable asset.
func corridorTestAssetID(t *testing.T, testnet *harness.TestnetConfig, funder *harness.FundTestAccount) uint64 {
	t.Helper()
	corridorTestAssetMu.Lock()
	defer corridorTestAssetMu.Unlock()

	account, err := testnet.Client.AccountInformation(funder.GetAddress()).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to inspect funding account for reusable corridor test asset: %v", err)
	}
	assetID, needsCreation, err := resolveCorridorTestAsset(testnet.Network, account)
	if err != nil {
		t.Fatal(err)
	}
	if !needsCreation {
		t.Logf("reusing corridor test asset %d", assetID)
		return assetID
	}

	txn, err := transaction.MakeAssetCreateTxn(
		funder.GetAddress(),
		[]byte("corridor-asset-create"),
		mustSuggestedParams(t, testnet),
		corridorTestAssetTotal,
		0,
		false,
		"",
		"",
		"",
		"",
		corridorTestAssetUnit,
		corridorTestAssetName,
		"",
		"",
	)
	if err != nil {
		t.Fatalf("failed to build corridor test asset creation transaction: %v", err)
	}
	txid := submitFundingTxnExpectSuccess(t, testnet, funder, txn)
	info, _, err := testnet.Client.PendingTransactionInformation(txid).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to read corridor test asset creation transaction %s: %v", txid, err)
	}
	if info.AssetIndex == 0 {
		t.Fatalf("corridor test asset creation transaction %s did not return an asset index", txid)
	}
	return info.AssetIndex
}

func resolveCorridorTestAsset(network string, account models.Account) (assetID uint64, needsCreation bool, err error) {
	if assetID, ok := selectReusableCorridorTestAsset(account); ok {
		return assetID, false, nil
	}
	dirty := dirtyCorridorTestAssets(account)
	if len(dirty) > 0 {
		return 0, false, fmt.Errorf(
			"funding account has existing but depleted %q asset on %s (%s); refusing to create a replacement",
			corridorTestAssetName, network, strings.Join(dirty, ", "),
		)
	}
	return 0, true, nil
}

func selectReusableCorridorTestAsset(account models.Account) (uint64, bool) {
	holdings := make(map[uint64]uint64, len(account.Assets))
	for _, holding := range account.Assets {
		holdings[holding.AssetId] = holding.Amount
	}

	var selected uint64
	for _, asset := range account.CreatedAssets {
		if !isCorridorTestAsset(asset) || holdings[asset.Index] != asset.Params.Total {
			continue
		}
		if selected == 0 || asset.Index < selected {
			selected = asset.Index
		}
	}
	return selected, selected != 0
}

func dirtyCorridorTestAssets(account models.Account) []string {
	holdings := make(map[uint64]uint64, len(account.Assets))
	for _, holding := range account.Assets {
		holdings[holding.AssetId] = holding.Amount
	}
	dirty := make([]string, 0)
	for _, asset := range account.CreatedAssets {
		if !isCorridorTestAsset(asset) || holdings[asset.Index] == asset.Params.Total {
			continue
		}
		dirty = append(dirty, fmt.Sprintf("%d holds %d/%d", asset.Index, holdings[asset.Index], asset.Params.Total))
	}
	sort.Strings(dirty)
	return dirty
}

func isCorridorTestAsset(asset models.Asset) bool {
	return !asset.Deleted &&
		asset.Params.Name == corridorTestAssetName &&
		asset.Params.UnitName == corridorTestAssetUnit &&
		asset.Params.Total == corridorTestAssetTotal &&
		asset.Params.Decimals == 0
}

func TestSelectReusableCorridorTestAsset(t *testing.T) {
	matching := func(id, held uint64) (models.Asset, models.AssetHolding) {
		return models.Asset{
			Index: id,
			Params: models.AssetParams{
				Name: corridorTestAssetName, UnitName: corridorTestAssetUnit,
				Total: corridorTestAssetTotal,
			},
		}, models.AssetHolding{AssetId: id, Amount: held}
	}

	older, olderHolding := matching(41, corridorTestAssetTotal)
	newer, newerHolding := matching(42, corridorTestAssetTotal)
	partial, partialHolding := matching(40, corridorTestAssetTotal-1)
	wrongName, wrongNameHolding := matching(39, corridorTestAssetTotal)
	wrongName.Params.Name = "Unrelated Asset"

	account := models.Account{
		CreatedAssets: []models.Asset{newer, partial, wrongName, older},
		Assets:        []models.AssetHolding{newerHolding, partialHolding, wrongNameHolding, olderHolding},
	}
	if got, ok := selectReusableCorridorTestAsset(account); !ok || got != older.Index {
		t.Fatalf("selectReusableCorridorTestAsset() = (%d, %v), want (%d, true)", got, ok, older.Index)
	}

	account.Assets = []models.AssetHolding{partialHolding, wrongNameHolding}
	if got, ok := selectReusableCorridorTestAsset(account); ok || got != 0 {
		t.Fatalf("selectReusableCorridorTestAsset(no clean fixture) = (%d, %v), want (0, false)", got, ok)
	}
}

func TestResolveCorridorTestAssetCreatesOnlyWhenAbsent(t *testing.T) {
	matching := models.Asset{
		Index: 52,
		Params: models.AssetParams{
			Name: corridorTestAssetName, UnitName: corridorTestAssetUnit,
			Total: corridorTestAssetTotal,
		},
	}
	account := models.Account{
		CreatedAssets: []models.Asset{matching},
		Assets:        []models.AssetHolding{{AssetId: matching.Index, Amount: corridorTestAssetTotal}},
	}

	for _, network := range []string{
		harness.IntegrationNetworkTestnet,
		harness.IntegrationNetworkLocalnet,
	} {
		assetID, needsCreation, err := resolveCorridorTestAsset(network, account)
		if err != nil || needsCreation || assetID != matching.Index {
			t.Fatalf("resolveCorridorTestAsset(%q, reusable) = (%d, %v, %v), want (%d, false, nil)", network, assetID, needsCreation, err, matching.Index)
		}

		assetID, needsCreation, err = resolveCorridorTestAsset(network, models.Account{})
		if err != nil || !needsCreation || assetID != 0 {
			t.Fatalf("resolveCorridorTestAsset(%q, empty) = (%d, %v, %v), want creation", network, assetID, needsCreation, err)
		}
	}

	dirty := account
	dirty.Assets = []models.AssetHolding{{AssetId: matching.Index, Amount: corridorTestAssetTotal - 1}}
	assetID, needsCreation, err := resolveCorridorTestAsset(harness.IntegrationNetworkTestnet, dirty)
	if err == nil || needsCreation || assetID != 0 || !strings.Contains(err.Error(), "refusing to create a replacement") {
		t.Fatalf("resolveCorridorTestAsset(dirty) = (%d, %v, %v), want refusal without creation", assetID, needsCreation, err)
	}
}

func sendAssetFromFunder(t *testing.T, testnet *harness.TestnetConfig, funder *harness.FundTestAccount, to string, assetID, amount uint64) {
	t.Helper()
	txn := corridorAssetTransferTxn(t, mustSuggestedParams(t, testnet), funder.GetAddress(), to, amount, assetID, "corridor-asset-fund")
	submitFundingTxnExpectSuccess(t, testnet, funder, txn)
}

func submitFundingTxnExpectSuccess(t *testing.T, testnet *harness.TestnetConfig, funder *harness.FundTestAccount, txn types.Transaction) string {
	t.Helper()
	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to read suggested params for corridor setup transaction: %v", err)
	}
	txid, signedBytes, err := funder.PrepareAndSignTransaction(txn, sp.MinFee)
	if err != nil {
		t.Fatalf("failed to sign corridor setup transaction: %v", err)
	}
	if _, err := testnet.Client.SendRawTransaction(signedBytes).Do(context.Background()); err != nil {
		t.Fatalf("corridor setup transaction %s failed to submit: %v", txid, err)
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("corridor transaction %s failed to confirm: %v", txid, err)
	}
	return txid
}

func submitEd25519TxnExpectSuccess(t *testing.T, testnet *harness.TestnetConfig, privateKey stded25519.PrivateKey, txn types.Transaction) string {
	t.Helper()
	txid, signedBytes, err := signing.SignTransactionWithKey(privateKey, txn)
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

// returnCorridorAsset transfers what a Corridor account holds of the shared test
// asset to a listed recipient. The account can't close out the asset, but the
// fixture's supply must end back with the funder.
func returnCorridorAsset(t *testing.T, testnet *harness.TestnetConfig, account corridorExecutionAccount, to string, proof []byte, assetID uint64) {
	t.Helper()
	info, err := testnet.Client.AccountInformation(account.address).Do(context.Background())
	if err != nil {
		t.Fatalf("read %s: %v", account.address, err)
	}
	var held uint64
	for _, holding := range info.Assets {
		if holding.AssetId == assetID {
			held = holding.Amount
		}
	}
	if held == 0 {
		return
	}
	txn := corridorAssetTransferTxn(t, mustSuggestedParams(t, testnet), account.address, to, held, assetID, "corridor-cleanup-asset")
	rawGroup, txid := account.signGroup(t, txn, proof, nil)
	submitCorridorGroupExpectSuccess(t, testnet, rawGroup, txid)
}

func bestEffortCloseRekeyedAccount(t *testing.T, testnet *harness.TestnetConfig, account, destination string, authPrivateKey stded25519.PrivateKey) {
	t.Helper()
	sp := mustSuggestedParams(t, testnet)
	txn := corridorPaymentTxn(t, sp, account, destination, 0, "corridor-cleanup-rekeyed")
	mustSetAddress(t, &txn.CloseRemainderTo, destination)
	_, signedBytes, err := signing.SignTransactionWithKey(authPrivateKey, txn)
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
