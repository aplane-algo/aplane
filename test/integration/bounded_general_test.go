// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/rekeylist"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/lsig/plainhost"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// boundsRequest is the plain host request for a bounded2 shape.
func boundsRequest(shape plainhost.Shape, recipients []string, unlockRound uint64, cosignerKey []byte, rekeyTo []string) map[string]string {
	spend := make([]string, len(shape.Spend))
	for i, effect := range shape.Spend {
		spend[i] = string(effect)
	}
	params := map[string]string{
		plainhost.ParameterSpendEffects:   strings.Join(spend, ","),
		plainhost.ParameterRekeyAuthority: shape.Rekey,
	}
	if shape.Encoding != "" {
		params[plainhost.ParameterListEncoding] = shape.Encoding
		params[plainhost.ParameterRecipients] = strings.Join(recipients, ",")
	}
	if shape.Timelock {
		params[plainhost.ParameterUnlockRound] = strconv.FormatUint(unlockRound, 10)
	}
	if shape.AnyRecipient {
		params[plainhost.ParameterRecipientScope] = plainhost.RecipientScopeAny
	}
	if shape.Cosigner {
		params[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(cosignerKey)
	}
	if shape.HasRekeyList() {
		params[plainhost.ParameterRekeyTo] = strings.Join(rekeyTo, ",")
	}
	return params
}

// newBoundsAccount generates a bounded2 account on the plain host's base as the
// signer does, with a Falcon-1024 or Ed25519 spending key to match and a
// Falcon-1024 cosigner. A shape with a rekey-to list (only these, plus cosigned)
// lists rekeyTo; key generation commits to the list's root.
func newBoundsAccount(t *testing.T, provider *plainhost.Provider, shape plainhost.Shape, recipients []string, unlockRound uint64, rekeyTo []string) corridorExecutionAccount {
	t.Helper()
	spendingPublic, spendingPrivate, edKey := newSpendingKey(t, provider.KeyType())
	cosignerPublic, cosignerPrivate, err := signerops.New(nil).GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate cosigner key: %v", err)
	}
	params := boundsRequest(shape, recipients, unlockRound, cosignerPublic, rekeyTo)
	instance, err := provider.ResolveInstance(params)
	if err != nil {
		t.Fatalf("resolve instance: %v", err)
	}
	values, err := provider.PrepareRekeyList(spendingPrivate, instance.Values)
	if err != nil {
		t.Fatalf("prepare rekey-to list: %v", err)
	}
	derived, err := provider.DeriveLsigWithSalt(context.Background(), spendingPublic, values)
	if err != nil {
		t.Fatalf("derive LogicSig: %v", err)
	}
	metadata, err := provider.BuildBoundedAuthorizationMetadata(spendingPublic, values, derived.Bytecode)
	if err != nil {
		t.Fatalf("build metadata: %v", err)
	}
	if metadata == nil || metadata.Contract != boundedmeta.Contract {
		t.Fatalf("%s metadata = %+v, want the bounded contract", shape.Descriptor(), metadata)
	}
	account := corridorExecutionAccount{
		address:            derived.Address.String(),
		bytecode:           derived.Bytecode,
		recipientsParam:    instance.Values[plainhost.ParameterRecipients],
		userPrivateKey:     spendingPrivate,
		edKey:              edKey,
		cosignerPrivateKey: cosignerPrivate,
		metadata:           metadata,
	}
	if shape.HasRekeyList() != (metadata.RekeyList != nil) {
		t.Fatalf("%s metadata rekey-to list = %+v", shape.Descriptor(), metadata.RekeyList)
	}
	if metadata.RekeyList != nil {
		list, err := composeddsa.RekeyListFor(spendingPrivate, values)
		if err != nil {
			t.Fatalf("rebuild rekey-to list: %v", err)
		}
		root := list.Root()
		if hex.EncodeToString(root[:]) != metadata.RekeyList.RootHex {
			t.Fatalf("rebuilt rekey-to root %x, metadata holds %s", root, metadata.RekeyList.RootHex)
		}
		account.rekeyList = list
	}
	return account
}

// withArg sets one LogicSig argument, restoring the empty slots that signing
// trims from the end.
func withArg(args [][]byte, index int, value []byte) [][]byte {
	for len(args) <= index {
		args = append(args, []byte{})
	}
	args[index] = append([]byte(nil), value...)
	return args
}

// handOver rekeys an account to target through the rekey path its shape offers.
func handOver(t *testing.T, network *harness.TestnetConfig, account corridorExecutionAccount, target types.Address, note string) {
	t.Helper()
	txn := corridorPaymentTxn(t, mustSuggestedParams(t, network), account.address, account.address, 0, note)
	txn.RekeyTo = target
	raw, txid := account.signGroup(t, txn, nil, nil)
	submitCorridorGroupExpectSuccess(t, network, raw, txid)
}

// drainBounded pays what a bounded account holds above its minimum balance to
// to, as a spend its program admits. A refused account can be neither rekeyed
// nor closed, so this is the only way its funds come back. It is best effort.
func drainBounded(t *testing.T, network *harness.TestnetConfig, account corridorExecutionAccount, to string, proof []byte) {
	t.Helper()
	info, err := network.Client.AccountInformation(account.address).Do(context.Background())
	if err != nil {
		t.Logf("cleanup: read %s: %v", account.address, err)
		return
	}
	txn := corridorPaymentTxn(t, mustSuggestedParams(t, network), account.address, to, 0, "bounds-drain")
	// signGroup puts the whole group's fee on this transaction.
	fee := uint64(corridorExecutionGroupSize) * uint64(txn.Fee)
	if info.Amount <= info.MinBalance+fee {
		return
	}
	txn.Amount = types.MicroAlgos(info.Amount - info.MinBalance - fee)
	raw, txid := account.signGroup(t, txn, proof, nil)
	if _, err := network.Client.SendRawTransaction(raw).Do(context.Background()); err != nil {
		t.Logf("cleanup: drain %s: %v", account.address, err)
		return
	}
	if _, err := network.WaitForConfirmation(txid, 10); err != nil {
		t.Logf("cleanup: drain %s did not confirm: %v", account.address, err)
	}
}

// Every Falcon-1024 shape runs its own program on the network, so each rejection
// here is the program's and each spend subset is exercised on its own, not only
// the largest family. Ed25519 offers the same grammar; a sample runs on it, every
// overlay arrangement over an inline list with every transfer kind, the cosigned
// ones included. Accounts go straight to algod: the signer would refuse much of
// this before the program ever saw it.
func TestBoundsShapeMatrixOnChainLocalnet(t *testing.T) {
	if harness.IntegrationNetwork() != harness.IntegrationNetworkLocalnet {
		t.Skip("bounded LogicSig execution requires localnet")
	}
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to localnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("load funding account: %v", err)
	}

	// The grammar is every combination: each policy takes each overlay
	// arrangement, so a refused rekey and a timelock with a spending-key or plus
	// cosigned rekey are shapes like any other, and run below.
	offered := make(map[string]map[plainhost.Arrangement]bool)
	for _, shape := range plainhost.Shapes() {
		if offered[shape.Policy()] == nil {
			offered[shape.Policy()] = make(map[plainhost.Arrangement]bool)
		}
		offered[shape.Policy()][plainhost.Arrangement{Rekey: shape.Rekey, Cosigner: shape.Cosigner}] = true
	}
	for policy, arrangements := range offered {
		for _, arrangement := range plainhost.Arrangements() {
			if !arrangements[arrangement] {
				t.Fatalf("policy %s does not offer rekey %s with cosigner %v", policy, arrangement.Rekey, arrangement.Cosigner)
			}
		}
	}

	type shapeCase struct {
		provider *plainhost.Provider
		shape    plainhost.Shape
	}
	var cases []shapeCase
	falconProvider := plainHostProvider(t, network, plainFalconKeyType)
	for _, shape := range plainhost.Shapes() {
		cases = append(cases, shapeCase{falconProvider, shape})
	}
	edProvider := plainHostProvider(t, network, plainEd25519KeyType)
	for _, shape := range plainhost.Shapes() {
		if shape.Encoding == plainhost.EncodingInline && !shape.Timelock && len(shape.Spend) == 3 {
			cases = append(cases, shapeCase{edProvider, shape})
		}
	}

	allowedAccount := algocrypto.GenerateAccount()
	allowed := allowedAccount.Address
	second := algocrypto.GenerateAccount().Address
	outside := algocrypto.GenerateAccount().Address
	// Every only-these account also lists this address, so a proof for the
	// wrong entry is always at hand.
	otherListed := algocrypto.GenerateAccount().Address
	if err := funder.FundMicroAlgosAndWait(allowed.String(), 300_000); err != nil {
		t.Fatalf("fund recipient: %v", err)
	}
	// A shape with no list has no outsiders, and pays this one like anyone else.
	if err := funder.FundMicroAlgosAndWait(outside.String(), 300_000); err != nil {
		t.Fatalf("fund outsider: %v", err)
	}
	assetID := corridorTestAssetID(t, network, funder)
	submitEd25519TxnExpectSuccess(t, network, allowedAccount.PrivateKey,
		corridorAssetTransferTxn(t, mustSuggestedParams(t, network), allowed.String(), allowed.String(), 0, assetID, "general-recipient-optin"))
	t.Cleanup(func() {
		bestEffortCloseBoundedAsset(t, network, allowed.String(), funder.GetAddress(), assetID, allowedAccount.PrivateKey)
		bestEffortCloseRekeyedAccount(t, network, allowed.String(), funder.GetAddress(), allowedAccount.PrivateKey)
	})

	for _, tc := range cases {
		shape := tc.shape
		t.Run(tc.provider.KeyType()+"/"+shape.Descriptor(), func(t *testing.T) {
			status, err := network.Client.Status().Do(context.Background())
			if err != nil {
				t.Fatalf("read status: %v", err)
			}
			if status.LastRound < 2 {
				t.Skip("localnet needs at least two rounds to backdate FirstValid")
			}
			// Already reached, so a backdated transaction is the only early one. Each
			// shape takes its own, because a transaction's life is limited in rounds.
			unlockRound := status.LastRound
			rekeyTarget := algocrypto.GenerateAccount()
			account := newBoundsAccount(t, tc.provider, shape, []string{allowed.String(), second.String()}, unlockRound,
				[]string{rekeyTarget.Address.String(), otherListed.String()})
			if err := funder.FundMicroAlgosAndWait(account.address, 400_000); err != nil {
				t.Fatalf("fund account: %v", err)
			}

			refused := shape.Rekey == plainhost.RekeyRefused
			mayPay := slices.Contains(shape.Spend, txeffects.SpendEffectPay)
			mayTransfer := slices.Contains(shape.Spend, txeffects.SpendEffectAxfer)
			mayOptIn := slices.Contains(shape.Spend, txeffects.SpendEffectAssetOptIn)
			merkle := shape.Encoding == plainhost.EncodingMerkle
			hasList := shape.Encoding != ""
			proof := func(to types.Address) []byte {
				if !merkle {
					return nil
				}
				return account.proofFor(t, to)
			}
			t.Cleanup(func() {
				if refused {
					// Nothing can rekey or close a refused account, so what it may
					// pay goes back by way of the listed recipient; the rest stays.
					if mayPay {
						drainBounded(t, network, account, allowed.String(), proof(allowed))
					}
					return
				}
				// The rekey below hands every other account to rekeyTarget, which
				// every list shape lists and a spending-key rekey reaches; if it never
				// ran, the cleanup hands it over first.
				if info, err := network.Client.AccountInformation(account.address).Do(context.Background()); err == nil && info.AuthAddr == "" {
					handOver(t, network, account, rekeyTarget.Address, "general-cleanup-handover")
				}
				bestEffortCloseBoundedAsset(t, network, account.address, funder.GetAddress(), assetID, rekeyTarget.PrivateKey)
				bestEffortCloseRekeyedAccount(t, network, account.address, funder.GetAddress(), rekeyTarget.PrivateKey)
			})
			expect := func(accepted bool, txn types.Transaction, proofBytes []byte, mutate func(types.Digest, [][]byte) [][]byte) {
				t.Helper()
				raw, txid := account.signGroup(t, txn, proofBytes, mutate)
				if accepted {
					submitCorridorGroupExpectSuccess(t, network, raw, txid)
				} else {
					submitCorridorGroupExpectFailure(t, network, raw)
				}
			}
			payment := func(to, note string) types.Transaction {
				return corridorPaymentTxn(t, mustSuggestedParams(t, network), account.address, to, 1_000, note)
			}
			transfer := func(to string, amount uint64, note string) types.Transaction {
				return corridorAssetTransferTxn(t, mustSuggestedParams(t, network), account.address, to, amount, assetID, note)
			}
			// early backdates a transaction to one round before the unlock.
			early := func(txn types.Transaction) types.Transaction {
				txn.FirstValid = types.Round(unlockRound - 1)
				txn.LastValid = types.Round(unlockRound + 900)
				return txn
			}
			// passesProgram is for what only the network refuses: the program must
			// admit it, or an admitted spend would be blocked for the wrong reason.
			passesProgram := func(txn types.Transaction, proofBytes []byte) {
				t.Helper()
				raw, _ := account.signGroup(t, txn, proofBytes, nil)
				_, err := network.Client.SendRawTransaction(raw).Do(context.Background())
				if err == nil {
					t.Fatal("the network accepted a transaction it should refuse")
				}
				if text := strings.ToLower(err.Error()); strings.Contains(text, "rejected by logic") || strings.Contains(text, "logic eval") {
					t.Fatalf("the program refused an admitted transaction: %v", err)
				}
			}

			t.Run("payment to a listed recipient", func(t *testing.T) { expect(mayPay, payment(allowed.String(), "a"), proof(allowed), nil) })
			t.Run("payment to itself", func(t *testing.T) { expect(mayPay, payment(account.address, "b"), nil, nil) })
			t.Run("payment to an outsider", func(t *testing.T) { expect(mayPay && !hasList, payment(outside.String(), "c"), proof(allowed), nil) })
			t.Run("transfer to an outsider", func(t *testing.T) {
				if mayTransfer && !hasList {
					// The outsider holds no asset, so only the network can refuse.
					passesProgram(transfer(outside.String(), 1, "d"), nil)
					return
				}
				expect(false, transfer(outside.String(), 0, "d"), proof(allowed), nil)
			})
			t.Run("close out to a listed recipient", func(t *testing.T) {
				txn := payment(allowed.String(), "e")
				txn.Amount = 0
				mustSetAddress(t, &txn.CloseRemainderTo, allowed.String())
				expect(false, txn, proof(allowed), nil)
			})
			t.Run("wrong spending signature", func(t *testing.T) {
				expect(false, payment(account.address, "f"), nil, func(_ types.Digest, args [][]byte) [][]byte {
					args[0] = append([]byte(nil), args[0]...)
					args[0][len(args[0])/2] ^= 0xff
					return args
				})
			})
			if merkle {
				t.Run("listed recipient without a proof", func(t *testing.T) { expect(false, payment(allowed.String(), "g"), nil, nil) })
			}
			if shape.Cosigner {
				t.Run("no cosigner signature", func(t *testing.T) {
					slot := account.argumentIndex(t, boundedmeta.ArgSourceCosigner)
					expect(false, payment(account.address, "h"), nil, func(_ types.Digest, args [][]byte) [][]byte {
						args[slot] = []byte{}
						return args
					})
				})
			}
			if shape.AnyRecipient {
				// With no list, the envelope is the whole rule. Every accepted case here
				// pays exactly the ceiling, ten transactions at 1,000, so one microAlgo
				// more per transaction must be refused.
				t.Run("payment above the fee ceiling", func(t *testing.T) {
					txn := payment(outside.String(), "n")
					txn.Fee = 1_001
					expect(false, txn, nil, nil)
				})
				t.Run("key registration", func(t *testing.T) {
					txn := payment(account.address, "o")
					txn.Type = types.KeyRegistrationTx
					txn.PaymentTxnFields = types.PaymentTxnFields{}
					expect(false, txn, nil, nil)
				})
			}
			if shape.Timelock {
				t.Run("payment one round early", func(t *testing.T) { expect(false, early(payment(allowed.String(), "g2")), proof(allowed), nil) })
				t.Run("payment to itself one round early", func(t *testing.T) { expect(false, early(payment(account.address, "g3")), nil, nil) })
			}
			t.Run("asset opt-in", func(t *testing.T) { expect(mayOptIn, transfer(account.address, 0, "i"), nil, nil) })
			switch {
			case !mayTransfer:
				t.Run("asset transfer", func(t *testing.T) { expect(false, transfer(allowed.String(), 0, "j"), proof(allowed), nil) })
			case mayOptIn:
				sendAssetFromFunder(t, network, funder, account.address, assetID, 1)
				t.Run("asset transfer", func(t *testing.T) { expect(true, transfer(allowed.String(), 1, "j"), proof(allowed), nil) })
				// The fixture's supply is small and must end back with the funder.
				submitEd25519TxnExpectSuccess(t, network, allowedAccount.PrivateKey,
					corridorAssetTransferTxn(t, mustSuggestedParams(t, network), allowed.String(), funder.GetAddress(), 1, assetID, "general-recipient-return"+account.address[:8]))
			default:
				// This account cannot opt in, so it can never hold the asset. The
				// program must still pass it: the network, not the program, refuses.
				t.Run("asset transfer", func(t *testing.T) { passesProgram(transfer(allowed.String(), 1, "j"), proof(allowed)) })
			}

			rekeyTo := func(target types.Address, note string) types.Transaction {
				txn := payment(account.address, note)
				txn.Amount = 0
				txn.RekeyTo = target
				return txn
			}
			rekey := func(note string) types.Transaction { return rekeyTo(rekeyTarget.Address, note) }
			// A listed target's rekey carries its proof, so the shape check alone refuses this.
			t.Run("rekey with a nonzero amount", func(t *testing.T) {
				txn := rekey("k")
				txn.Amount = 1
				expect(false, txn, nil, nil)
			})
			slot := -1
			if shape.HasRekeyList() {
				slot = account.listProofIndex(t)
			}
			listedProof := func(target types.Address) []byte {
				proof := account.listProof(target)
				if proof == nil {
					t.Fatalf("%s is not listed", target)
				}
				return proof
			}
			withProof := func(proof []byte) func(types.Digest, [][]byte) [][]byte {
				return func(_ types.Digest, args [][]byte) [][]byte { return withArg(args, slot, proof) }
			}
			// withoutCosigner empties the cosigner's slot, which a listed rekey never
			// reads and every other cosigned path requires.
			withoutCosigner := func(more func(types.Digest, [][]byte) [][]byte) func(types.Digest, [][]byte) [][]byte {
				return func(txid types.Digest, args [][]byte) [][]byte {
					if more != nil {
						args = more(txid, args)
					}
					if shape.Cosigner {
						args = withArg(args, account.argumentIndex(t, boundedmeta.ArgSourceCosigner), nil)
					}
					return args
				}
			}
			unlisted := algocrypto.GenerateAccount()
			if shape.HasRekeyList() {
				// A proof that fails commits the rekey to the listed branch, whatever
				// the cosigner signed.
				t.Run("rekey to an unlisted address with a listed proof", func(t *testing.T) {
					expect(false, rekeyTo(unlisted.Address, "l4"), nil, withProof(listedProof(rekeyTarget.Address)))
				})
				t.Run("rekey to itself", func(t *testing.T) {
					expect(false, rekeyTo(mustDecodeAddress(t, account.address), "l5"), nil, withProof(listedProof(rekeyTarget.Address)))
				})
				t.Run("listed rekey with the other entry's proof", func(t *testing.T) {
					expect(false, rekey("l6"), nil, withProof(listedProof(otherListed)))
				})
				t.Run("listed rekey with a short proof", func(t *testing.T) {
					expect(false, rekey("l8"), nil, withProof(listedProof(rekeyTarget.Address)[:boundedmeta.RekeyListProofSize-32]))
				})
				t.Run("listed rekey with a corrupted proof", func(t *testing.T) {
					proof := append([]byte(nil), listedProof(rekeyTarget.Address)...)
					proof[len(proof)-1] ^= 0x01
					expect(false, rekey("l9"), nil, withProof(proof))
				})
			}
			switch shape.Rekey {
			case plainhost.RekeyRefused:
				// Refused: no rekey at all. The spending key signs, and on a cosigned
				// shape the cosigner too, and neither opens one.
				t.Run("rekey refused", func(t *testing.T) { expect(false, rekey("l3"), nil, nil) })
				if shape.Timelock {
					t.Run("rekey refused one round early", func(t *testing.T) { expect(false, early(rekey("l3b")), nil, nil) })
				}
			case plainhost.RekeyOnlyThese:
				// Only these: nothing but a listed target with its proof, and the
				// cosigner opens nothing.
				t.Run("rekey to an unlisted address", func(t *testing.T) { expect(false, rekeyTo(unlisted.Address, "l3"), nil, nil) })
				t.Run("listed rekey without a proof", func(t *testing.T) { expect(false, rekey("l7"), nil, withProof(nil)) })
			case plainhost.RekeyPlusCosigned:
				// Plus cosigned: an empty proof takes the cosigner's branch, to any
				// address; without the cosigner it fails.
				t.Run("rekey to an unlisted address without the cosigner", func(t *testing.T) {
					expect(false, rekeyTo(unlisted.Address, "l3"), nil, withoutCosigner(nil))
				})
				t.Run("cosigned rekey to an unlisted address", func(t *testing.T) {
					txn := rekeyTo(unlisted.Address, "p1")
					if shape.Timelock {
						// No host rule gates a rekey (O11), so the cosigned branch too
						// leaves a timelock before the unlock round.
						txn = early(txn)
					}
					expect(true, txn, nil, nil)
				})
				// The unlisted key holds the account now; it hands it back, so the
				// listed rekey below starts from the account's own program.
				t.Run("the unlisted key hands the account back", func(t *testing.T) {
					back := payment(account.address, "p2")
					back.Amount = 0
					back.RekeyTo = mustDecodeAddress(t, account.address)
					submitEd25519TxnExpectSuccess(t, network, unlisted.PrivateKey, back)
					if got := authAddress(t, network, account.address); got != "" {
						t.Fatalf("authorizer = %q after the hand-back", got)
					}
				})
			case plainhost.RekeySpendingKey:
				if shape.Cosigner {
					t.Run("rekey without the cosigner", func(t *testing.T) { expect(false, rekey("l10"), nil, withoutCosigner(nil)) })
				}
			}
			// The account's last rekey hands it to rekeyTarget for the cleanup. A
			// listed target takes the spending key alone, so its cosigner slot stays
			// empty on a cosigned shape; a declared rekey needs the cosigner. No host
			// rule gates a rekey (O11), so on a timelock each way out is open before
			// the unlock round.
			wantAuth := rekeyTarget.Address.String()
			switch {
			case refused:
				// Nothing hands it over: it stays with its own program.
				wantAuth = ""
			case shape.HasRekeyList() && shape.Timelock:
				t.Run("listed rekey one round early", func(t *testing.T) { expect(true, early(rekey("m")), nil, withoutCosigner(nil)) })
			case shape.HasRekeyList():
				t.Run("listed rekey with the spending key alone", func(t *testing.T) { expect(true, rekey("m"), nil, withoutCosigner(nil)) })
			case shape.Timelock && shape.Cosigner:
				t.Run("rekey with the spending key and the cosigner one round early", func(t *testing.T) { expect(true, early(rekey("m")), nil, nil) })
			case shape.Timelock:
				t.Run("rekey with the spending key one round early", func(t *testing.T) { expect(true, early(rekey("m")), nil, nil) })
			case shape.Cosigner:
				t.Run("rekey with the spending key and the cosigner", func(t *testing.T) { expect(true, rekey("m"), nil, nil) })
			default:
				t.Run("rekey with the spending key", func(t *testing.T) { expect(true, rekey("m"), nil, nil) })
			}
			info, err := network.Client.AccountInformation(account.address).Do(context.Background())
			if err != nil {
				t.Fatalf("read account: %v", err)
			}
			if info.AuthAddr != wantAuth {
				t.Fatalf("auth address = %q, want %q", info.AuthAddr, wantAuth)
			}
		})
	}
}

// assertSignerRefusesRekey asks apshell for a rekey the signer must refuse, with
// a refusal naming reason, before anything reaches the chain.
func assertSignerRefusesRekey(t *testing.T, apshell *harness.ApshellHarness, network *harness.TestnetConfig, account, to, reason string) {
	t.Helper()
	output, err := apshell.RunWithInput(fmt.Sprintf("rekey %s to %s\nquit\n", account, to))
	if !strings.Contains(output, reason) || strings.Contains(strings.ToLower(output), "rekey transaction submitted:") {
		t.Fatalf("the signer did not refuse a rekey of %s to %s with %q: %v\n%s", account, to, reason, err, output)
	}
	before := authAddress(t, network, account)
	if before == to {
		t.Fatalf("%s was rekeyed to %s", account, to)
	}
}

// authAddress is an account's current authorizer, empty when it signs for itself.
func authAddress(t *testing.T, network *harness.TestnetConfig, account string) string {
	t.Helper()
	info, err := network.Client.AccountInformation(account).Do(context.Background())
	if err != nil {
		t.Fatalf("read %s: %v", account, err)
	}
	return info.AuthAddr
}

// boundsPassedUnlockRound has been reached on any network, so an account using it
// can spend immediately and a test can measure its costliest paths.
const boundsPassedUnlockRound = 1

// boundsFamily is one policy and overlay arrangement, with every transfer kind
// enabled and the list at its largest for that encoding.
type boundsFamily struct {
	shape      plainhost.Shape
	recipients int
}

func boundsFamilies() []boundsFamily {
	var families []boundsFamily
	for _, shape := range plainhost.Shapes() {
		if len(shape.Spend) != 3 {
			continue
		}
		recipients := 0
		switch shape.Encoding {
		case plainhost.EncodingInline:
			recipients = plainhost.InlineMax
		case plainhost.EncodingMerkle:
			recipients = 64
		}
		families = append(families, boundsFamily{shape: shape, recipients: recipients})
	}
	return families
}

// BuildBoundedAuthorizationMetadata runs the generation backstop, so each account
// here, every Falcon-1024 plain host shape, passed the production solver and fee
// ceiling at its list size. The simulation then shows the declared opcode
// ceilings hold on the costliest path.
func TestBoundedGeneralResourceMatrix(t *testing.T) {
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to integration algod: %v", err)
	}
	compiler := matrixCompileAlgod(t, network)
	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("load funding account: %v", err)
	}
	provider := plainHostProvider(t, network, plainFalconKeyType)
	provider.SetAlgodClient(compiler)

	// Each encoding's longest list, built once: every account has its own
	// spending key, so the shapes can share their lists.
	addresses := func(count int) []string {
		list := make([]string, count)
		for i := range list {
			list[i] = algocrypto.GenerateAccount().Address.String()
		}
		return list
	}
	longest := map[string][]string{
		plainhost.EncodingInline: addresses(plainhost.InlineMax),
		plainhost.EncodingMerkle: addresses(plainhost.RecipientsMax),
	}
	// A list proof's size is fixed, so the list's length costs nothing; a full
	// list shows generation still fits.
	fullRekeyTo := addresses(rekeylist.MaxEntries)
	for _, shape := range plainhost.Shapes() {
		account := newBoundsAccount(t, provider, shape, longest[shape.Encoding], boundsPassedUnlockRound, fullRekeyTo)
		if account.metadata.MaxFee == nil || *account.metadata.MaxFee != plainhost.MaxFee {
			t.Fatalf("%s MaxFee = %v", shape.Descriptor(), account.metadata.MaxFee)
		}
		t.Logf("%s: %d program bytes", shape.Descriptor(), len(account.bytecode))
	}

	for _, family := range boundsFamilies() {
		shape := family.shape
		t.Run(shape.Descriptor(), func(t *testing.T) {
			funderAddress := mustDecodeAddress(t, funder.GetAddress())
			recipients := []string{funder.GetAddress()}
			for len(recipients) < family.recipients {
				recipients = append(recipients, algocrypto.GenerateAccount().Address.String())
			}
			// A full list: every proof has the tree's fixed depth, so this is the
			// costliest listed rekey as well as the cleanup's way out, on every
			// shape but a refused one.
			cleanup := algocrypto.GenerateAccount()
			rekeyTo := []string{cleanup.Address.String()}
			for len(rekeyTo) < rekeylist.MaxEntries {
				rekeyTo = append(rekeyTo, algocrypto.GenerateAccount().Address.String())
			}
			account := newBoundsAccount(t, provider, shape, recipients, boundsPassedUnlockRound, rekeyTo)
			// Everything that can fail runs before funding, so the cleanup that
			// returns the funds is registered as soon as there are funds to return.
			var proof []byte
			if shape.Encoding == plainhost.EncodingMerkle {
				proof = account.proofFor(t, funderAddress)
			}
			if err := funder.FundMicroAlgosAndWait(account.address, 500_000); err != nil {
				t.Fatalf("fund account: %v", err)
			}
			t.Cleanup(func() {
				if shape.Rekey == plainhost.RekeyRefused {
					// A refused account can't be rekeyed or closed; it pays back all
					// but its minimum balance.
					drainBounded(t, network, account, funder.GetAddress(), proof)
					return
				}
				handOver(t, network, account, cleanup.Address, "general-cleanup-rekey")
				bestEffortCloseRekeyedAccount(t, network, account.address, funder.GetAddress(), cleanup.PrivateKey)
			})
			sp := mustSuggestedParams(t, network)
			spend, _ := account.signedGroup(t, corridorPaymentTxn(t, sp, account.address, funder.GetAddress(), 0, "general-opcode-spend"), proof, nil)
			paths := []lsigresource.AuthorizationPath{lsigresource.PathSpend}
			vectors := []harness.OpcodeCeilingVector{{Name: "maximum-spend", Path: lsigresource.PathSpend, SignedTxns: spend, LSigIndex: 0}}
			// Every shape but a refused one has a rekey path: the listed one to the
			// cleanup key, or a declared one, with the cosigner on a cosigned shape,
			// to any other address. Plus cosigned has both; refused has only the spend.
			rekeyVector := func(target types.Address, path lsigresource.AuthorizationPath, name string) {
				rekeyTxn := corridorPaymentTxn(t, sp, account.address, account.address, 0, "general-opcode-"+name)
				rekeyTxn.RekeyTo = target
				rekey, _ := account.signedGroup(t, rekeyTxn, nil, nil)
				paths = append(paths, path)
				vectors = append(vectors, harness.OpcodeCeilingVector{Name: name, Path: path, SignedTxns: rekey, LSigIndex: 0})
			}
			if shape.HasRekeyList() {
				rekeyVector(cleanup.Address, lsigresource.PathListedRekey, "maximum-listed-rekey")
			}
			if shape.Rekey == plainhost.RekeySpendingKey || shape.Rekey == plainhost.RekeyPlusCosigned {
				rekeyVector(algocrypto.GenerateAccount().Address, lsigresource.PathSpendingRekey, "maximum-rekey")
			}
			report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), compiler, harness.OpcodeCeilingValidation{
				Name:          shape.Descriptor(),
				FinalProgram:  account.bytecode,
				Profile:       provider.BoundedLogicSigOpcodeProfile(),
				Bounded:       true,
				RequiredPaths: paths,
				Vectors:       vectors,
			})
			if err != nil {
				t.Fatalf("validate opcode ceilings: %v", err)
			}
			for observedPath, observed := range report.Paths {
				t.Logf("path %d: %d observed / %d declared", observedPath, observed.MaximumObserved, observed.DeclaredCeiling)
			}
		})
	}
}

// This is the account as an operator gets it: with no setup, the signer generates
// a bounded Falcon plain host, enabled by default, assembles its arguments, and
// rescans it after a restart.
func TestBoundsThroughSigner(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed test")
	}
	lockOnDisconnect := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to network: %v", err)
	}
	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("load funding account: %v", err)
	}
	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("unlock signer: %v", err)
	}
	client := signerclient.NewSignerClient(signerd.GetURL())
	apshell := harness.NewApshellHarness(t)

	request := func(recipients ...string) map[string]string {
		return map[string]string{
			plainhost.ParameterSpendEffects:   "pay,axfer,asset_opt_in",
			plainhost.ParameterRekeyAuthority: plainhost.RekeySpendingKey,
			plainhost.ParameterRecipients:     strings.Join(recipients, ","),
		}
	}
	accounts := make(map[string]string)
	for _, test := range []struct {
		name       string
		recipients int
		policy     string
		onlyThese  bool
	}{
		{name: "inline", recipients: 2, policy: composeddsa.Layer3PolicyFixedAllowlist},
		{name: "auto chooses merkle above ten", recipients: 11, policy: composeddsa.Layer3PolicyMerkleAllowlist},
		{name: "only these", recipients: 2, policy: composeddsa.Layer3PolicyFixedAllowlist, onlyThese: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			allowed := algocrypto.GenerateAccount().Address.String()
			if err := funder.FundMicroAlgosAndWait(allowed, 200_000); err != nil {
				t.Fatalf("fund recipient: %v", err)
			}
			recipients := []string{allowed}
			for len(recipients) < test.recipients {
				recipients = append(recipients, algocrypto.GenerateAccount().Address.String())
			}
			params := request(recipients...)
			if test.onlyThese {
				params[plainhost.ParameterRekeyAuthority] = plainhost.RekeyOnlyThese
				params[plainhost.ParameterRekeyTo] = algocrypto.GenerateAccount().Address.String()
			}
			account := mustAdminGenerateKeyNoCleanup(t, client, signerd, plainFalconKeyType, params)
			if err := funder.FundMicroAlgosAndWait(account, 2_000_000); err != nil {
				t.Fatalf("fund account: %v", err)
			}
			assertAuthorAllowlistInventory(t, client, account, test.policy)
			accounts[account] = test.policy

			send := func(to string) string {
				output, err := apshell.RunWithInput(fmt.Sprintf("send 0.1 algo from %s to %s\nquit\n", account, to))
				if err != nil {
					t.Fatalf("run apshell: %v\n%s", err, output)
				}
				return output
			}
			outsider := algocrypto.GenerateAccount().Address.String()
			if output := send(outsider); strings.Contains(strings.ToLower(output), "confirmed") {
				t.Fatalf("an outsider payment confirmed:\n%s", output)
			}
			output := send(allowed)
			if _, err := network.WaitForConfirmation(mustExtractTxID(t, output), 10); err != nil {
				t.Fatalf("payment failed to confirm: %v\n%s", err, output)
			}
			received, err := network.Client.AccountInformation(allowed).Do(context.Background())
			if err != nil {
				t.Fatalf("read recipient: %v", err)
			}
			if received.Amount != 300_000 {
				t.Fatalf("recipient holds %d, want 300000", received.Amount)
			}
			if !test.onlyThese {
				return
			}
			// The program takes no other rekey, so the signer refuses it first.
			assertSignerRefusesRekey(t, apshell, network, account, outsider, "is not on this account's rekey-to list")
		})
	}

	t.Run("apshell timelock boundary file", func(t *testing.T) {
		directory := t.TempDir()
		// generate creates the account a boundary file describes through apshell,
		// then lists the keys.
		generate := func(t *testing.T, name, body string) (string, string) {
			t.Helper()
			path := filepath.Join(directory, name)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("write boundary file: %v", err)
			}
			output, err := apshell.RunWithInput(fmt.Sprintf("generate %s --boundary=%s\ny\nkeys\nquit\n", plainFalconKeyType, path))
			if err != nil {
				t.Fatalf("run apshell: %v\n%s", err, output)
			}
			account := ""
			for _, line := range strings.Split(output, "\n") {
				if _, address, found := strings.Cut(line, plainFalconKeyType+" key: "); found {
					account = strings.TrimSpace(address)
				}
			}
			if account == "" {
				t.Fatalf("no generated address:\n%s", output)
			}
			return account, output
		}
		// assertLocked funds an account and shows the timelock holds: a spend
		// before the unlock round moves nothing.
		assertLocked := func(t *testing.T, account string, funding uint64) {
			t.Helper()
			if err := funder.FundMicroAlgosAndWait(account, funding); err != nil {
				t.Fatalf("fund account: %v", err)
			}
			before, err := network.Client.AccountInformation(account).Do(context.Background())
			if err != nil {
				t.Fatalf("read balance: %v", err)
			}
			refused, err := apshell.RunWithInput(fmt.Sprintf("send 0.01 algo from %s to %s\nquit\n", account, funder.GetAddress()))
			if err != nil {
				t.Fatalf("run apshell: %v\n%s", err, refused)
			}
			after, err := network.Client.AccountInformation(account).Do(context.Background())
			if err != nil {
				t.Fatalf("read balance: %v", err)
			}
			if after.Amount != before.Amount || strings.Contains(strings.ToLower(refused), "confirmed") {
				t.Fatalf("a locked account spent: %d to %d\n%s", before.Amount, after.Amount, refused)
			}
		}
		const never = "unlock_round: 18446744073709551615\n"

		// A timelock takes every rekey setting. With a spending-key rekey the
		// account leaves before the unlock round: no host rule applies to a rekey
		// (O11), so the lock holds only while the spending key keeps it.
		walkable, output := generate(t, "walkable.yaml", "schema: aplane.boundary.v1\nspend: [pay]\nrekey: {authority: spending_key}\n"+never)
		for _, want := range []string{"Generated", "Unlock round:   18446744073709551615", "Rekey:          spending_key", "Timelock · spending-key rekey"} {
			if !strings.Contains(output, want) {
				t.Fatalf("output lacks %q:\n%s", want, output)
			}
		}
		assertLocked(t, walkable, 500_000)
		exit := algocrypto.GenerateAccount()
		txid, err := apshell.RekeyAccount(walkable, exit.Address.String())
		if err != nil {
			t.Fatalf("rekey %s before its unlock round: %v", walkable, err)
		}
		if _, err := network.WaitForConfirmation(txid, 10); err != nil {
			t.Fatalf("rekey %s did not confirm: %v", walkable, err)
		}
		if got := authAddress(t, network, walkable); got != exit.Address.String() {
			t.Fatalf("%s authorizer = %q after the rekey, want %s", walkable, got, exit.Address)
		}
		bestEffortCloseRekeyedAccount(t, network, walkable, funder.GetAddress(), exit.PrivateKey)
		accounts[walkable] = composeddsa.Layer3PolicyTimelock

		// A refused rekey: before the unlock round nothing moves the account or
		// what it holds.
		refused, output := generate(t, "refused.yaml", "schema: aplane.boundary.v1\nspend: [pay]\nrekey: {authority: refused}\n"+never)
		for _, want := range []string{"Generated", "Unlock round:   18446744073709551615", "Rekey:          refused", "Timelock · no rekey"} {
			if !strings.Contains(output, want) {
				t.Fatalf("output lacks %q:\n%s", want, output)
			}
		}
		assertLocked(t, refused, 200_000)
		assertSignerRefusesRekey(t, apshell, network, refused, algocrypto.GenerateAccount().Address.String(),
			boundedmeta.Contract+" account permanently disables rekey")
		accounts[refused] = composeddsa.Layer3PolicyTimelock

		listedKey := algocrypto.GenerateAccount().Address.String()
		locked, output := generate(t, "locked.yaml", "schema: aplane.boundary.v1\nspend: [pay]\nrekey:\n  authority: only_these\n  to: ["+listedKey+"]\n"+never)
		for _, want := range []string{"Unlocks at: round 18446744073709551615", "Recipients: any, once unlocked",
			"Rekey:      only to this address, with the spending key alone:", listedKey, "That is a way around the unlock round.",
			"Unlock round:   18446744073709551615", "Timelock · rekey to listed only"} {
			if !strings.Contains(output, want) {
				t.Fatalf("output lacks %q:\n%s", want, output)
			}
		}
		assertLocked(t, locked, 500_000)
		accounts[locked] = composeddsa.Layer3PolicyTimelock
	})

	t.Run("apshell boundary file", func(t *testing.T) {
		directory := t.TempDir()
		recipient := algocrypto.GenerateAccount().Address.String()
		path := filepath.Join(directory, "boundary.yaml")
		if err := os.WriteFile(path, []byte("schema: aplane.boundary.v1\nspend: [pay]\nrecipients: ["+recipient+"]\nrekey: {authority: spending_key}\n"), 0o600); err != nil {
			t.Fatalf("write boundary file: %v", err)
		}
		resultFile := filepath.Join(directory, "result.json")

		declined, err := apshell.RunWithInput(fmt.Sprintf("generate %s --boundary=%s\nn\nquit\n", plainFalconKeyType, path))
		if err != nil {
			t.Fatalf("run apshell: %v\n%s", err, declined)
		}
		if !strings.Contains(declined, "Local summary") || !strings.Contains(declined, "Cancelled") {
			t.Fatalf("declining did not cancel:\n%s", declined)
		}

		output, err := apshell.RunWithInput(fmt.Sprintf("generate %s --boundary=%s --result=%s\ny\nkeys\nquit\n", plainFalconKeyType, path, resultFile))
		if err != nil {
			t.Fatalf("run apshell: %v\n%s", err, output)
		}
		for _, want := range []string{"Generated", "List encoding:  inline", "Allowlist · spending-key rekey"} {
			if !strings.Contains(output, want) {
				t.Fatalf("output lacks %q:\n%s", want, output)
			}
		}
		data, err := os.ReadFile(resultFile)
		if err != nil {
			t.Fatalf("read result file: %v", err)
		}
		var saved struct {
			Address    string            `json:"address"`
			Parameters map[string]string `json:"parameters"`
		}
		if err := json.Unmarshal(data, &saved); err != nil {
			t.Fatalf("parse result file: %v", err)
		}
		if saved.Parameters[plainhost.ParameterRecipients] != recipient || saved.Parameters[plainhost.ParameterSpendEffects] != "pay" {
			t.Fatalf("saved parameters = %v", saved.Parameters)
		}
		accounts[saved.Address] = composeddsa.Layer3PolicyFixedAllowlist
	})

	if err := signerd.Stop(); err != nil {
		t.Fatalf("stop signer: %v", err)
	}
	if err := signerd.Start(); err != nil {
		t.Fatalf("restart signer: %v", err)
	}
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("unlock signer: %v", err)
	}
	client = signerclient.NewSignerClient(signerd.GetURL())
	for account, policy := range accounts {
		if !waitForKey(t, signerd.GetURL(), account, 10*time.Second) {
			t.Fatalf("signer did not rescan %s", account)
		}
		assertAuthorAllowlistInventory(t, client, account, policy)
	}
}
