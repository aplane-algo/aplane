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
	"github.com/aplane-algo/aplane/lsig/boundedaccount"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

func generalRequest(shape boundedaccount.Shape, recipients []string, unlockRound uint64, cosignerKey []byte, rekeyTo []string) map[string]string {
	spend := make([]string, len(shape.Spend))
	for i, effect := range shape.Spend {
		spend[i] = string(effect)
	}
	params := map[string]string{
		boundedaccount.ParameterSpendEffects:   strings.Join(spend, ","),
		boundedaccount.ParameterRekeyAuthority: shape.Rekey,
	}
	if shape.Encoding != "" {
		params[boundedaccount.ParameterListEncoding] = shape.Encoding
		params[boundedaccount.ParameterRecipients] = strings.Join(recipients, ",")
	}
	if shape.Timelock {
		params[boundedaccount.ParameterUnlockRound] = strconv.FormatUint(unlockRound, 10)
	}
	if shape.AnyRecipient {
		params[boundedaccount.ParameterRecipientScope] = boundedaccount.RecipientScopeAny
	}
	if shape.Cosigner {
		params[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(cosignerKey)
	}
	if shape.Rekey == boundedaccount.RekeyOnlyThese {
		params[boundedaccount.ParameterRekeyTo] = strings.Join(rekeyTo, ",")
	}
	return params
}

// newGeneralAccount generates an account as the signer does. An only-these shape
// lists rekeyTo; key generation commits to the list's root.
func newGeneralAccount(t *testing.T, provider *boundedaccount.Provider, shape boundedaccount.Shape, recipients []string, unlockRound uint64, rekeyTo []string) corridorExecutionAccount {
	t.Helper()
	ops := signerops.New(nil)
	spendingPublic, spendingPrivate, err := ops.GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate spending key: %v", err)
	}
	cosignerPublic, cosignerPrivate, err := ops.GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate cosigner key: %v", err)
	}
	params := generalRequest(shape, recipients, unlockRound, cosignerPublic, rekeyTo)
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
	account := corridorExecutionAccount{
		address:            derived.Address.String(),
		bytecode:           derived.Bytecode,
		recipientsParam:    instance.Values[boundedaccount.ParameterRecipients],
		userPrivateKey:     spendingPrivate,
		cosignerPrivateKey: cosignerPrivate,
		metadata:           metadata,
	}
	if (shape.Rekey == boundedaccount.RekeyOnlyThese) != (metadata.RekeyList != nil) {
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

func newGeneralProvider(t *testing.T, network *harness.TestnetConfig) *boundedaccount.Provider {
	t.Helper()
	falcon1024.RegisterClient()
	provider, err := boundedaccount.NewProvider()
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}
	provider.SetAlgodClient(network.Client)
	return provider
}

// Every shape runs its own program on the network, so each rejection here is the
// program's and each spend subset is exercised on its own, not only the largest
// family. Accounts go straight to algod: the signer would refuse much of this
// before the program ever saw it.
func TestBoundedGeneralShapeMatrixOnChainLocalnet(t *testing.T) {
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
	provider := newGeneralProvider(t, network)

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

	for _, shape := range boundedaccount.Shapes() {
		t.Run(shape.Descriptor(), func(t *testing.T) {
			// A spending-key rekey would leave a timelock before the unlock round, so
			// no timelock offers one. A listed rekey may leave it: the lock holds only
			// while the listed keys' holders cooperate.
			if shape.Timelock && shape.Rekey == boundedaccount.RekeySpendingKey {
				t.Fatalf("a timelock shape offers a %s rekey", shape.Rekey)
			}
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
			account := newGeneralAccount(t, provider, shape, []string{allowed.String(), second.String()}, unlockRound,
				[]string{rekeyTarget.Address.String(), otherListed.String()})
			if err := funder.FundMicroAlgosAndWait(account.address, 400_000); err != nil {
				t.Fatalf("fund account: %v", err)
			}

			mayPay := slices.Contains(shape.Spend, txeffects.SpendEffectPay)
			mayTransfer := slices.Contains(shape.Spend, txeffects.SpendEffectAxfer)
			mayOptIn := slices.Contains(shape.Spend, txeffects.SpendEffectAssetOptIn)
			merkle := shape.Encoding == boundedaccount.EncodingMerkle
			hasList := shape.Encoding != ""
			proof := func(to types.Address) []byte {
				if !merkle {
					return nil
				}
				return account.proofFor(t, to)
			}
			t.Cleanup(func() {
				if shape.Rekey == boundedaccount.RekeyRefused {
					// A listed recipient's own cleanup returns the sweep to the funder.
					to, toProof := funder.GetAddress(), []byte(nil)
					if hasList {
						to, toProof = allowed.String(), proof(allowed)
					}
					sweepRefusedAccount(t, network, account, to, toProof)
					return
				}
				// The rekey below hands every other account to rekeyTarget, listed
				// or not; if it never ran, the cleanup hands it over first.
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
			switch shape.Rekey {
			case boundedaccount.RekeyRefused:
				// No rekey path exists, so a pure rekey with a valid spending signature fails.
				t.Run("rekey is refused", func(t *testing.T) { expect(false, rekey("l"), nil, nil) })
				if shape.Timelock {
					// The unlock round opens only the spend path.
					t.Run("rekey one round early is refused", func(t *testing.T) { expect(false, early(rekey("l2")), nil, nil) })
				}
			case boundedaccount.RekeyOnlyThese:
				slot := account.listProofIndex(t)
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
				unlisted := algocrypto.GenerateAccount().Address
				t.Run("rekey to an unlisted address", func(t *testing.T) { expect(false, rekeyTo(unlisted, "l3"), nil, nil) })
				t.Run("rekey to an unlisted address with a listed proof", func(t *testing.T) {
					expect(false, rekeyTo(unlisted, "l4"), nil, withProof(listedProof(rekeyTarget.Address)))
				})
				t.Run("rekey to itself", func(t *testing.T) {
					expect(false, rekeyTo(mustDecodeAddress(t, account.address), "l5"), nil, withProof(listedProof(rekeyTarget.Address)))
				})
				t.Run("listed rekey with the other entry's proof", func(t *testing.T) {
					expect(false, rekey("l6"), nil, withProof(listedProof(otherListed)))
				})
				t.Run("listed rekey without a proof", func(t *testing.T) { expect(false, rekey("l7"), nil, withProof(nil)) })
				t.Run("listed rekey with a short proof", func(t *testing.T) {
					expect(false, rekey("l8"), nil, withProof(listedProof(rekeyTarget.Address)[:boundedmeta.RekeyListProofSize-32]))
				})
				t.Run("listed rekey with a corrupted proof", func(t *testing.T) {
					proof := append([]byte(nil), listedProof(rekeyTarget.Address)...)
					proof[len(proof)-1] ^= 0x01
					expect(false, rekey("l9"), nil, withProof(proof))
				})
				if shape.Cosigner {
					t.Fatal("phase 3 offers only-these without a cosigner")
				}
				if shape.Timelock {
					// No host rule gates a rekey (O11), so the list is a way out before the unlock.
					t.Run("listed rekey one round early", func(t *testing.T) { expect(true, early(rekey("m")), nil, nil) })
				} else {
					t.Run("listed rekey with the spending key alone", func(t *testing.T) { expect(true, rekey("m"), nil, nil) })
				}
			default:
				t.Run("rekey with the spending key", func(t *testing.T) { expect(true, rekey("m"), nil, nil) })
			}
			info, err := network.Client.AccountInformation(account.address).Do(context.Background())
			if err != nil {
				t.Fatalf("read account: %v", err)
			}
			wantAuth := rekeyTarget.Address.String()
			if shape.Rekey == boundedaccount.RekeyRefused {
				wantAuth = ""
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

// sweepRefusedAccount pays a refused account's spare ALGO to a recipient it may pay.
// It can neither close nor be rekeyed, so its minimum balance stays. Every refused
// shape has pay, so a failed sweep is a real refusal, not a cleanup miss.
func sweepRefusedAccount(t *testing.T, network *harness.TestnetConfig, account corridorExecutionAccount, to string, proof []byte) {
	t.Helper()
	info, err := network.Client.AccountInformation(account.address).Do(context.Background())
	if err != nil {
		t.Fatalf("read %s: %v", account.address, err)
	}
	txn := corridorPaymentTxn(t, mustSuggestedParams(t, network), account.address, to, 0, "general-refused-sweep")
	// signedGroup charges this account the whole group's fees.
	fee := uint64(corridorExecutionGroupSize) * uint64(txn.Fee)
	if info.Amount <= info.MinBalance+fee {
		return
	}
	txn.Amount = types.MicroAlgos(info.Amount - info.MinBalance - fee)
	raw, txid := account.signGroup(t, txn, proof, nil)
	submitCorridorGroupExpectSuccess(t, network, raw, txid)
}

// generalPassedUnlockRound has been reached on any network, so an account using it
// can spend immediately and a test can measure its costliest paths.
const generalPassedUnlockRound = 1

// generalFamily is one list encoding and authority arrangement, with every
// transfer kind enabled and the list at its largest for that encoding.
type generalFamily struct {
	shape      boundedaccount.Shape
	recipients int
}

func generalFamilies() []generalFamily {
	var families []generalFamily
	for _, shape := range boundedaccount.Shapes() {
		if len(shape.Spend) != 3 {
			continue
		}
		recipients := 0
		switch shape.Encoding {
		case boundedaccount.EncodingInline:
			recipients = boundedaccount.InlineMax
		case boundedaccount.EncodingMerkle:
			recipients = 64
		}
		families = append(families, generalFamily{shape: shape, recipients: recipients})
	}
	return families
}

// BuildBoundedAuthorizationMetadata runs the generation backstop, so each account
// here passed the production solver and fee ceiling at its list size. The
// simulation then shows the declared opcode ceilings hold on the costliest path.
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
	falcon1024.RegisterClient()
	provider, err := boundedaccount.NewProvider()
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}
	provider.SetAlgodClient(compiler)

	for _, shape := range boundedaccount.Shapes() {
		count := 0
		switch shape.Encoding {
		case boundedaccount.EncodingInline:
			count = boundedaccount.InlineMax
		case boundedaccount.EncodingMerkle:
			count = boundedaccount.RecipientsMax
		}
		recipients := make([]string, count)
		for i := range recipients {
			recipients[i] = algocrypto.GenerateAccount().Address.String()
		}
		// A list proof's size is fixed, so the list's length costs nothing; a full
		// list shows generation still fits.
		rekeyTo := make([]string, rekeylist.MaxEntries)
		for i := range rekeyTo {
			rekeyTo[i] = algocrypto.GenerateAccount().Address.String()
		}
		account := newGeneralAccount(t, provider, shape, recipients, generalPassedUnlockRound, rekeyTo)
		if account.metadata.MaxFee != boundedaccount.MaxFee {
			t.Fatalf("%s MaxFee = %d", shape.Descriptor(), account.metadata.MaxFee)
		}
		t.Logf("%s: %d program bytes", shape.Descriptor(), len(account.bytecode))
	}

	for _, family := range generalFamilies() {
		shape := family.shape
		t.Run(shape.Descriptor(), func(t *testing.T) {
			funderAddress := mustDecodeAddress(t, funder.GetAddress())
			recipients := []string{funder.GetAddress()}
			for len(recipients) < family.recipients {
				recipients = append(recipients, algocrypto.GenerateAccount().Address.String())
			}
			// A full list: every proof has the tree's fixed depth, so this is the
			// costliest listed rekey as well as the cleanup's way out.
			cleanup := algocrypto.GenerateAccount()
			rekeyTo := []string{cleanup.Address.String()}
			for len(rekeyTo) < rekeylist.MaxEntries {
				rekeyTo = append(rekeyTo, algocrypto.GenerateAccount().Address.String())
			}
			account := newGeneralAccount(t, provider, shape, recipients, generalPassedUnlockRound, rekeyTo)
			// Everything that can fail runs before funding, so the cleanup that
			// returns the funds is registered as soon as there are funds to return.
			var proof []byte
			if shape.Encoding == boundedaccount.EncodingMerkle {
				proof = account.proofFor(t, funderAddress)
			}
			if err := funder.FundMicroAlgosAndWait(account.address, 500_000); err != nil {
				t.Fatalf("fund account: %v", err)
			}
			refused := shape.Rekey == boundedaccount.RekeyRefused
			t.Cleanup(func() {
				// A refused account can never close, so its minimum balance stays
				// behind: 0.1 ALGO per refused family on a public network.
				if refused {
					sweepRefusedAccount(t, network, account, funder.GetAddress(), proof)
					return
				}
				handOver(t, network, account, cleanup.Address, "general-cleanup-rekey")
				bestEffortCloseRekeyedAccount(t, network, account.address, funder.GetAddress(), cleanup.PrivateKey)
			})
			sp := mustSuggestedParams(t, network)
			spend, _ := account.signedGroup(t, corridorPaymentTxn(t, sp, account.address, funder.GetAddress(), 0, "general-opcode-spend"), proof, nil)
			paths := []lsigresource.AuthorizationPath{lsigresource.PathSpend}
			vectors := []harness.OpcodeCeilingVector{{Name: "maximum-spend", Path: lsigresource.PathSpend, SignedTxns: spend, LSigIndex: 0}}
			// A refused shape has no rekey path to measure.
			if !refused {
				rekeyTxn := corridorPaymentTxn(t, sp, account.address, account.address, 0, "general-opcode-rekey")
				rekeyTxn.RekeyTo = cleanup.Address
				rekey, _ := account.signedGroup(t, rekeyTxn, nil, nil)
				path, name := lsigresource.PathSpendingRekey, "maximum-rekey"
				if shape.Rekey == boundedaccount.RekeyOnlyThese {
					path, name = lsigresource.PathListedRekey, "maximum-listed-rekey"
				}
				paths = append(paths, path)
				vectors = append(vectors, harness.OpcodeCeilingVector{Name: name, Path: path, SignedTxns: rekey, LSigIndex: 0})
			}
			report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), compiler, harness.OpcodeCeilingValidation{
				Name:          shape.Descriptor(),
				FinalProgram:  account.bytecode,
				Profile:       provider.LogicSigOpcodeProfile(),
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
// it, assembles its arguments, and rescans it after a restart.
func TestBoundedGeneralThroughSigner(t *testing.T) {
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
			boundedaccount.ParameterSpendEffects:   "pay,axfer,asset_opt_in",
			boundedaccount.ParameterRekeyAuthority: boundedaccount.RekeySpendingKey,
			boundedaccount.ParameterRecipients:     strings.Join(recipients, ","),
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
				params[boundedaccount.ParameterRekeyAuthority] = boundedaccount.RekeyOnlyThese
				params[boundedaccount.ParameterRekeyTo] = algocrypto.GenerateAccount().Address.String()
			}
			account := mustAdminGenerateKeyNoCleanup(t, client, signerd, boundedaccount.KeyTypeV1, params)
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
		// A spending-key rekey would leave the lock early, so the signer refuses it.
		walkable := filepath.Join(directory, "walkable.yaml")
		if err := os.WriteFile(walkable, []byte("schema: aplane.boundary.v1\nspend: [pay]\nrekey: {authority: spending_key}\nunlock_round: 18446744073709551615\n"), 0o600); err != nil {
			t.Fatalf("write boundary file: %v", err)
		}
		refusal, _ := apshell.RunWithInput(fmt.Sprintf("generate %s boundary=%s\ny\nquit\n", boundedaccount.KeyTypeV1, walkable))
		if !strings.Contains(refusal, "a timelock can't take rekey_authority=spending_key") || strings.Contains(refusal, "Generated ") {
			t.Fatalf("a timelock with a spending-key rekey was not refused:\n%s", refusal)
		}

		// Without a cosigner, a timelock's only way out is a listed rekey.
		uncosigned := filepath.Join(directory, "uncosigned.yaml")
		if err := os.WriteFile(uncosigned, []byte("schema: aplane.boundary.v1\nspend: [pay]\nrekey: {authority: refused}\nunlock_round: 18446744073709551615\n"), 0o600); err != nil {
			t.Fatalf("write boundary file: %v", err)
		}
		refusal, _ = apshell.RunWithInput(fmt.Sprintf("generate %s boundary=%s\ny\nquit\n", boundedaccount.KeyTypeV1, uncosigned))
		if !strings.Contains(refusal, "rekey_authority=refused needs a cosigner") || strings.Contains(refusal, "Generated ") {
			t.Fatalf("an uncosigned refused timelock was not refused:\n%s", refusal)
		}

		listedKey := algocrypto.GenerateAccount().Address.String()
		locked := filepath.Join(directory, "locked.yaml")
		if err := os.WriteFile(locked, []byte("schema: aplane.boundary.v1\nspend: [pay]\nrekey:\n  authority: only_these\n  to: ["+listedKey+"]\nunlock_round: 18446744073709551615\n"), 0o600); err != nil {
			t.Fatalf("write boundary file: %v", err)
		}
		output, err := apshell.RunWithInput(fmt.Sprintf("generate %s boundary=%s\ny\nkeys\nquit\n", boundedaccount.KeyTypeV1, locked))
		if err != nil {
			t.Fatalf("run apshell: %v\n%s", err, output)
		}
		for _, want := range []string{"Unlocks at: round 18446744073709551615", "Recipients: any, once unlocked",
			"Rekey:      only to this address, with the spending key alone:", listedKey, "That is a way around the unlock round.",
			"Unlock round:   18446744073709551615", "Timelock · rekey to listed only"} {
			if !strings.Contains(output, want) {
				t.Fatalf("output lacks %q:\n%s", want, output)
			}
		}
		account := ""
		for _, line := range strings.Split(output, "\n") {
			if _, address, found := strings.Cut(line, boundedaccount.KeyTypeV1+" key: "); found {
				account = strings.TrimSpace(address)
			}
		}
		if account == "" {
			t.Fatalf("no generated address:\n%s", output)
		}
		if err := funder.FundMicroAlgosAndWait(account, 500_000); err != nil {
			t.Fatalf("fund account: %v", err)
		}
		before, err := network.Client.AccountInformation(account).Do(context.Background())
		if err != nil {
			t.Fatalf("read balance: %v", err)
		}
		refused, err := apshell.RunWithInput(fmt.Sprintf("send 0.1 algo from %s to %s\nquit\n", account, funder.GetAddress()))
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
		accounts[account] = composeddsa.Layer3PolicyTimelock
	})

	t.Run("apshell boundary file", func(t *testing.T) {
		directory := t.TempDir()
		recipient := algocrypto.GenerateAccount().Address.String()
		path := filepath.Join(directory, "boundary.yaml")
		if err := os.WriteFile(path, []byte("schema: aplane.boundary.v1\nspend: [pay]\nrecipients: ["+recipient+"]\nrekey: {authority: spending_key}\n"), 0o600); err != nil {
			t.Fatalf("write boundary file: %v", err)
		}
		resultFile := filepath.Join(directory, "result.json")

		declined, err := apshell.RunWithInput(fmt.Sprintf("generate %s boundary=%s\nn\nquit\n", boundedaccount.KeyTypeV1, path))
		if err != nil {
			t.Fatalf("run apshell: %v\n%s", err, declined)
		}
		if !strings.Contains(declined, "Local summary") || !strings.Contains(declined, "Cancelled") {
			t.Fatalf("declining did not cancel:\n%s", declined)
		}

		output, err := apshell.RunWithInput(fmt.Sprintf("generate %s boundary=%s result=%s\ny\nkeys\nquit\n", boundedaccount.KeyTypeV1, path, resultFile))
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
		if saved.Parameters[boundedaccount.ParameterRecipients] != recipient || saved.Parameters[boundedaccount.ParameterSpendEffects] != "pay" {
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
