// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/boundedaccount"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

func generalRequest(shape boundedaccount.Shape, recipients []string, adminKey, cosignerKey []byte) map[string]string {
	spend := make([]string, len(shape.Spend))
	for i, effect := range shape.Spend {
		spend[i] = string(effect)
	}
	params := map[string]string{
		boundedaccount.ParameterSpendEffects:   strings.Join(spend, ","),
		boundedaccount.ParameterRekeyAuthority: shape.Rekey,
		boundedaccount.ParameterListEncoding:   shape.Encoding,
		boundedaccount.ParameterRecipients:     strings.Join(recipients, ","),
	}
	if shape.Rekey == boundedaccount.RekeyAdminKey {
		params[composeddsa.BoundedAdminPublicKeyParameter] = hex.EncodeToString(adminKey)
	}
	if shape.Cosigner {
		params[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(cosignerKey)
	}
	return params
}

func newGeneralAccount(t *testing.T, provider *boundedaccount.Provider, shape boundedaccount.Shape, recipients []string) corridorExecutionAccount {
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
	adminPublic, adminPrivate, err := ops.GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate admin key: %v", err)
	}
	params := generalRequest(shape, recipients, adminPublic, cosignerPublic)
	instance, err := provider.ResolveInstance(params)
	if err != nil {
		t.Fatalf("resolve instance: %v", err)
	}
	derived, err := provider.DeriveLsigWithSalt(context.Background(), spendingPublic, instance.Values)
	if err != nil {
		t.Fatalf("derive LogicSig: %v", err)
	}
	metadata, err := provider.BuildBoundedAuthorizationMetadata(spendingPublic, instance.Values, derived.Bytecode)
	if err != nil {
		t.Fatalf("build metadata: %v", err)
	}
	return corridorExecutionAccount{
		address:            derived.Address.String(),
		bytecode:           derived.Bytecode,
		recipientsParam:    instance.Values[boundedaccount.ParameterRecipients],
		userPrivateKey:     spendingPrivate,
		cosignerPrivateKey: cosignerPrivate,
		adminPrivateKey:    adminPrivate,
		metadata:           metadata,
	}
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
	if err := funder.FundMicroAlgosAndWait(allowed.String(), 300_000); err != nil {
		t.Fatalf("fund recipient: %v", err)
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
			account := newGeneralAccount(t, provider, shape, []string{allowed.String(), second.String()})
			if err := funder.FundMicroAlgosAndWait(account.address, 400_000); err != nil {
				t.Fatalf("fund account: %v", err)
			}
			rekeyTarget := algocrypto.GenerateAccount()
			t.Cleanup(func() {
				bestEffortCloseBoundedAsset(t, network, account.address, funder.GetAddress(), assetID, rekeyTarget.PrivateKey)
				bestEffortCloseRekeyedAccount(t, network, account.address, funder.GetAddress(), rekeyTarget.PrivateKey)
			})

			mayPay := slices.Contains(shape.Spend, txeffects.SpendEffectPay)
			mayTransfer := slices.Contains(shape.Spend, txeffects.SpendEffectAxfer)
			mayOptIn := slices.Contains(shape.Spend, txeffects.SpendEffectAssetOptIn)
			merkle := shape.Encoding == boundedaccount.EncodingMerkle
			proof := func(to types.Address) []byte {
				if !merkle {
					return nil
				}
				return account.proofFor(t, to)
			}
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

			t.Run("payment to a listed recipient", func(t *testing.T) { expect(mayPay, payment(allowed.String(), "a"), proof(allowed), nil) })
			t.Run("payment to itself", func(t *testing.T) { expect(mayPay, payment(account.address, "b"), nil, nil) })
			t.Run("payment to an outsider", func(t *testing.T) { expect(false, payment(outside.String(), "c"), proof(allowed), nil) })
			t.Run("transfer to an outsider", func(t *testing.T) { expect(false, transfer(outside.String(), 0, "d"), proof(allowed), nil) })
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
				t.Run("asset transfer", func(t *testing.T) {
					raw, _ := account.signGroup(t, transfer(allowed.String(), 1, "j"), proof(allowed), nil)
					_, err := network.Client.SendRawTransaction(raw).Do(context.Background())
					if err == nil {
						t.Fatal("transfer from an account with no holding was accepted")
					}
					if text := strings.ToLower(err.Error()); strings.Contains(text, "rejected by logic") || strings.Contains(text, "logic eval") {
						t.Fatalf("the program refused an admitted transfer: %v", err)
					}
				})
			}

			rekey := func(note string) types.Transaction {
				txn := payment(account.address, note)
				txn.Amount = 0
				txn.RekeyTo = rekeyTarget.Address
				return txn
			}
			t.Run("rekey with a nonzero amount", func(t *testing.T) {
				txn := rekey("k")
				txn.Amount = 1
				expect(false, txn, nil, nil)
			})
			if shape.Rekey == boundedaccount.RekeyAdminKey {
				t.Run("rekey without the admin key", func(t *testing.T) { expect(false, rekey("l"), nil, nil) })
				t.Run("rekey with the admin key", func(t *testing.T) {
					expect(true, rekey("m"), nil, func(txid types.Digest, args [][]byte) [][]byte {
						return account.adminRekeyArgs(t, args[0], txid)
					})
				})
			} else {
				t.Run("rekey with the spending key", func(t *testing.T) { expect(true, rekey("m"), nil, nil) })
			}
			info, err := network.Client.AccountInformation(account.address).Do(context.Background())
			if err != nil {
				t.Fatalf("read account: %v", err)
			}
			if info.AuthAddr != rekeyTarget.Address.String() {
				t.Fatalf("auth address = %q, want %q", info.AuthAddr, rekeyTarget.Address)
			}
		})
	}
}

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
		recipients := boundedaccount.InlineMax
		if shape.Encoding == boundedaccount.EncodingMerkle {
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
		count := boundedaccount.InlineMax
		if shape.Encoding == boundedaccount.EncodingMerkle {
			count = boundedaccount.RecipientsMax
		}
		recipients := make([]string, count)
		for i := range recipients {
			recipients[i] = algocrypto.GenerateAccount().Address.String()
		}
		account := newGeneralAccount(t, provider, shape, recipients)
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
			account := newGeneralAccount(t, provider, shape, recipients)
			if err := funder.FundMicroAlgosAndWait(account.address, 500_000); err != nil {
				t.Fatalf("fund account: %v", err)
			}
			cleanup := algocrypto.GenerateAccount()
			t.Cleanup(func() {
				if shape.Rekey == boundedaccount.RekeyAdminKey {
					bestEffortCorridorAdminRekey(t, network, account, cleanup.Address)
				} else {
					txn := corridorPaymentTxn(t, mustSuggestedParams(t, network), account.address, account.address, 0, "general-cleanup-rekey")
					txn.RekeyTo = cleanup.Address
					raw, txid := account.signGroup(t, txn, nil, nil)
					submitCorridorGroupExpectSuccess(t, network, raw, txid)
				}
				bestEffortCloseRekeyedAccount(t, network, account.address, funder.GetAddress(), cleanup.PrivateKey)
			})
			var proof []byte
			if shape.Encoding == boundedaccount.EncodingMerkle {
				proof = account.proofFor(t, funderAddress)
			}
			sp := mustSuggestedParams(t, network)
			spend, _ := account.signedGroup(t, corridorPaymentTxn(t, sp, account.address, funder.GetAddress(), 0, "general-opcode-spend"), proof, nil)
			rekeyTxn := corridorPaymentTxn(t, sp, account.address, account.address, 0, "general-opcode-rekey")
			rekeyTxn.RekeyTo = cleanup.Address
			path := lsigresource.PathSpendingRekey
			var mutate func(types.Digest, [][]byte) [][]byte
			if shape.Rekey == boundedaccount.RekeyAdminKey {
				path = lsigresource.PathAdminRekey
				mutate = func(txid types.Digest, args [][]byte) [][]byte { return account.adminRekeyArgs(t, args[0], txid) }
			}
			rekey, _ := account.signedGroup(t, rekeyTxn, nil, mutate)
			report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), compiler, harness.OpcodeCeilingValidation{
				Name:          shape.Descriptor(),
				FinalProgram:  account.bytecode,
				Profile:       provider.LogicSigOpcodeProfile(),
				Bounded:       true,
				RequiredPaths: []lsigresource.AuthorizationPath{lsigresource.PathSpend, path},
				Vectors: []harness.OpcodeCeilingVector{
					{Name: "maximum-spend", Path: lsigresource.PathSpend, SignedTxns: spend, LSigIndex: 0},
					{Name: "maximum-rekey", Path: path, SignedTxns: rekey, LSigIndex: 0},
				},
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

// This is the account as an operator gets it: the signer generates it after the
// grammar is approved, assembles its arguments, and rescans it after a restart.
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
	if _, err := client.AdminGenerate(boundedaccount.KeyTypeV1, request(funder.GetAddress())); err == nil {
		t.Fatal("generated before the grammar was approved")
	}
	if err := apadmin.ActivateKeyType(boundedaccount.KeyTypeV1); err != nil {
		t.Fatalf("approve grammar: %v", err)
	}

	adminPublicKey, _, err := signerops.New(nil).GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate admin key: %v", err)
	}
	accounts := make(map[string]string)
	for _, test := range []struct {
		name       string
		recipients int
		policy     string
		adminKey   bool
	}{
		{name: "inline", recipients: 2, policy: composeddsa.Layer3PolicyFixedAllowlist},
		{name: "auto chooses merkle above ten", recipients: 11, policy: composeddsa.Layer3PolicyMerkleAllowlist},
		{name: "admin key rekey", recipients: 2, policy: composeddsa.Layer3PolicyFixedAllowlist, adminKey: true},
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
			if test.adminKey {
				params[boundedaccount.ParameterRekeyAuthority] = boundedaccount.RekeyAdminKey
				params[composeddsa.BoundedAdminPublicKeyParameter] = hex.EncodeToString(adminPublicKey)
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
		})
	}

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
