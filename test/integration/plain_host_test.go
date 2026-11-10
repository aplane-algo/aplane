// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	stded25519 "crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signing"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/lsig/plainhost"
	"github.com/aplane-algo/aplane/pkg/signerapi"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

const (
	plainFalconKeyType  = "aplane.falcon1024.v1"
	plainEd25519KeyType = "aplane.ed25519.v1"
)

// plainHostAccount is a plain host built with test-held keys, as the signer
// generates one. Its spending key is Falcon-1024 or, with edKey set, Ed25519.
type plainHostAccount struct {
	corridorExecutionAccount
}

func plainHostProvider(t *testing.T, network *harness.TestnetConfig, keyType string) *plainhost.Provider {
	t.Helper()
	falcon1024.RegisterClient()
	ed25519lsig.RegisterClient()
	provider, ok := lsigprovider.Get(keyType).(*plainhost.Provider)
	if !ok {
		t.Fatalf("%s is not a plain host", keyType)
	}
	provider.SetAlgodClient(network.Client)
	return provider
}

// newSpendingKey generates a plain host's spending key: Ed25519 on the Ed25519
// host, returned as edKey too, and Falcon-1024 otherwise.
func newSpendingKey(t *testing.T, keyType string) ([]byte, []byte, stded25519.PrivateKey) {
	t.Helper()
	if keyType == plainEd25519KeyType {
		public, private, err := stded25519.GenerateKey(cryptorand.Reader)
		if err != nil {
			t.Fatalf("generate Ed25519 spending key: %v", err)
		}
		return public, private, private
	}
	public, private, err := signerops.New(nil).GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate Falcon spending key: %v", err)
	}
	return public, private, nil
}

func listedArrangement(arrangement plainhost.Arrangement) bool {
	return arrangement.Rekey == plainhost.RekeyOnlyThese || arrangement.Rekey == plainhost.RekeyPlusCosigned
}

// newPlainHostAccount generates a plain host as the signer does: resolve the
// request, add the rekey-to list's root, derive the program, and snapshot the
// contract.
func newPlainHostAccount(t *testing.T, network *harness.TestnetConfig, keyType string, arrangement plainhost.Arrangement, rekeyTo []string) plainHostAccount {
	t.Helper()
	provider := plainHostProvider(t, network, keyType)
	var account plainHostAccount
	spendingPublic, spendingPrivate, edKey := newSpendingKey(t, keyType)
	account.edKey = edKey
	params := map[string]string{plainhost.ParameterRekeyAuthority: arrangement.Rekey}
	if arrangement.Cosigner {
		cosignerPublic, cosignerPrivate, err := signerops.New(nil).GenerateKeypair(randomFalconSeed(t))
		if err != nil {
			t.Fatalf("generate cosigner key: %v", err)
		}
		params[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(cosignerPublic)
		account.cosignerPrivateKey = cosignerPrivate
	}
	if listedArrangement(arrangement) {
		params[plainhost.ParameterRekeyTo] = strings.Join(rekeyTo, ",")
	}
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
	if metadata.Contract != boundedmeta.PlainContract || (metadata.Cosigner != nil) != arrangement.Cosigner {
		t.Fatalf("metadata = %+v", metadata)
	}
	account.address = derived.Address.String()
	account.bytecode = derived.Bytecode
	account.userPrivateKey = spendingPrivate
	account.metadata = metadata
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

// signGroup signs one transaction from the plain host in a budget group, as
// corridorExecutionAccount.signGroup does, with this account's spending key.
// A rekey to a listed target carries its list proof; the cosigner signs when
// the account has one.
func (a plainHostAccount) signGroup(t *testing.T, target types.Transaction, mutateArgs func([][]byte) [][]byte) ([]byte, string) {
	t.Helper()
	minFee := uint64(1_000)
	target.Fee = types.MicroAlgos(uint64(corridorExecutionGroupSize) * minFee)
	dummies, err := signing.CreateDummyTransactions(corridorExecutionGroupSize-1, types.SuggestedParams{
		Fee: types.MicroAlgos(minFee), GenesisID: target.GenesisID, GenesisHash: target.GenesisHash[:],
		FirstRoundValid: target.FirstValid, LastRoundValid: target.LastValid, FlatFee: true,
	})
	if err != nil {
		t.Fatalf("build dummies: %v", err)
	}
	groupID, err := algocrypto.ComputeGroupID(append([]types.Transaction{target}, dummies...))
	if err != nil {
		t.Fatalf("compute group ID: %v", err)
	}
	target.Group = groupID
	for i := range dummies {
		dummies[i].Group = groupID
	}
	var txid types.Digest
	copy(txid[:], algocrypto.TransactionID(target))
	var cosignerSignature []byte
	if a.cosignerPrivateKey != nil {
		cosignerSignature = a.signComponent(t, message.RoleCosigner, txid, a.cosignerPrivateKey)
	}
	args := a.spendArgs(t, a.signBase(t, txid[:]), nil, a.listProof(target.RekeyTo), cosignerSignature)
	if mutateArgs != nil {
		args = mutateArgs(args)
	}
	_, signedTarget, err := algocrypto.SignLogicSigAccountTransaction(algocrypto.LogicSigAccount{Lsig: types.LogicSig{
		Logic: append([]byte(nil), a.bytecode...), Args: args,
	}}, target)
	if err != nil {
		t.Fatalf("sign target: %v", err)
	}
	signedDummies, err := signing.SignDummyTransactions(dummies)
	if err != nil {
		t.Fatalf("sign dummies: %v", err)
	}
	raw := append([]byte(nil), signedTarget...)
	for _, dummy := range signedDummies {
		raw = append(raw, dummy...)
	}
	return raw, algocrypto.GetTxID(target)
}

// withoutCosignerSlot empties the cosigner's slot, which a listed rekey never
// reads and every other cosigned path requires. It is a no-op without one.
func (a plainHostAccount) withoutCosignerSlot(t *testing.T) func([][]byte) [][]byte {
	return func(args [][]byte) [][]byte {
		if a.metadata.Cosigner == nil {
			return args
		}
		return withArg(args, a.argumentIndex(t, boundedmeta.ArgSourceCosigner), nil)
	}
}

// handBack rekeys an account back to its own program from the native key that
// holds it now.
func handBack(t *testing.T, network *harness.TestnetConfig, account string, holder algocrypto.Account) {
	t.Helper()
	back := corridorPaymentTxn(t, mustSuggestedParams(t, network), account, account, 0, "plain-host-hand-back-"+holder.Address.String()[:6])
	back.RekeyTo = mustDecodeAddress(t, account)
	submitEd25519TxnExpectSuccess(t, network, holder.PrivateKey, back)
	if got := authAddress(t, network, account); got != "" {
		t.Fatalf("authorizer = %q after the hand-back", got)
	}
}

// Every plain host arrangement runs its own program on the network, with
// test-held keys and straight to algod: a plain host spends any transaction
// type, closes and clawback included, with no fee ceiling and with the cosigner
// when it has one, and a rekey passes only as a pure rekey on the paths its
// arrangement gives.
func TestPlainHostArrangementsOnChainLocalnet(t *testing.T) {
	if harness.IntegrationNetwork() != harness.IntegrationNetworkLocalnet {
		t.Skip("plain host LogicSig execution requires localnet")
	}
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to localnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("load funding account: %v", err)
	}
	assetID := corridorTestAssetID(t, network, funder)

	type plainCase struct {
		keyType     string
		arrangement plainhost.Arrangement
		// extras exercises the other transaction types once: an offline key
		// registration, an asset the account creates and claws back, and an app.
		extras bool
	}
	var cases []plainCase
	for _, arrangement := range plainhost.Arrangements() {
		cases = append(cases, plainCase{plainFalconKeyType, arrangement,
			arrangement == plainhost.Arrangement{Rekey: plainhost.RekeySpendingKey, Cosigner: true}})
	}
	cases = append(cases,
		plainCase{plainEd25519KeyType, plainhost.Arrangement{Rekey: plainhost.RekeySpendingKey, Cosigner: true}, true},
		plainCase{plainEd25519KeyType, plainhost.Arrangement{Rekey: plainhost.RekeyOnlyThese}, false},
	)

	for _, tc := range cases {
		name := fmt.Sprintf("%s/%s/cosigner=%v", tc.keyType, tc.arrangement.Rekey, tc.arrangement.Cosigner)
		t.Run(name, func(t *testing.T) {
			listed := algocrypto.GenerateAccount()
			otherListed := algocrypto.GenerateAccount()
			unlisted := algocrypto.GenerateAccount()
			account := newPlainHostAccount(t, network, tc.keyType, tc.arrangement,
				[]string{listed.Address.String(), otherListed.Address.String()})
			funding := uint64(1_000_000)
			if tc.extras {
				funding = 2_000_000
			}
			if err := funder.FundMicroAlgosAndWait(account.address, funding); err != nil {
				t.Fatalf("fund account: %v", err)
			}
			cosigned := tc.arrangement.Cosigner
			t.Cleanup(func() {
				info, err := network.Client.AccountInformation(account.address).Do(context.Background())
				if err != nil || info.Amount == 0 {
					return
				}
				for _, holder := range []algocrypto.Account{listed, unlisted} {
					if info.AuthAddr == holder.Address.String() {
						bestEffortCloseBoundedAsset(t, network, account.address, funder.GetAddress(), assetID, holder.PrivateKey)
						bestEffortCloseRekeyedAccount(t, network, account.address, funder.GetAddress(), holder.PrivateKey)
						return
					}
				}
				if info.AuthAddr == "" {
					closeOut := corridorPaymentTxn(t, mustSuggestedParams(t, network), account.address, funder.GetAddress(), 0, "plain-host-cleanup")
					mustSetAddress(t, &closeOut.CloseRemainderTo, funder.GetAddress())
					raw, txid := account.signGroup(t, closeOut, nil)
					if _, err := network.Client.SendRawTransaction(raw).Do(context.Background()); err == nil {
						_, _ = network.WaitForConfirmation(txid, 10)
					}
				}
			})
			submit := func(accepted bool, txn types.Transaction, mutate func([][]byte) [][]byte) string {
				t.Helper()
				raw, txid := account.signGroup(t, txn, mutate)
				if accepted {
					submitCorridorGroupExpectSuccess(t, network, raw, txid)
				} else {
					submitCorridorGroupExpectFailure(t, network, raw)
				}
				return txid
			}
			payment := func(to string, amount uint64, note string) types.Transaction {
				return corridorPaymentTxn(t, mustSuggestedParams(t, network), account.address, to, amount, note)
			}
			transfer := func(to string, amount, asset uint64, note string) types.Transaction {
				return corridorAssetTransferTxn(t, mustSuggestedParams(t, network), account.address, to, amount, asset, note)
			}
			rekeyTo := func(target types.Address, note string) types.Transaction {
				txn := payment(account.address, 0, note)
				txn.RekeyTo = target
				return txn
			}
			withoutCosigner := account.withoutCosignerSlot(t)

			t.Run("payment", func(t *testing.T) { submit(true, payment(funder.GetAddress(), 10_000, "a"), nil) })
			if cosigned {
				t.Run("payment without the cosigner", func(t *testing.T) {
					submit(false, payment(funder.GetAddress(), 10_000, "b"), withoutCosigner)
				})
				t.Run("payment with a wrong cosigner signature", func(t *testing.T) {
					slot := account.argumentIndex(t, boundedmeta.ArgSourceCosigner)
					submit(false, payment(funder.GetAddress(), 10_000, "b2"), func(args [][]byte) [][]byte {
						args[slot] = append([]byte(nil), args[slot]...)
						args[slot][len(args[slot])/2] ^= 0xff
						return args
					})
				})
			}
			t.Run("wrong spending signature", func(t *testing.T) {
				submit(false, payment(funder.GetAddress(), 10_000, "c"), func(args [][]byte) [][]byte {
					args[0] = append([]byte(nil), args[0]...)
					args[0][len(args[0])/2] ^= 0xff
					return args
				})
			})
			t.Run("asset opt-in, transfer and asset close-out", func(t *testing.T) {
				submit(true, transfer(account.address, 0, assetID, "d"), nil)
				sendAssetFromFunder(t, network, funder, account.address, assetID, 1)
				submit(true, transfer(funder.GetAddress(), 1, assetID, "e"), nil)
				closeOut := transfer(funder.GetAddress(), 0, assetID, "f")
				mustSetAddress(t, &closeOut.AssetCloseTo, funder.GetAddress())
				submit(true, closeOut, nil)
			})
			if tc.extras {
				t.Run("offline key registration", func(t *testing.T) {
					txn := payment(account.address, 0, "g")
					txn.Type = types.KeyRegistrationTx
					txn.PaymentTxnFields = types.PaymentTxnFields{}
					submit(true, txn, nil)
				})
				t.Run("asset creation, clawback and destruction", func(t *testing.T) {
					sp := mustSuggestedParams(t, network)
					create, err := transaction.MakeAssetCreateTxn(account.address, []byte("plain-host-asset"), sp, 1, 0, false,
						account.address, "", "", account.address, "PLNH", "Plain host clawback", "", "")
					if err != nil {
						t.Fatal(err)
					}
					txid := submit(true, create, nil)
					pending, _, err := network.Client.PendingTransactionInformation(txid).Do(context.Background())
					if err != nil || pending.AssetIndex == 0 {
						t.Fatalf("created asset = %d, %v", pending.AssetIndex, err)
					}
					created := pending.AssetIndex
					holder := algocrypto.GenerateAccount()
					if err := funder.FundMicroAlgosAndWait(holder.Address.String(), 300_000); err != nil {
						t.Fatalf("fund holder: %v", err)
					}
					t.Cleanup(func() {
						bestEffortCloseRekeyedAccount(t, network, holder.Address.String(), funder.GetAddress(), holder.PrivateKey)
					})
					submitEd25519TxnExpectSuccess(t, network, holder.PrivateKey,
						corridorAssetTransferTxn(t, sp, holder.Address.String(), holder.Address.String(), 0, created, "plain-host-holder-optin"))
					submit(true, transfer(holder.Address.String(), 1, created, "h"), nil)
					revoke, err := transaction.MakeAssetRevocationTxn(account.address, holder.Address.String(), 1, account.address,
						[]byte("plain-host-clawback"), mustSuggestedParams(t, network), created)
					if err != nil {
						t.Fatal(err)
					}
					submit(true, revoke, nil)
					holderClose := corridorAssetTransferTxn(t, mustSuggestedParams(t, network), holder.Address.String(), account.address, 0, created, "plain-host-holder-close")
					mustSetAddress(t, &holderClose.AssetCloseTo, account.address)
					submitEd25519TxnExpectSuccess(t, network, holder.PrivateKey, holderClose)
					destroy, err := transaction.MakeAssetDestroyTxn(account.address, []byte("plain-host-destroy"), mustSuggestedParams(t, network), created)
					if err != nil {
						t.Fatal(err)
					}
					submit(true, destroy, nil)
				})
				t.Run("app creation and deletion", func(t *testing.T) {
					program := func() []byte {
						compiled, err := network.Client.TealCompile([]byte("#pragma version 10\npushint 1\n")).Do(context.Background())
						if err != nil {
							t.Fatalf("compile app program: %v", err)
						}
						decoded, err := base64.StdEncoding.DecodeString(compiled.Result)
						if err != nil {
							t.Fatal(err)
						}
						return decoded
					}
					sender := mustDecodeAddress(t, account.address)
					create, err := transaction.MakeApplicationCreateTx(false, program(), program(), types.StateSchema{}, types.StateSchema{},
						nil, nil, nil, nil, mustSuggestedParams(t, network), sender, []byte("plain-host-app"), types.Digest{}, [32]byte{}, types.ZeroAddress)
					if err != nil {
						t.Fatal(err)
					}
					txid := submit(true, create, nil)
					pending, _, err := network.Client.PendingTransactionInformation(txid).Do(context.Background())
					if err != nil || pending.ApplicationIndex == 0 {
						t.Fatalf("created app = %d, %v", pending.ApplicationIndex, err)
					}
					remove, err := transaction.MakeApplicationDeleteTx(pending.ApplicationIndex, nil, nil, nil, nil,
						mustSuggestedParams(t, network), sender, []byte("plain-host-app-delete"), types.Digest{}, [32]byte{}, types.ZeroAddress)
					if err != nil {
						t.Fatal(err)
					}
					submit(true, remove, nil)
				})
			}

			// A rekey passes only as a pure rekey, whatever the arrangement.
			t.Run("rekey with an amount", func(t *testing.T) {
				txn := rekeyTo(listed.Address, "i")
				txn.Amount = 1
				submit(false, txn, nil)
			})
			t.Run("rekey with a close", func(t *testing.T) {
				txn := rekeyTo(listed.Address, "j")
				mustSetAddress(t, &txn.CloseRemainderTo, funder.GetAddress())
				submit(false, txn, nil)
			})
			switch tc.arrangement.Rekey {
			case plainhost.RekeyRefused:
				t.Run("rekey refused", func(t *testing.T) { submit(false, rekeyTo(listed.Address, "k"), nil) })
			case plainhost.RekeySpendingKey:
				if cosigned {
					t.Run("rekey without the cosigner", func(t *testing.T) { submit(false, rekeyTo(listed.Address, "k"), withoutCosigner) })
				}
				t.Run("rekey with the spending key", func(t *testing.T) {
					submit(true, rekeyTo(listed.Address, "l"), nil)
					handBack(t, network, account.address, listed)
				})
			case plainhost.RekeyOnlyThese:
				t.Run("rekey to an unlisted address", func(t *testing.T) { submit(false, rekeyTo(unlisted.Address, "k"), nil) })
				t.Run("listed rekey with the spending key alone", func(t *testing.T) {
					submit(true, rekeyTo(listed.Address, "l"), withoutCosigner)
					handBack(t, network, account.address, listed)
				})
			case plainhost.RekeyPlusCosigned:
				t.Run("unlisted rekey without the cosigner", func(t *testing.T) {
					submit(false, rekeyTo(unlisted.Address, "k"), withoutCosigner)
				})
				t.Run("cosigned rekey to an unlisted address", func(t *testing.T) {
					submit(true, rekeyTo(unlisted.Address, "l"), nil)
					handBack(t, network, account.address, unlisted)
				})
				t.Run("listed rekey with the spending key alone", func(t *testing.T) {
					submit(true, rekeyTo(listed.Address, "m"), withoutCosigner)
					handBack(t, network, account.address, listed)
				})
			}

			t.Run("close", func(t *testing.T) {
				closeOut := payment(funder.GetAddress(), 0, "n")
				mustSetAddress(t, &closeOut.CloseRemainderTo, funder.GetAddress())
				submit(true, closeOut, nil)
				info, err := network.Client.AccountInformation(account.address).Do(context.Background())
				if err != nil || info.Amount != 0 {
					t.Fatalf("after the close the account holds %d, %v", info.Amount, err)
				}
			})
		})
	}
}

// activatePlainHosts enables the opt-in plain host, Ed25519, on the node's
// signer, as an operator does before generating one. The Falcon host is enabled
// by default and takes no activation.
func activatePlainHosts(t *testing.T, n *cosignedNode) {
	t.Helper()
	if result := activateKeyType(t, n, plainEd25519KeyType); !result.Success {
		t.Fatalf("activate %s: %+v", plainEd25519KeyType, result)
	}
}

// activateKeyType asks the node's signer to activate keyType and returns its answer.
func activateKeyType(t *testing.T, n *cosignedNode, keyType string) protocol.ActivateKeyTypeResultMessage {
	t.Helper()
	ipc := mustConnectIPCClient(t, n.signerd.GetWorkDir())
	defer ipc.Close()
	response, err := ipc.SendAndReceive(protocol.ActivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeActivateKeyType, ID: fmt.Sprintf("activate-%d", time.Now().UnixNano())},
		KeyType:     keyType,
	}, 30*time.Second)
	if err != nil {
		t.Fatalf("activate %s: %v", keyType, err)
	}
	var result protocol.ActivateKeyTypeResultMessage
	if err := json.Unmarshal(response, &result); err != nil {
		t.Fatalf("activate %s: %v", keyType, err)
	}
	return result
}

// generatePlainHost generates and funds a plain host through the signer and
// waits until the signer serves it.
func generatePlainHost(t *testing.T, n *cosignedNode, keyType string, params map[string]string) string {
	t.Helper()
	resp, err := n.client.AdminGenerate(keyType, params)
	if err != nil || resp.Address == "" {
		t.Fatalf("generate: %+v, %v", resp, err)
	}
	if !waitForKey(t, n.signerd.GetURL(), resp.Address, 10*time.Second) {
		t.Fatalf("signer did not reload %s", resp.Address)
	}
	if err := n.funder.FundMicroAlgosAndWait(resp.Address, 1_000_000); err != nil {
		t.Fatalf("fund %s: %v", resp.Address, err)
	}
	return resp.Address
}

// A cosigned plain host and an ordinary signer-held LogicSig account sign in one
// atomic group: the cosigned flow plans the budget over both LogicSigs, asks
// the cosigner for the plain host's position only, signs the other position
// through /sign over the frozen bytes, assembles, and the group confirms.
func TestPlainHostMixedGroupThroughSigner(t *testing.T) {
	n := newCosignedNode(t)
	activatePlainHosts(t, n)
	cosigned := generatePlainHost(t, n, plainFalconKeyType, map[string]string{
		cosignerrefs.ParamCosignerName: cosignedReferenceName, plainhost.ParameterRekeyAuthority: plainhost.RekeySpendingKey,
	})
	ordinary := generatePlainHost(t, n, plainFalconKeyType, nil)
	if err := n.eng.EnsureSignerCache(context.Background()); err != nil {
		t.Fatalf("refresh signer cache: %v", err)
	}
	sp, err := n.network.GetSuggestedParams()
	if err != nil {
		t.Fatalf("suggested params: %v", err)
	}
	first, err := transaction.MakePaymentTxn(cosigned, ordinary, 10_000, []byte("mixed-cosigned"), "", sp)
	if err != nil {
		t.Fatal(err)
	}
	second, err := transaction.MakePaymentTxn(ordinary, cosigned, 20_000, []byte("mixed-ordinary"), "", sp)
	if err != nil {
		t.Fatal(err)
	}
	before := n.cosignerCalls.Load()
	result, err := n.eng.SignAndSubmitTransactions(context.Background(), []types.Transaction{first, second}, true)
	if err != nil {
		output := ""
		if result != nil {
			output = result.Output
		}
		t.Fatalf("mixed group: %v\n%s", err, output)
	}
	if !result.Confirmed || len(result.TxIDs) < 2 {
		t.Fatalf("mixed group: confirmed %v with %d txids", result.Confirmed, len(result.TxIDs))
	}
	if asked := n.cosignerCalls.Load() - before; asked != 1 {
		t.Fatalf("the cosigner was asked %d times, want once for the plain host's position", asked)
	}
	for _, address := range []string{cosigned, ordinary} {
		info, err := n.network.Client.AccountInformation(address).Do(context.Background())
		if err != nil || info.Amount == 1_000_000 {
			t.Fatalf("%s holds %d after the group, %v", address, info.Amount, err)
		}
	}
}

// A cosigned group follows the planner's ordinary rule for who pays the
// signer's authorization charge: a native Falcon position the signer holds
// takes it, ahead of any LogicSig account. The cosigned account's fee is not
// raised. The Falcon position used to be sent to the planner as foreign, which
// left the cosigned account as the only one that could pay (audit #10).
func TestCosignedGroupChargesTheNativeFalconPosition(t *testing.T) {
	// apshell registers the native Falcon client metadata at startup
	// (internal/apshellcli/providers.go); this engine is built without it.
	nativefalcon.RegisterClient()
	n := newCosignedNode(t)
	activatePlainHosts(t, n)
	cosigned := generatePlainHost(t, n, plainFalconKeyType, map[string]string{
		cosignerrefs.ParamCosignerName: cosignedReferenceName, plainhost.ParameterRekeyAuthority: plainhost.RekeySpendingKey,
	})
	falcon := generatePlainHost(t, n, nativefalcon.KeyType, nil)
	if err := n.eng.EnsureSignerCache(context.Background()); err != nil {
		t.Fatalf("refresh signer cache: %v", err)
	}
	sp, err := n.network.GetSuggestedParams()
	if err != nil {
		t.Fatalf("suggested params: %v", err)
	}
	first, err := transaction.MakePaymentTxn(cosigned, falcon, 10_000, []byte("cosigned-with-falcon"), "", sp)
	if err != nil {
		t.Fatal(err)
	}
	second, err := transaction.MakePaymentTxn(falcon, cosigned, 20_000, []byte("falcon-with-cosigned"), "", sp)
	if err != nil {
		t.Fatal(err)
	}
	result, err := n.eng.SignAndSubmitTransactions(context.Background(), []types.Transaction{first, second}, true)
	if err != nil {
		output := ""
		if result != nil {
			output = result.Output
		}
		t.Fatalf("cosigned group with a native Falcon position: %v\n%s", err, output)
	}
	if !result.Confirmed || len(result.TxIDs) < 2 {
		t.Fatalf("group: confirmed %v with %d txids", result.Confirmed, len(result.TxIDs))
	}
	fees := make([]types.MicroAlgos, 2)
	for i, want := range []string{cosigned, falcon} {
		info, _, err := n.network.Client.PendingTransactionInformation(result.TxIDs[i]).Do(context.Background())
		if err != nil {
			t.Fatalf("read position %d: %v", i+1, err)
		}
		if got := info.Transaction.Txn.Sender.String(); got != want {
			t.Fatalf("position %d sender = %s, want %s", i+1, got, want)
		}
		fees[i] = info.Transaction.Txn.Fee
	}
	if fees[0] != first.Fee {
		t.Fatalf("cosigned position paid %d microAlgos, want its own %d: the charge belongs on the Falcon position", fees[0], first.Fee)
	}
	if fees[1] < second.Fee+2_000 {
		t.Fatalf("native Falcon position paid %d microAlgos, want at least %d: its fee plus its Falcon contribution", fees[1], second.Fee+2_000)
	}
}

// A cosigned plain host has no type list in its program, so any transaction
// type that isn't a rekey takes the cosigned spend path. An offline keyreg, a
// type transfer routing doesn't govern, signs through the signer and the
// cosigner and confirms. This is what lets a cosigner policy allow any type
// (restrictions C1).
func TestCosignedPlainHostSignsANonTransferType(t *testing.T) {
	n := newCosignedNode(t)
	activatePlainHosts(t, n)
	cosigned := generatePlainHost(t, n, plainFalconKeyType, map[string]string{
		cosignerrefs.ParamCosignerName: cosignedReferenceName, plainhost.ParameterRekeyAuthority: plainhost.RekeySpendingKey,
	})
	if err := n.eng.EnsureSignerCache(context.Background()); err != nil {
		t.Fatalf("refresh signer cache: %v", err)
	}
	sp, err := n.network.GetSuggestedParams()
	if err != nil {
		t.Fatalf("suggested params: %v", err)
	}
	keyreg, err := transaction.MakeKeyRegTxnWithStateProofKey(cosigned, []byte("cosigned-offline-keyreg"), sp, "", "", "", 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	before := n.cosignerCalls.Load()
	result, err := n.eng.SignAndSubmitTransactions(context.Background(), []types.Transaction{keyreg}, true)
	if err != nil {
		output := ""
		if result != nil {
			output = result.Output
		}
		t.Fatalf("cosigned offline keyreg: %v\n%s", err, output)
	}
	if !result.Confirmed {
		t.Fatal("cosigned offline keyreg did not confirm")
	}
	if asked := n.cosignerCalls.Load() - before; asked != 1 {
		t.Fatalf("the cosigner was asked %d times, want once", asked)
	}
}

// Plain hosts created and spent through the signer: a cosigned one, on Falcon
// and on Ed25519, signs through the cosigned flow and asks the cosigner; one
// without a cosigner and the plain program sign through /sign and never ask it.
// Each pays and then closes out.
func TestPlainHostThroughSigner(t *testing.T) {
	n := newCosignedNode(t)
	// The Falcon host is enabled by default; it is not a library key type, so it
	// can't be activated as one.
	t.Run("the Falcon host is enabled by default", func(t *testing.T) {
		result := activateKeyType(t, n, plainFalconKeyType)
		if result.Success || !strings.Contains(result.Error, "is not library-visible") {
			t.Fatalf("activate %s: %+v, want the not-library-visible refusal", plainFalconKeyType, result)
		}
		keyTypes, err := n.client.GetKeyTypes()
		if err != nil {
			t.Fatalf("list key types: %v", err)
		}
		enabled := false
		for _, info := range keyTypes.KeyTypes {
			enabled = enabled || info.KeyType == plainFalconKeyType
		}
		if !enabled {
			t.Fatalf("%s is not enabled by default", plainFalconKeyType)
		}
	})
	activatePlainHosts(t, n)

	for _, tc := range []struct {
		name     string
		keyType  string
		params   map[string]string
		flow     string
		cosigned bool
	}{
		{"cosigned plain host on Falcon", plainFalconKeyType, map[string]string{
			cosignerrefs.ParamCosignerName: cosignedReferenceName, plainhost.ParameterRekeyAuthority: plainhost.RekeySpendingKey,
		}, signerapi.SigningFlowCosigned1, true},
		{"cosigned plain host on Ed25519", plainEd25519KeyType, map[string]string{
			cosignerrefs.ParamCosignerName: cosignedReferenceName, plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused,
		}, signerapi.SigningFlowCosigned1, true},
		{"plain host without a cosigner", plainFalconKeyType, map[string]string{
			plainhost.ParameterRekeyAuthority: plainhost.RekeyOnlyThese, plainhost.ParameterRekeyTo: algocrypto.GenerateAccount().Address.String(),
		}, signerapi.SigningFlowBounded1, false},
		{"the plain program", plainFalconKeyType, nil, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := n.client.AdminGenerate(tc.keyType, tc.params)
			if err != nil || resp.Address == "" {
				t.Fatalf("generate: %+v, %v", resp, err)
			}
			address := resp.Address
			if !waitForKey(t, n.signerd.GetURL(), address, 10*time.Second) {
				t.Fatalf("signer did not reload %s", address)
			}
			if err := n.funder.FundMicroAlgosAndWait(address, 1_000_000); err != nil {
				t.Fatalf("fund %s: %v", address, err)
			}
			keys, err := n.client.GetKeysWithContext(context.Background())
			if err != nil {
				t.Fatalf("read keys: %v", err)
			}
			found := false
			for _, key := range keys.Keys {
				if key.Address != address {
					continue
				}
				found = true
				if key.SigningFlow != tc.flow {
					t.Fatalf("signing flow = %q, want %q", key.SigningFlow, tc.flow)
				}
				switch {
				case tc.params == nil && key.BoundedAuthorization != nil:
					t.Fatalf("the plain program has a contract: %+v", key.BoundedAuthorization)
				case tc.params != nil && (key.BoundedAuthorization == nil || key.BoundedAuthorization.Contract != signerapi.BoundedContractPlain1 ||
					key.BoundedAuthorization.MaxFee != nil):
					t.Fatalf("contract = %+v, want plain1 with no fee ceiling", key.BoundedAuthorization)
				}
			}
			if !found {
				t.Fatalf("%s is not in /keys", address)
			}
			if err := n.eng.EnsureSignerCache(context.Background()); err != nil {
				t.Fatalf("refresh signer cache: %v", err)
			}
			sp, err := n.network.GetSuggestedParams()
			if err != nil {
				t.Fatalf("suggested params: %v", err)
			}
			spend, err := transaction.MakePaymentTxn(address, n.funder.GetAddress(), 10_000, []byte("plain-host-spend"), "", sp)
			if err != nil {
				t.Fatal(err)
			}
			before := n.cosignerCalls.Load()
			if err := n.submit(t, spend); err != nil {
				t.Fatalf("payment: %v", err)
			}
			if asked := n.cosignerCalls.Load() != before; asked != tc.cosigned {
				t.Fatalf("payment asked the cosigner: %v, want %v", asked, tc.cosigned)
			}
			closeOut, err := transaction.MakePaymentTxn(address, n.funder.GetAddress(), 0, []byte("plain-host-close"), n.funder.GetAddress(), sp)
			if err != nil {
				t.Fatal(err)
			}
			before = n.cosignerCalls.Load()
			if err := n.submit(t, closeOut); err != nil {
				t.Fatalf("close: %v", err)
			}
			if asked := n.cosignerCalls.Load() != before; asked != tc.cosigned {
				t.Fatalf("close asked the cosigner: %v, want %v", asked, tc.cosigned)
			}
			info, err := n.network.Client.AccountInformation(address).Do(context.Background())
			if err != nil || info.Amount != 0 {
				t.Fatalf("after the close %s holds %d, %v", address, info.Amount, err)
			}
		})
	}
}

// meshMember is a native account rekeyed to a bounded program, and the key its
// program lists as its way out.
type meshMember struct {
	key     algocrypto.Account
	program corridorExecutionAccount
	listed  algocrypto.Account
}

func (m meshMember) address() string { return m.key.Address.String() }

// pay signs a payment from the member through program, the member's
// authorizer, as a rekeyed account's LogicSig: Sender is the member and
// AuthAddr the program.
func meshPayment(t *testing.T, network *harness.TestnetConfig, member string, program corridorExecutionAccount, to string, note string) ([]byte, string) {
	t.Helper()
	txn := corridorPaymentTxn(t, mustSuggestedParams(t, network), member, to, 10_000, note)
	return program.signGroup(t, txn, nil, nil)
}

// meshHandOver hands member to its listed key and, in the same atomic group,
// has that key rekey it onto next: the listed rekey through the current
// program, then a rekey signed by the listed key, which holds the account once
// the first transaction applies. The member keeps its address throughout.
func meshHandOver(t *testing.T, network *harness.TestnetConfig, member string, current corridorExecutionAccount, listed algocrypto.Account, next string) {
	t.Helper()
	sp := mustSuggestedParams(t, network)
	handover := corridorPaymentTxn(t, sp, member, member, 0, "mesh-handover")
	handover.RekeyTo = listed.Address
	reprogram := corridorPaymentTxn(t, sp, member, member, 0, "mesh-reprogram")
	reprogram.RekeyTo = mustDecodeAddress(t, next)
	reprogram.Fee = 0
	handover.Fee = types.MicroAlgos(uint64(corridorExecutionGroupSize) * 1_000)
	dummies, err := signing.CreateDummyTransactions(corridorExecutionGroupSize-2, types.SuggestedParams{
		Fee: 1_000, GenesisID: handover.GenesisID, GenesisHash: handover.GenesisHash[:],
		FirstRoundValid: handover.FirstValid, LastRoundValid: handover.LastValid, FlatFee: true,
	})
	if err != nil {
		t.Fatalf("build dummies: %v", err)
	}
	all := append([]types.Transaction{handover, reprogram}, dummies...)
	groupID, err := algocrypto.ComputeGroupID(all)
	if err != nil {
		t.Fatalf("compute group ID: %v", err)
	}
	handover.Group, reprogram.Group = groupID, groupID
	for i := range dummies {
		dummies[i].Group = groupID
	}
	var txid types.Digest
	copy(txid[:], algocrypto.TransactionID(handover))
	base, err := signerops.New(nil).Sign(current.userPrivateKey, txid[:])
	if err != nil {
		t.Fatalf("sign handover: %v", err)
	}
	args := current.spendArgs(t, base, nil, current.listProof(listed.Address), nil)
	_, signedHandover, err := algocrypto.SignLogicSigAccountTransaction(algocrypto.LogicSigAccount{Lsig: types.LogicSig{
		Logic: append([]byte(nil), current.bytecode...), Args: args,
	}}, handover)
	if err != nil {
		t.Fatalf("sign handover: %v", err)
	}
	_, signedReprogram, err := signing.SignTransactionWithKey(listed.PrivateKey, reprogram)
	if err != nil {
		t.Fatalf("sign reprogram: %v", err)
	}
	var check types.SignedTxn
	if err := msgpack.Decode(signedReprogram, &check); err != nil || check.AuthAddr != listed.Address {
		t.Fatalf("the reprogram is not authorized by the listed key: %+v, %v", check.AuthAddr, err)
	}
	signedDummies, err := signing.SignDummyTransactions(dummies)
	if err != nil {
		t.Fatalf("sign dummies: %v", err)
	}
	raw := append(append([]byte(nil), signedHandover...), signedReprogram...)
	for _, dummy := range signedDummies {
		raw = append(raw, dummy...)
	}
	submitCorridorGroupExpectSuccess(t, network, raw, algocrypto.GetTxID(reprogram))
}

// The mesh: native members rekeyed to bounded programs that pay only one
// another and a native hatch, each with a listed key. Members pay within the
// mesh and nowhere else; the hatch is the only member whose funds can leave. A
// member is handed to its listed key and reprogrammed in one atomic group,
// keeping its address, and then follows its new program.
func TestBoundedMeshLocalnet(t *testing.T) {
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
	provider := plainHostProvider(t, network, plainFalconKeyType)
	shape := plainhost.Shape{
		Spend:    []txeffects.SpendEffect{txeffects.SpendEffectPay},
		Encoding: plainhost.EncodingInline,
		Rekey:    plainhost.RekeyOnlyThese,
	}

	hatch := algocrypto.GenerateAccount()
	outsider := algocrypto.GenerateAccount()
	for _, native := range []algocrypto.Account{hatch, outsider} {
		if err := funder.FundMicroAlgosAndWait(native.Address.String(), 300_000); err != nil {
			t.Fatalf("fund %s: %v", native.Address, err)
		}
		native := native
		t.Cleanup(func() {
			bestEffortCloseRekeyedAccount(t, network, native.Address.String(), funder.GetAddress(), native.PrivateKey)
		})
	}
	members := make([]*meshMember, 3)
	for i := range members {
		members[i] = &meshMember{key: algocrypto.GenerateAccount(), listed: algocrypto.GenerateAccount()}
		if err := funder.FundMicroAlgosAndWait(members[i].address(), 1_000_000); err != nil {
			t.Fatalf("fund member %d: %v", i, err)
		}
	}
	for i, member := range members {
		allowed := []string{hatch.Address.String()}
		for j, other := range members {
			if j != i {
				allowed = append(allowed, other.address())
			}
		}
		member.program = newBoundsAccount(t, provider, shape, allowed, []string{member.listed.Address.String()})
		rekey := corridorPaymentTxn(t, mustSuggestedParams(t, network), member.address(), member.address(), 0, "mesh-join")
		rekey.RekeyTo = mustDecodeAddress(t, member.program.address)
		submitEd25519TxnExpectSuccess(t, network, member.key.PrivateKey, rekey)
		if got := authAddress(t, network, member.address()); got != member.program.address {
			t.Fatalf("member %d authorizer = %q, want its program", i, got)
		}
	}
	// Cleanup hands each member to its listed key through the program that holds
	// it, then closes it with that key.
	t.Cleanup(func() {
		for _, member := range members {
			if authAddress(t, network, member.address()) == member.program.address {
				handover := corridorPaymentTxn(t, mustSuggestedParams(t, network), member.address(), member.address(), 0, "mesh-cleanup-handover")
				handover.RekeyTo = member.listed.Address
				raw, txid := member.program.signGroup(t, handover, nil, nil)
				if _, err := network.Client.SendRawTransaction(raw).Do(context.Background()); err == nil {
					_, _ = network.WaitForConfirmation(txid, 10)
				}
			}
			bestEffortCloseRekeyedAccount(t, network, member.address(), funder.GetAddress(), member.listed.PrivateKey)
		}
	})

	pay := func(accepted bool, member *meshMember, to, note string) {
		t.Helper()
		raw, txid := meshPayment(t, network, member.address(), member.program, to, note)
		if accepted {
			submitCorridorGroupExpectSuccess(t, network, raw, txid)
		} else {
			submitCorridorGroupExpectFailure(t, network, raw)
		}
	}
	t.Run("members pay one another and the hatch", func(t *testing.T) {
		pay(true, members[0], members[1].address(), "mesh-a")
		pay(true, members[1], members[2].address(), "mesh-b")
		pay(true, members[2], members[0].address(), "mesh-c")
		for i, member := range members {
			pay(true, member, hatch.Address.String(), fmt.Sprintf("mesh-hatch-%d", i))
		}
	})
	t.Run("no member pays outside the mesh", func(t *testing.T) {
		for i, member := range members {
			pay(false, member, outsider.Address.String(), fmt.Sprintf("mesh-out-%d", i))
		}
	})
	t.Run("only the hatch's funds leave the mesh", func(t *testing.T) {
		out := corridorPaymentTxn(t, mustSuggestedParams(t, network), hatch.Address.String(), outsider.Address.String(), 10_000, "mesh-hatch-out")
		submitEd25519TxnExpectSuccess(t, network, hatch.PrivateKey, out)
	})

	t.Run("a member is handed over and reprogrammed in one group", func(t *testing.T) {
		member := members[0]
		old := member.program
		nextListed := algocrypto.GenerateAccount()
		// The new program pays only the hatch.
		next := newBoundsAccount(t, provider, shape, []string{hatch.Address.String()}, []string{nextListed.Address.String()})
		meshHandOver(t, network, member.address(), old, member.listed, next.address)
		if got := authAddress(t, network, member.address()); got != next.address {
			t.Fatalf("authorizer = %q, want the new program %s", got, next.address)
		}
		member.program, member.listed = next, nextListed

		pay(true, member, hatch.Address.String(), "mesh-next-hatch")
		pay(false, member, members[1].address(), "mesh-next-member")
		// The old program no longer holds the account: the network refuses it as
		// the authorizer before any program runs.
		raw, _ := meshPayment(t, network, member.address(), old, hatch.Address.String(), "mesh-old-program")
		if _, err := network.Client.SendRawTransaction(raw).Do(context.Background()); err == nil {
			t.Fatal("the old program still authorized the member")
		}
		// The rest of the mesh still pays the reprogrammed member, at its address.
		pay(true, members[1], member.address(), "mesh-still-member")
	})
}
