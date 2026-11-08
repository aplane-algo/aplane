// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	falconv1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"
	"github.com/aplane-algo/aplane/test/integration/harness"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	boundedIntegrationKeyType = "aplane.test-falcon1024-bounded.v1"
	boundedExecutionGroupSize = 7
)

func TestBoundedComposerCompiledBudgetMatrix(t *testing.T) {
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("set INTEGRATION=1 to compile bounded composer contracts")
	}
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		profile    *composeddsa.BoundedAuthorizationProfile
		bytecode   int
		spendArgs  int
		spendGroup int
		spendFee   uint64
		address    string
	}{
		{
			name:       "rekey-disabled-pay",
			profile:    boundedIntegrationProfile([]txeffects.SpendEffect{txeffects.SpendEffectPay}, boundedmeta.RekeyRefused),
			bytecode:   1906,
			spendArgs:  1423,
			spendGroup: 2,
			spendFee:   2000,
			address:    "NDW4G7KSXADVZSLN4XKRYFEOQ5SVVZK2T3BQGLZIHFMRVDPDXSGPA4Z74E",
		},
		{
			name: "spending-key-rekey-pay-axfer",
			profile: boundedIntegrationProfile(
				[]txeffects.SpendEffect{txeffects.SpendEffectPay, txeffects.SpendEffectAxfer},
				boundedmeta.RekeySpendingKey,
			),
			bytecode: 1950, spendArgs: 1423, spendGroup: 2, spendFee: 2000,
			address: "UNXBYLJQS3WTPIR63PKNDHZHXLMGAHPBCWIRRZXXQ3SGEEYEMG7NH2BB74",
		},
	}
	consensus, err := lsigresource.ResolveConsensus(network.ConsensusVersion)
	if err != nil {
		t.Fatal(err)
	}
	spendingPublicKey := bytes.Repeat([]byte{0x21}, family.PublicKeySize)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := newBoundedIntegrationProvider(test.profile)
			provider.SetAlgodClient(network.Client)
			params := map[string]string{}
			result, err := provider.DeriveLsigWithSalt(context.Background(), spendingPublicKey, params)
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := provider.BuildBoundedAuthorizationMetadata(spendingPublicKey, params, result.Bytecode)
			if err != nil {
				t.Fatal(err)
			}
			spendArgs := metadata.ArgumentBytesForPath(boundedmeta.PathSpend)
			spendPlan := solveV42IntegrationPath(t, consensus, len(result.Bytecode), spendArgs)
			spendFee := v42IntegrationPathFee(spendPlan)
			if len(result.Bytecode) != test.bytecode || spendArgs != test.spendArgs ||
				int(spendPlan.GroupSize) != test.spendGroup || spendFee != test.spendFee || result.Address.String() != test.address {
				t.Fatalf(
					"v42 compiled matrix = bytecode=%d spend args=%d/group=%d/fee=%d address=%s; want %d/%d/%d/%d/%s",
					len(result.Bytecode), spendArgs, spendPlan.GroupSize, spendFee, result.Address.String(),
					test.bytecode, test.spendArgs, test.spendGroup, test.spendFee, test.address,
				)
			}
			if spendFee > test.profile.MaxFee {
				t.Fatalf("required v42 fee exceeds compiled max_fee %d: spend=%d", test.profile.MaxFee, spendFee)
			}
		})
	}
}

func solveV42IntegrationPath(t *testing.T, profile lsigresource.ConsensusProfile, programBytes, argumentBytes int) lsigresource.Plan {
	t.Helper()
	plan, err := lsigresource.Solve(profile, lsigresource.PlanInput{
		TransactionCount: 1,
		LogicSigs: []lsigresource.Usage{{
			ProgramBytes:  uint64(programBytes),
			ArgumentBytes: uint64(argumentBytes),
			MaxOpcodeCost: lsigresource.SingleTransactionOpcodeCeiling,
		}},
		Dummy: lsigresource.Usage{
			ProgramBytes:  uint64(len(signing.EmbeddedDummyTealTok)),
			MaxOpcodeCost: 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func v42IntegrationPathFee(plan lsigresource.Plan) uint64 {
	if plan.GroupSize == 0 {
		return 0
	}
	const minFee = uint64(1_000)
	const factorScale = uint64(1_000_000)
	usage := plan.GroupSize*factorScale + plan.ProgramFeeFactorUsage
	return (minFee*usage + factorScale - 1) / factorScale
}

func TestBoundedComposerExecutionAgreementLocalnet(t *testing.T) {
	if harness.IntegrationNetwork() != harness.IntegrationNetworkLocalnet {
		t.Skip("bounded LogicSig execution agreement requires localnet")
	}
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to localnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("load funding account: %v", err)
	}

	account := newBoundedExecutionAccount(t, network, funder.GetAddress())
	if err := funder.FundMicroAlgosAndWait(account.address, 2_000_000); err != nil {
		t.Fatalf("fund bounded account %s: %v", account.address, err)
	}

	target := algocrypto.GenerateAccount()
	other := algocrypto.GenerateAccount()
	assetID := corridorTestAssetID(t, network, funder)
	baseTxn := func(note string) types.Transaction {
		return boundedPaymentTxn(t, mustSuggestedParams(t, network), account.address, funder.GetAddress(), 1_000, note)
	}
	assetTxn := func(note string) types.Transaction {
		return corridorAssetTransferTxn(t, mustSuggestedParams(t, network), account.address, account.address, 0, assetID, note)
	}
	// The spending key is this account's rekey authority, and it signs every case,
	// so each rejected rekey below is refused for its shape, not for a missing
	// authority. A pure rekey is accepted, so it runs last, in its own subtest.
	tests := []struct {
		name           string
		build          func() types.Transaction
		mutate         func(*types.Transaction)
		classifierOnly bool
		wantShape      txeffects.Shape
		wantAccept     bool
	}{
		{name: "pure payment spend", wantShape: txeffects.ShapePureSpend, wantAccept: true},
		{name: "foreign payment receiver", mutate: func(txn *types.Transaction) { txn.Receiver = other.Address }, wantShape: txeffects.ShapePureSpend},
		{
			name: "pure asset opt-in spend", wantShape: txeffects.ShapePureSpend, wantAccept: true,
			build: func() types.Transaction {
				return corridorAssetTransferTxn(t, mustSuggestedParams(t, network), account.address, account.address, 0, assetID, "bounded-asset-opt-in")
			},
		},
		{name: "fee at profile ceiling", mutate: func(txn *types.Transaction) { txn.Fee = types.MicroAlgos(composeddsa.BoundedMaxFee) }, wantShape: txeffects.ShapePureSpend, wantAccept: true},
		{name: "fee above profile", mutate: func(txn *types.Transaction) { txn.Fee = types.MicroAlgos(composeddsa.BoundedMaxFee + 1) }, wantShape: txeffects.ShapePureSpend},
		{name: "close remainder", mutate: func(txn *types.Transaction) { txn.CloseRemainderTo = other.Address }, wantShape: txeffects.ShapeDeniedEffect},
		{name: "asset close", build: func() types.Transaction { return assetTxn("bounded-agreement-asset-close") }, mutate: func(txn *types.Transaction) { txn.AssetCloseTo = other.Address }, wantShape: txeffects.ShapeDeniedEffect},
		{name: "clawback", build: func() types.Transaction { return assetTxn("bounded-agreement-clawback") }, mutate: func(txn *types.Transaction) { txn.AssetSender = other.Address }, wantShape: txeffects.ShapeDeniedEffect},
		{
			name: "denied keyreg type", wantShape: txeffects.ShapeDeniedType,
			build: func() types.Transaction {
				txn := baseTxn("bounded-agreement-denied-keyreg-type")
				txn.Type = types.KeyRegistrationTx
				txn.PaymentTxnFields = types.PaymentTxnFields{}
				txn.Nonparticipation = true
				return txn
			},
		},
		{name: "denied asset config type", mutate: func(txn *types.Transaction) { txn.Type = types.AssetConfigTx }, classifierOnly: true, wantShape: txeffects.ShapeDeniedType},
		{name: "denied asset freeze type", mutate: func(txn *types.Transaction) { txn.Type = types.AssetFreezeTx }, classifierOnly: true, wantShape: txeffects.ShapeDeniedType},
		{name: "denied application type", mutate: func(txn *types.Transaction) { txn.Type = types.ApplicationCallTx }, classifierOnly: true, wantShape: txeffects.ShapeDeniedType},
		{name: "denied state proof type", mutate: func(txn *types.Transaction) { txn.Type = types.StateProofTx }, classifierOnly: true, wantShape: txeffects.ShapeDeniedType},
		{name: "denied heartbeat type", mutate: func(txn *types.Transaction) { txn.Type = types.HeartbeatTx }, classifierOnly: true, wantShape: txeffects.ShapeDeniedType},
		{name: "unknown type", mutate: func(txn *types.Transaction) { txn.Type = "future" }, classifierOnly: true, wantShape: txeffects.ShapeDeniedType},
		{
			name: "rekey plus amount", wantShape: txeffects.ShapeHybrid,
			mutate: func(txn *types.Transaction) {
				txn.Receiver = mustAddress(t, account.address)
				txn.RekeyTo = target.Address
			},
		},
		{
			name: "rekey plus foreign receiver", wantShape: txeffects.ShapeHybrid,
			mutate: func(txn *types.Transaction) { txn.Amount = 0; txn.RekeyTo = target.Address },
		},
		{
			name: "rekey plus close", wantShape: txeffects.ShapeHybrid,
			mutate: func(txn *types.Transaction) {
				txn.Amount = 0
				txn.Receiver = mustAddress(t, account.address)
				txn.RekeyTo = target.Address
				txn.CloseRemainderTo = other.Address
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var txn types.Transaction
			if test.build != nil {
				txn = test.build()
			} else {
				txn = baseTxn("bounded-agreement-" + test.name)
			}
			if test.mutate != nil {
				test.mutate(&txn)
			}
			classification := txeffects.Classify(txn)
			if classification.Shape != test.wantShape {
				t.Fatalf("classifier shape = %q, want %q", classification.Shape, test.wantShape)
			}
			classifierAccept := classification.Shape == txeffects.ShapePureSpend ||
				classification.Shape == txeffects.ShapePureRekey
			classifierAccept = classifierAccept && uint64(txn.Fee) <= composeddsa.BoundedMaxFee
			if classification.Shape == txeffects.ShapePureSpend {
				switch txn.Type {
				case types.PaymentTx:
					classifierAccept = classifierAccept && (txn.Receiver == txn.Sender || txn.Receiver.String() == funder.GetAddress())
				case types.AssetTransferTx:
					classifierAccept = classifierAccept && (txn.AssetReceiver == txn.Sender || txn.AssetReceiver.String() == funder.GetAddress())
				}
			}
			if classifierAccept != test.wantAccept {
				t.Fatalf("classifier/profile acceptance = %v, test expectation = %v", classifierAccept, test.wantAccept)
			}
			// Algod rejects these transaction types during structural or
			// protocol validation before their LogicSig can execute. Their
			// closed-set classification is covered here; keyreg provides the
			// executable denied-type agreement case.
			if test.classifierOnly {
				return
			}
			rawGroup, txid := account.signGroup(t, txn)
			if test.wantAccept {
				submitCorridorGroupExpectSuccess(t, network, rawGroup, txid)
			} else {
				submitCorridorGroupExpectFailure(t, network, rawGroup)
			}
		})
	}

	t.Run("framework allowlist asset receivers", func(t *testing.T) {
		sendAssetFromFunder(t, network, funder, account.address, assetID, 2)
		allowedTxn := corridorAssetTransferTxn(t, mustSuggestedParams(t, network), account.address, funder.GetAddress(), 1, assetID, "bounded-asset-allowed")
		rawGroup, txid := account.signGroup(t, allowedTxn)
		submitCorridorGroupExpectSuccess(t, network, rawGroup, txid)

		foreignTxn := corridorAssetTransferTxn(t, mustSuggestedParams(t, network), account.address, other.Address.String(), 1, assetID, "bounded-asset-foreign")
		rawGroup, _ = account.signGroup(t, foreignTxn)
		submitCorridorGroupExpectFailure(t, network, rawGroup)
	})

	t.Run("all danger-effect combinations", func(t *testing.T) {
		for mask := 1; mask < 16; mask++ {
			t.Run(fmt.Sprintf("mask-%04b", mask), func(t *testing.T) {
				var txn types.Transaction
				if mask&12 != 0 {
					txn = corridorAssetTransferTxn(t, mustSuggestedParams(t, network), account.address, account.address, 0, assetID, fmt.Sprintf("bounded-effects-%04b", mask))
				} else {
					txn = boundedPaymentTxn(t, mustSuggestedParams(t, network), account.address, account.address, 0, fmt.Sprintf("bounded-effects-%04b", mask))
				}
				if mask&1 != 0 {
					txn.RekeyTo = target.Address
				}
				if mask&2 != 0 {
					txn.CloseRemainderTo = other.Address
				}
				if mask&4 != 0 {
					txn.AssetCloseTo = other.Address
				}
				if mask&8 != 0 {
					txn.AssetSender = other.Address
				}
				classification := txeffects.Classify(txn)
				wantShape := txeffects.ShapeDeniedEffect
				if mask == 1 {
					wantShape = txeffects.ShapePureRekey
				} else if mask&1 != 0 {
					wantShape = txeffects.ShapeHybrid
				}
				if classification.Shape != wantShape {
					t.Fatalf("classifier shape = %q, want %q", classification.Shape, wantShape)
				}
				// CloseRemainderTo is payment-only, AssetCloseTo and
				// AssetSender are asset-transfer-only, and an asset cannot be
				// closed by a clawback transaction. Keep those impossible
				// combinations as classifier coverage without claiming that
				// algod can execute them.
				hasPaymentClose := mask&2 != 0
				hasAssetEffect := mask&12 != 0
				hasAssetCloseAndClawback := mask&12 == 12
				if (hasPaymentClose && hasAssetEffect) || hasAssetCloseAndClawback {
					return
				}
				// The spending key may make a pure rekey, which would move the
				// account away from this program; the last subtest submits it.
				if mask == 1 {
					return
				}
				rawGroup, _ := account.signGroup(t, txn)
				submitCorridorGroupExpectFailure(t, network, rawGroup)
			})
		}
	})

	// Last, because it moves the account away from this program.
	t.Run("pure rekey with the spending key", func(t *testing.T) {
		txn := boundedPaymentTxn(t, mustSuggestedParams(t, network), account.address, account.address, 0, "bounded-pure-rekey")
		txn.RekeyTo = target.Address
		if got := txeffects.Classify(txn).Shape; got != txeffects.ShapePureRekey {
			t.Fatalf("classifier shape = %q, want pure rekey", got)
		}
		rawGroup, txid := account.signGroup(t, txn)
		submitCorridorGroupExpectSuccess(t, network, rawGroup, txid)
		t.Cleanup(func() {
			bestEffortCloseBoundedAsset(t, network, account.address, funder.GetAddress(), assetID, target.PrivateKey)
			bestEffortCloseRekeyedAccount(t, network, account.address, funder.GetAddress(), target.PrivateKey)
		})
	})
}

type boundedExecutionAccount struct {
	address            string
	bytecode           []byte
	spendingPublicKey  []byte
	spendingPrivateKey []byte
	provider           *composeddsa.ComposedDSA
	metadata           *boundedmeta.Metadata
}

// newBoundedExecutionAccount's spending key may also rekey the account. A rekey
// never reaches Layer 3.
func newBoundedExecutionAccount(t *testing.T, network *harness.TestnetConfig, recipient string) boundedExecutionAccount {
	t.Helper()
	ops := signerops.New(nil)
	spendingPublicKey, spendingPrivateKey, err := ops.GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate bounded spending key: %v", err)
	}
	profile := boundedIntegrationProfile(
		[]txeffects.SpendEffect{txeffects.SpendEffectPay, txeffects.SpendEffectAxfer, txeffects.SpendEffectAssetOptIn},
		boundedmeta.RekeySpendingKey,
	)
	provider := newFixedAllowlistIntegrationProvider(profile)
	provider.SetAlgodClient(network.Client)
	params := map[string]string{"recipients": recipient}
	derived, err := provider.DeriveLsigWithSalt(context.Background(), spendingPublicKey, params)
	if err != nil {
		t.Fatalf("derive bounded LogicSig: %v", err)
	}
	metadata, err := provider.BuildBoundedAuthorizationMetadata(spendingPublicKey, params, derived.Bytecode)
	if err != nil {
		t.Fatalf("build bounded authorization metadata: %v", err)
	}
	return boundedExecutionAccount{
		address: derived.Address.String(), bytecode: append([]byte(nil), derived.Bytecode...),
		spendingPublicKey: append([]byte(nil), spendingPublicKey...), spendingPrivateKey: append([]byte(nil), spendingPrivateKey...),
		provider: provider, metadata: metadata,
	}
}

func (account boundedExecutionAccount) signGroup(t *testing.T, targetTxn types.Transaction) ([]byte, string) {
	t.Helper()
	signed, txid := account.signedGroup(t, targetTxn)
	rawGroup := make([]byte, 0)
	for _, stxn := range signed {
		rawGroup = append(rawGroup, msgpack.Encode(stxn)...)
	}
	return rawGroup, txid
}

func (account boundedExecutionAccount) signedGroup(t *testing.T, targetTxn types.Transaction) ([]types.SignedTxn, string) {
	t.Helper()
	return account.signedGroupWithLayer3Args(t, targetTxn, nil)
}

// signedGroupWithLayer3Args places layer3Args directly after the base signature,
// so a test can present values a signer would refuse to assemble.
func (account boundedExecutionAccount) signedGroupWithLayer3Args(t *testing.T, targetTxn types.Transaction, layer3Args [][]byte) ([]types.SignedTxn, string) {
	t.Helper()
	minFee := uint64(1_000)
	if targetTxn.Fee > 0 && uint64(targetTxn.Fee) < composeddsa.BoundedMaxFee+1 {
		minFee = uint64(targetTxn.Fee)
	}
	minimumGroupFee := types.MicroAlgos(boundedExecutionGroupSize * 1_000)
	if targetTxn.Fee < minimumGroupFee {
		targetTxn.Fee = minimumGroupFee
	}
	dummySP := types.SuggestedParams{
		Fee: types.MicroAlgos(minFee), GenesisID: targetTxn.GenesisID, GenesisHash: targetTxn.GenesisHash[:],
		FirstRoundValid: targetTxn.FirstValid, LastRoundValid: targetTxn.LastValid, FlatFee: true,
	}
	dummies, err := signing.CreateDummyTransactions(boundedExecutionGroupSize-1, dummySP)
	if err != nil {
		t.Fatalf("build bounded budget dummies: %v", err)
	}
	allTxns := append([]types.Transaction{targetTxn}, dummies...)
	groupID, err := algocrypto.ComputeGroupID(allTxns)
	if err != nil {
		t.Fatalf("compute bounded group ID: %v", err)
	}
	targetTxn.Group = groupID
	for i := range dummies {
		dummies[i].Group = groupID
	}

	txID := algocrypto.TransactionID(targetTxn)
	spendingSignature, err := signerops.New(nil).Sign(account.spendingPrivateKey, txID)
	if err != nil {
		t.Fatalf("sign bounded spending proof: %v", err)
	}
	// Signing packs the signature through the base provider, not the composed
	// one, which would demand this program's runtime arguments here.
	base := lsigprovider.Get(account.provider.BaseKeyType())
	if base == nil {
		t.Fatalf("base provider %s is not registered", account.provider.BaseKeyType())
	}
	args, err := base.BuildArgs(spendingSignature, nil)
	if err != nil {
		t.Fatalf("build bounded base args: %v", err)
	}
	args = append(args, layer3Args...)
	lsigAccount := algocrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: append([]byte(nil), account.bytecode...), Args: args}}
	_, signedTarget, err := algocrypto.SignLogicSigAccountTransaction(lsigAccount, targetTxn)
	if err != nil {
		t.Fatalf("sign bounded target transaction: %v", err)
	}
	signedDummies, err := signing.SignDummyTransactions(dummies)
	if err != nil {
		t.Fatalf("sign bounded dummies: %v", err)
	}
	group := make([]types.SignedTxn, 0, 1+len(signedDummies))
	var target types.SignedTxn
	if err := msgpack.Decode(signedTarget, &target); err != nil {
		t.Fatalf("decode signed bounded target: %v", err)
	}
	group = append(group, target)
	for _, signedDummy := range signedDummies {
		var dummy types.SignedTxn
		if err := msgpack.Decode(signedDummy, &dummy); err != nil {
			t.Fatalf("decode signed bounded dummy: %v", err)
		}
		group = append(group, dummy)
	}
	return group, algocrypto.GetTxID(targetTxn)
}

func newBoundedIntegrationProvider(profile *composeddsa.BoundedAuthorizationProfile) *composeddsa.ComposedDSA {
	return composeddsa.NewComposedDSA(composeddsa.Config{
		KeyType: boundedIntegrationKeyType, BaseKeyType: "aplane.falcon1024.v1", FamilyName: "aplane.test-bounded", Version: 1,
		Ops: falconv1.NewFalconOps(nil), SaltStyle: lsigsalt.StylePushbytes,
		TEALSuffix: "// Controlled trivially true Layer-3 predicate.\nint 1\nassert", Bounded: profile,
	})
}

func newFixedAllowlistIntegrationProvider(profile *composeddsa.BoundedAuthorizationProfile) *composeddsa.ComposedDSA {
	return composeddsa.NewComposedDSA(composeddsa.Config{
		KeyType: boundedIntegrationKeyType, BaseKeyType: "aplane.falcon1024.v1", FamilyName: "aplane.test-bounded", Version: 1,
		Ops: falconv1.NewFalconOps(nil), SaltStyle: lsigsalt.StylePushbytes, TemplateMode: "generated", Bounded: profile,
		Params: []lsigprovider.ParameterDef{{Name: "recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: composeddsa.BoundedInlineListMax}},
		Layer3: &composeddsa.Layer3Policy{Policy: composeddsa.Layer3PolicyFixedAllowlist, RecipientsParameter: "recipients"},
	})
}

func boundedIntegrationProfile(allowed []txeffects.SpendEffect, rekey boundedmeta.RekeySetting) *composeddsa.BoundedAuthorizationProfile {
	return &composeddsa.BoundedAuthorizationProfile{
		Contract: composeddsa.BoundedContract, SpendEffects: allowed,
		MaxFee: composeddsa.BoundedMaxFee, Rekey: rekey,
	}
}

func boundedPaymentTxn(t *testing.T, sp types.SuggestedParams, from, to string, amount uint64, note string) types.Transaction {
	t.Helper()
	txn, err := transaction.MakePaymentTxn(from, to, amount, []byte(note), "", sp)
	if err != nil {
		t.Fatalf("build bounded payment: %v", err)
	}
	return txn
}

func mustAddress(t *testing.T, encoded string) types.Address {
	t.Helper()
	address, err := types.DecodeAddress(encoded)
	if err != nil {
		t.Fatalf("decode address %s: %v", encoded, err)
	}
	return address
}

func bestEffortCloseBoundedAsset(t *testing.T, network *harness.TestnetConfig, account, destination string, assetID uint64, authPrivateKey []byte) {
	t.Helper()
	txn := corridorAssetTransferTxn(t, mustSuggestedParams(t, network), account, account, 0, assetID, "bounded-cleanup-asset")
	txn.AssetCloseTo = mustAddress(t, destination)
	_, signed, err := signing.SignTransactionWithKey(authPrivateKey, txn)
	if err != nil {
		t.Logf("cleanup: failed to sign bounded asset close: %v", err)
		return
	}
	txid, err := network.Client.SendRawTransaction(signed).Do(context.Background())
	if err != nil {
		t.Logf("cleanup: bounded asset close submit failed: %v", err)
		return
	}
	if _, err := network.WaitForConfirmation(txid, 10); err != nil {
		t.Logf("cleanup: bounded asset close confirmation failed: %v", err)
	}
}
