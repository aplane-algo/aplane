// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"bytes"
	"context"
	"encoding/hex"
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
		adminArgs  int
		spendGroup int
		adminGroup int
		spendFee   uint64
		adminFee   uint64
		address    string
	}{
		{
			name:       "rekey-disabled-pay",
			profile:    boundedIntegrationProfile([]txeffects.SpendEffect{txeffects.SpendEffectPay}),
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
				composeddsa.AdminOperationSpec{Kind: composeddsa.AdminOperationRekey, Authorization: composeddsa.AdminAuthorizationSpendingKey, PolicyGate: composeddsa.AdminPolicyGateNone},
			),
			bytecode: 1950, spendArgs: 1423, spendGroup: 2, spendFee: 2000,
			address: "UNXBYLJQS3WTPIR63PKNDHZHXLMGAHPBCWIRRZXXQ3SGEEYEMG7NH2BB74",
		},
		{
			name: "admin-key-rekey-pay-axfer",
			profile: boundedIntegrationProfile(
				[]txeffects.SpendEffect{txeffects.SpendEffectPay, txeffects.SpendEffectAxfer},
				composeddsa.AdminOperationSpec{Kind: composeddsa.AdminOperationRekey, Authorization: composeddsa.AdminAuthorizationAdminKey, PolicyGate: composeddsa.AdminPolicyGateNone},
			),
			bytecode: 3848, spendArgs: 1423, adminArgs: 2846,
			spendGroup: 2, adminGroup: 3, spendFee: 2186, adminFee: 3086,
			address: "N4HFY5R724WD6UUEOLLULPIS33D7LSHVPJNAN6IZV3E4ESSHXPO7R44CKE",
		},
	}
	consensus, err := lsigresource.ResolveConsensus(network.ConsensusVersion)
	if err != nil {
		t.Fatal(err)
	}
	spendingPublicKey := bytes.Repeat([]byte{0x21}, family.PublicKeySize)
	adminPublicKey := bytes.Repeat([]byte{0x31}, composeddsa.BoundedAdminPublicKeySize)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := newBoundedIntegrationProvider(test.profile)
			provider.SetAlgodClient(network.Client)
			params := boundedIntegrationParams(test.profile, adminPublicKey)
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
			adminArgs := 0
			var adminPlan lsigresource.Plan
			if boundedProfileUsesAdminKey(test.profile) {
				adminArgs = metadata.ArgumentBytesForPath(boundedmeta.PathAdminRekey)
				adminPlan = solveV42IntegrationPath(t, consensus, len(result.Bytecode), adminArgs)
			}
			spendFee := v42IntegrationPathFee(spendPlan)
			adminFee := v42IntegrationPathFee(adminPlan)
			if len(result.Bytecode) != test.bytecode || spendArgs != test.spendArgs || adminArgs != test.adminArgs ||
				int(spendPlan.GroupSize) != test.spendGroup || int(adminPlan.GroupSize) != test.adminGroup ||
				spendFee != test.spendFee || adminFee != test.adminFee || result.Address.String() != test.address {
				t.Fatalf(
					"v42 compiled matrix = bytecode=%d spend args=%d/group=%d/fee=%d admin args=%d/group=%d/fee=%d address=%s; want %d/%d/%d/%d/%d/%d/%d/%s",
					len(result.Bytecode), spendArgs, spendPlan.GroupSize, spendFee,
					adminArgs, adminPlan.GroupSize, adminFee, result.Address.String(),
					test.bytecode, test.spendArgs, test.spendGroup, test.spendFee,
					test.adminArgs, test.adminGroup, test.adminFee, test.address,
				)
			}
			if spendFee > test.profile.MaxFee || adminFee > test.profile.MaxFee {
				t.Fatalf("required v42 fee exceeds compiled max_fee %d: spend=%d admin=%d", test.profile.MaxFee, spendFee, adminFee)
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
	tests := []struct {
		name           string
		build          func() types.Transaction
		mutate         func(*types.Transaction)
		includeAdmin   bool
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
		{name: "fee at profile ceiling", mutate: func(txn *types.Transaction) { txn.Fee = types.MicroAlgos(composeddsa.BoundedMaxFeeV1) }, wantShape: txeffects.ShapePureSpend, wantAccept: true},
		{name: "fee above profile", mutate: func(txn *types.Transaction) { txn.Fee = types.MicroAlgos(composeddsa.BoundedMaxFeeV1 + 1) }, wantShape: txeffects.ShapePureSpend},
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
			name: "rekey plus amount", includeAdmin: true, wantShape: txeffects.ShapeHybrid,
			mutate: func(txn *types.Transaction) {
				txn.Receiver = mustAddress(t, account.address)
				txn.RekeyTo = target.Address
			},
		},
		{
			name: "rekey plus foreign receiver", includeAdmin: true, wantShape: txeffects.ShapeHybrid,
			mutate: func(txn *types.Transaction) { txn.Amount = 0; txn.RekeyTo = target.Address },
		},
		{
			name: "rekey plus close", includeAdmin: true, wantShape: txeffects.ShapeHybrid,
			mutate: func(txn *types.Transaction) {
				txn.Amount = 0
				txn.Receiver = mustAddress(t, account.address)
				txn.RekeyTo = target.Address
				txn.CloseRemainderTo = other.Address
			},
		},
		{
			name: "pure rekey without admin proof", wantShape: txeffects.ShapePureRekey,
			mutate: func(txn *types.Transaction) {
				txn.Amount = 0
				txn.Receiver = mustAddress(t, account.address)
				txn.RekeyTo = target.Address
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
				(classification.Shape == txeffects.ShapePureRekey && test.includeAdmin)
			classifierAccept = classifierAccept && uint64(txn.Fee) <= composeddsa.BoundedMaxFeeV1
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
			rawGroup, txid := account.signGroup(t, txn, test.includeAdmin)
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
		rawGroup, txid := account.signGroup(t, allowedTxn, false)
		submitCorridorGroupExpectSuccess(t, network, rawGroup, txid)

		foreignTxn := corridorAssetTransferTxn(t, mustSuggestedParams(t, network), account.address, other.Address.String(), 1, assetID, "bounded-asset-foreign")
		rawGroup, _ = account.signGroup(t, foreignTxn, false)
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
				rawGroup, _ := account.signGroup(t, txn, mask != 1)
				submitCorridorGroupExpectFailure(t, network, rawGroup)
			})
		}
	})

	t.Run("pure rekey with admin proof", func(t *testing.T) {
		txn := boundedPaymentTxn(t, mustSuggestedParams(t, network), account.address, account.address, 0, "bounded-pure-rekey")
		txn.RekeyTo = target.Address
		if got := txeffects.Classify(txn).Shape; got != txeffects.ShapePureRekey {
			t.Fatalf("classifier shape = %q, want pure rekey", got)
		}
		rawGroup, txid := account.signGroup(t, txn, true)
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
	adminPublicKey     []byte
	adminPrivateKey    []byte
	provider           *composeddsa.ComposedDSA
	metadata           *boundedmeta.Metadata
}

func newBoundedExecutionAccount(t *testing.T, network *harness.TestnetConfig, recipient string) boundedExecutionAccount {
	t.Helper()
	ops := signerops.New(nil)
	spendingPublicKey, spendingPrivateKey, err := ops.GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate bounded spending key: %v", err)
	}
	adminPublicKey, adminPrivateKey, err := ops.GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate bounded admin key: %v", err)
	}
	profile := boundedIntegrationProfile(
		[]txeffects.SpendEffect{txeffects.SpendEffectPay, txeffects.SpendEffectAxfer, txeffects.SpendEffectAssetOptIn},
		composeddsa.AdminOperationSpec{Kind: composeddsa.AdminOperationRekey, Authorization: composeddsa.AdminAuthorizationAdminKey, PolicyGate: composeddsa.AdminPolicyGateNone},
	)
	provider := newFixedAllowlistIntegrationProvider(profile)
	provider.SetAlgodClient(network.Client)
	params := boundedIntegrationParams(profile, adminPublicKey)
	params["recipients"] = recipient
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
		adminPublicKey: append([]byte(nil), adminPublicKey...), adminPrivateKey: append([]byte(nil), adminPrivateKey...),
		provider: provider, metadata: metadata,
	}
}

func (account boundedExecutionAccount) signGroup(t *testing.T, targetTxn types.Transaction, includeAdmin bool) ([]byte, string) {
	t.Helper()
	signed, txid := account.signedGroup(t, targetTxn, includeAdmin)
	rawGroup := make([]byte, 0)
	for _, stxn := range signed {
		rawGroup = append(rawGroup, msgpack.Encode(stxn)...)
	}
	return rawGroup, txid
}

func (account boundedExecutionAccount) signedGroup(t *testing.T, targetTxn types.Transaction, includeAdmin bool) ([]types.SignedTxn, string) {
	t.Helper()
	minFee := uint64(1_000)
	if targetTxn.Fee > 0 && uint64(targetTxn.Fee) < composeddsa.BoundedMaxFeeV1+1 {
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
	args, err := account.provider.BuildArgs(spendingSignature, nil)
	if err != nil {
		t.Fatalf("build bounded base args: %v", err)
	}
	if includeAdmin {
		encodedBinding, err := hex.DecodeString(account.metadata.ProgramBindingHex)
		if err != nil {
			t.Fatalf("decode bounded program binding: %v", err)
		}
		if len(encodedBinding) != 32 {
			t.Fatalf("bounded program binding is %d bytes, want 32", len(encodedBinding))
		}
		var binding [32]byte
		copy(binding[:], encodedBinding)
		message, err := composeddsa.BoundedAdminMessage(composeddsa.AdminOperationRekey, binding, txID)
		if err != nil {
			t.Fatal(err)
		}
		adminSignature, err := signerops.New(nil).Sign(account.adminPrivateKey, message[:])
		if err != nil {
			t.Fatalf("sign bounded admin proof: %v", err)
		}
		args = append(args, adminSignature)
	}
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

func boundedIntegrationProfile(allowed []txeffects.SpendEffect, operations ...composeddsa.AdminOperationSpec) *composeddsa.BoundedAuthorizationProfile {
	return &composeddsa.BoundedAuthorizationProfile{
		Contract: composeddsa.BoundedContractV1, SpendEffects: allowed,
		MaxFee: composeddsa.BoundedMaxFeeV1, AdminOperations: operations,
	}
}

func boundedIntegrationParams(profile *composeddsa.BoundedAuthorizationProfile, adminPublicKey []byte) map[string]string {
	if !boundedProfileUsesAdminKey(profile) {
		return map[string]string{}
	}
	return map[string]string{composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(adminPublicKey)}
}

func boundedProfileUsesAdminKey(profile *composeddsa.BoundedAuthorizationProfile) bool {
	for _, operation := range profile.AdminOperations {
		if operation.Authorization == composeddsa.AdminAuthorizationAdminKey {
			return true
		}
	}
	return false
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
	_, signed, err := algocrypto.SignTransaction(authPrivateKey, txn)
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
