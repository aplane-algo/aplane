// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"context"
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// compositeKey holds one component's key pair.
type compositeKey struct {
	primitive sigconstruction.PrimitiveID
	public    []byte
	private   []byte
}

func newFalconKey(t *testing.T) compositeKey {
	t.Helper()
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	public, private, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatal(err)
	}
	return compositeKey{primitive: sigconstruction.PrimitiveFalcon1024, public: public, private: private}
}

func newCompositeKey(t *testing.T, primitive sigconstruction.PrimitiveID) compositeKey {
	t.Helper()
	if primitive == sigconstruction.PrimitiveFalcon1024 {
		return newFalconKey(t)
	}
	public, private, err := stded25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return compositeKey{primitive: primitive, public: public, private: private}
}

func (k compositeKey) sign(t *testing.T, message []byte) []byte {
	t.Helper()
	if k.primitive == sigconstruction.PrimitiveEd25519 {
		return stded25519.Sign(k.private, message)
	}
	signature, err := signerops.New(nil).Sign(k.private, message)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

// compositeAccount is a funded fixture account on LocalNet.
type compositeAccount struct {
	provider *composeddsa.ComposedDSA
	keys     []compositeKey
	metadata *boundedmeta.Metadata
	address  string
	bytecode []byte
	cosigner *compositeKey
}

func newCompositeAccount(t *testing.T, network *harness.TestnetConfig, funder *harness.FundTestAccount, primitives []sigconstruction.PrimitiveID, withCosigner bool) *compositeAccount {
	t.Helper()
	extra, params := spendingKeyRekeyYAML, map[string]string{}
	account := &compositeAccount{}
	support := composeddsa.FixtureSupport{}
	if withCosigner {
		cosigner := newFalconKey(t)
		account.cosigner = &cosigner
		extra, support.Cosigner = cosignerYAML, true
		params[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(cosigner.public)
	}
	account.provider = compositeProvider(t, compositeConstruction(t, primitives...), extra, support)
	account.provider.SetAlgodClient(network.Client)

	var publicKey []byte
	for _, primitive := range primitives {
		key := newCompositeKey(t, primitive)
		account.keys = append(account.keys, key)
		publicKey = append(publicKey, key.public...)
	}
	derived, err := account.provider.DeriveLsigWithSalt(context.Background(), publicKey, params)
	if err != nil {
		t.Fatalf("DeriveLsigWithSalt() error = %v", err)
	}
	account.address, account.bytecode = derived.Address.String(), derived.Bytecode
	account.metadata, err = account.provider.BuildBoundedAuthorizationMetadata(publicKey, params, derived.Bytecode)
	if err != nil {
		t.Fatalf("BuildBoundedAuthorizationMetadata() error = %v", err)
	}
	if err := funder.FundMicroAlgosAndWait(account.address, 500_000); err != nil {
		t.Fatalf("failed to fund %s: %v", account.address, err)
	}
	return account
}

// groupPlan sizes the group through the planner the product uses.
func groupPlan(t *testing.T, programBytes, argumentBytes int) (groupSize, fee uint64) {
	t.Helper()
	consensus, err := lsigresource.CurrentConsensus()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := lsigresource.Solve(consensus, lsigresource.PlanInput{
		TransactionCount: 1,
		LogicSigs:        []lsigresource.Usage{{ProgramBytes: uint64(programBytes), ArgumentBytes: uint64(argumentBytes), MaxOpcodeCost: 20_000}},
		Dummy:            lsigresource.Usage{ProgramBytes: uint64(len(signing.EmbeddedDummyTealTok)), MaxOpcodeCost: 1},
	})
	if err != nil {
		t.Fatalf("lsigresource.Solve() error = %v", err)
	}
	const scale = 1_000_000
	usage := plan.GroupSize*scale + plan.ProgramFeeFactorUsage
	return plan.GroupSize, (consensus.MinTxnFee*usage + scale - 1) / scale
}

// argsFor builds arguments for a transaction ID. Each signer's position matches the
// slot it fills, so a test can substitute one component.
func (a *compositeAccount) argsFor(t *testing.T, txid []byte, signers []compositeKey, cosigned bool) [][]byte {
	t.Helper()
	parts := make([][]byte, len(signers))
	for i, signer := range signers {
		parts[i] = signer.sign(t, txid)
	}
	if a.cosigner == nil {
		args, err := a.provider.BuildArgs(encodeCompositeSignature(parts...), nil)
		if err != nil {
			t.Fatalf("BuildArgs() error = %v", err)
		}
		return args
	}
	// BuildArgs has no transaction context, so it refuses a required cosigner slot.
	// Placement follows the stored layout, as the signer's assembly does.
	args := make([][]byte, len(a.metadata.ArgumentLayout))
	base := 0
	for _, slot := range a.metadata.ArgumentLayout {
		args[slot.Index] = []byte{}
		switch slot.Source {
		case boundedmeta.ArgSourceBaseSignature:
			args[slot.Index] = parts[base]
			base++
		case boundedmeta.ArgSourceCosigner:
			if cosigned {
				var digest types.Digest
				copy(digest[:], txid)
				componentMessage := message.ComponentMessage(message.RoleCosigner, digest)
				args[slot.Index] = a.cosigner.sign(t, componentMessage[:])
			}
		}
	}
	for len(args) > 0 && len(args[len(args)-1]) == 0 {
		args = args[:len(args)-1]
	}
	return args
}

// signedGroup returns a group whose first transaction pays from the account. The
// plan is sized for the largest signatures, so every case in a test shares it.
func (a *compositeAccount) signedGroup(t *testing.T, network *harness.TestnetConfig, receiver, note string, build func(txid []byte) [][]byte) ([]byte, string) {
	t.Helper()
	sp, err := network.Client.SuggestedParams().Do(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sp.FlatFee = true
	txn, err := transaction.MakePaymentTxn(a.address, receiver, 0, []byte(note), "", sp)
	if err != nil {
		t.Fatal(err)
	}
	maximum := 0
	for _, size := range a.metadata.BaseSignatureArgLayout.MaxSizes {
		maximum += size
	}
	if a.cosigner != nil {
		maximum += boundedmeta.CosignerSignatureMaxSizeV1
	}
	size, fee := groupPlan(t, len(a.bytecode), maximum)
	txn.Fee = types.MicroAlgos(fee)
	dummies, err := signing.CreateDummyTransactions(int(size)-1, sp)
	if err != nil {
		t.Fatal(err)
	}
	all := append([]types.Transaction{txn}, dummies...)
	groupID, err := algocrypto.ComputeGroupID(all)
	if err != nil {
		t.Fatal(err)
	}
	txn.Group = groupID
	for i := range dummies {
		dummies[i].Group = groupID
	}
	account := algocrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: a.bytecode, Args: build(algocrypto.TransactionID(txn))}}
	txid, raw, err := algocrypto.SignLogicSigAccountTransaction(account, txn)
	if err != nil {
		t.Fatal(err)
	}
	signedDummies, err := signing.SignDummyTransactions(dummies)
	if err != nil {
		t.Fatal(err)
	}
	var target types.SignedTxn
	if err := msgpack.Decode(raw, &target); err != nil {
		t.Fatal(err)
	}
	group := append([]byte(nil), msgpack.Encode(target)...)
	for _, dummy := range signedDummies {
		group = append(group, dummy...)
	}
	return group, txid
}

func expectRejected(t *testing.T, network *harness.TestnetConfig, group []byte) {
	t.Helper()
	_, err := network.Client.SendRawTransaction(group).Do(context.Background())
	if err == nil {
		t.Fatal("group was accepted")
	}
	lower := strings.ToLower(err.Error())
	if !strings.Contains(lower, "rejected by logic") && !strings.Contains(lower, "logic eval") {
		t.Fatalf("group failed for a non-LogicSig reason: %v", err)
	}
}

func expectConfirmed(t *testing.T, network *harness.TestnetConfig, group []byte, txid string) {
	t.Helper()
	if _, err := network.Client.SendRawTransaction(group).Do(context.Background()); err != nil {
		t.Fatalf("group was refused: %v", err)
	}
	if _, err := network.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("transaction %s did not confirm: %v", txid, err)
	}
}

// TestCompositeLogicSigsExecuteLocalnet runs fixture programs on a real AVM. Each
// must refuse a wrong signature in any one component, and accept only all of them.
func TestCompositeLogicSigsExecuteLocalnet(t *testing.T) {
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("integration tests are disabled")
	}
	if harness.IntegrationNetwork() != harness.IntegrationNetworkLocalnet {
		t.Skip("composite LogicSig execution requires localnet")
	}
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatal(err)
	}
	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatal(err)
	}

	const falconPrimitive, edPrimitive = sigconstruction.PrimitiveFalcon1024, sigconstruction.PrimitiveEd25519
	for name, test := range map[string]struct {
		primitives []sigconstruction.PrimitiveID
		cosigned   bool
	}{
		"Falcon then Ed25519":          {primitives: []sigconstruction.PrimitiveID{falconPrimitive, edPrimitive}},
		"Ed25519 then Falcon":          {primitives: []sigconstruction.PrimitiveID{edPrimitive, falconPrimitive}},
		"three components":             {primitives: []sigconstruction.PrimitiveID{edPrimitive, falconPrimitive, edPrimitive}},
		"two components with cosigner": {primitives: []sigconstruction.PrimitiveID{falconPrimitive, edPrimitive}, cosigned: true},
	} {
		t.Run(name, func(t *testing.T) {
			account := newCompositeAccount(t, network, funder, test.primitives, test.cosigned)
			submit := func(note string, signers []compositeKey, cosigned bool) ([]byte, string) {
				return account.signedGroup(t, network, funder.GetAddress(), note, func(txid []byte) [][]byte {
					return account.argsFor(t, txid, signers, cosigned)
				})
			}

			for i := range account.keys {
				wrong := append([]compositeKey(nil), account.keys...)
				wrong[i] = newCompositeKey(t, wrong[i].primitive)
				group, _ := submit(fmt.Sprintf("wrong-%d", i), wrong, test.cosigned)
				expectRejected(t, network, group)
			}
			// Each proof below is valid in every component but one.
			for i := range account.keys {
				for label, damage := range map[string]func(args [][]byte, txid []byte){
					"corrupted": func(args [][]byte, _ []byte) {
						args[i] = bytes.Clone(args[i])
						args[i][len(args[i])/2] ^= 0xff
					},
					"missing": func(args [][]byte, _ []byte) { args[i] = []byte{} },
					"signed over the wrong message": func(args [][]byte, txid []byte) {
						other := bytes.Clone(txid)
						other[0] ^= 0xff
						args[i] = account.keys[i].sign(t, other)
					},
				} {
					group, _ := account.signedGroup(t, network, funder.GetAddress(), fmt.Sprintf("%s-%d", label, i), func(txid []byte) [][]byte {
						args := account.argsFor(t, txid, account.keys, test.cosigned)
						damage(args, txid)
						return args
					})
					expectRejected(t, network, group)
				}
			}
			if len(test.primitives) == 2 {
				group, _ := account.signedGroup(t, network, funder.GetAddress(), "swapped", func(txid []byte) [][]byte {
					args := account.argsFor(t, txid, account.keys, test.cosigned)
					args[0], args[1] = args[1], args[0]
					return args
				})
				expectRejected(t, network, group)
			}
			if test.cosigned {
				group, _ := submit("no-cosigner", account.keys, false)
				expectRejected(t, network, group)
				group, _ = account.signedGroup(t, network, funder.GetAddress(), "wrong-cosigner", func(txid []byte) [][]byte {
					original := *account.cosigner
					other := newFalconKey(t)
					account.cosigner = &other
					defer func() { account.cosigner = &original }()
					return account.argsFor(t, txid, account.keys, true)
				})
				expectRejected(t, network, group)
			}

			group, txid := submit("accepted", account.keys, test.cosigned)
			expectConfirmed(t, network, group, txid)
		})
	}
}
