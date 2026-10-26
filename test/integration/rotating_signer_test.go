// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/stagetable"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/txnutil"
	rotatingslhsignerreg "github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/signerreg"
	rotatingtriplesignerreg "github.com/aplane-algo/aplane/lsig/rotatingtriplewots/signerreg"
	rotatingxmsssignerreg "github.com/aplane-algo/aplane/lsig/rotatingtriplexmss/signerreg"
	"github.com/aplane-algo/aplane/pkg/signerapi"
	"github.com/aplane-algo/aplane/test/integration/harness"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

type rotatingSeedStore struct {
	keyType       string
	seed, genesis []byte
}

func (s *rotatingSeedStore) Get(context.Context, string) (*coresigning.KeyMaterial, error) {
	return &coresigning.KeyMaterial{
		Type:     s.keyType,
		Category: keys.CategoryRotatingLsig,
		Value:    &coresigning.RotatingKeyMaterial{Seed: bytes.Clone(s.seed), GenesisHash: bytes.Clone(s.genesis)},
	}, nil
}

// localnetRotatingType is one rotating key type as the LocalNet tests drive
// it through the real signer-side registrations.
type localnetRotatingType struct {
	keyType       string
	register      func()
	newKeyPayload func(*rotatinghybrid.Seed, [rotatinghybrid.GenesisHashSize]byte) (*keys.Payload, string, error)
}

var (
	localnetTriple = localnetRotatingType{
		keyType: rotatingkey.RotatingTripleWotsV1, register: rotatingtriplesignerreg.Register, newKeyPayload: rotatingtriplesignerreg.NewKeyPayload,
	}
	localnetXmss = localnetRotatingType{
		keyType: rotatingkey.RotatingTripleXmssV1, register: rotatingxmsssignerreg.Register, newKeyPayload: rotatingxmsssignerreg.NewKeyPayload,
	}
)

// TestRotatingTripleSignerFlowOnChain drives the signer's stateless rotating
// prepare and sign service against a live network: real chain reads through
// chainread, the stage address table as the only file, the default policy,
// and submission of the exact signed groups. It then deletes the table and
// keeps signing (the restore case), and shows that two releases from one
// stage are both signed but only one can land. Approval is user_auto_approve.
func TestRotatingTripleSignerFlowOnChain(t *testing.T) {
	runRotatingSignerFlowOnChain(t, localnetTriple)
}

// TestRotatingXmssSignerFlowOnChain runs the same flow for the XMSS triple,
// whose stages sign with leaves of a shared tree built at key creation.
func TestRotatingXmssSignerFlowOnChain(t *testing.T) {
	runRotatingSignerFlowOnChain(t, localnetXmss)
}

func TestRotatingSlhdsaSignerFlowOnChain(t *testing.T) {
	runRotatingSignerFlowOnChain(t, localnetRotatingType{
		keyType: rotatingkey.RotatingTripleSlhdsaV1, register: rotatingslhsignerreg.Register, newKeyPayload: rotatingslhsignerreg.NewKeyPayload,
	})
}

func runRotatingSignerFlowOnChain(t *testing.T, kind localnetRotatingType) {
	t.Helper()
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("funding account: %v", err)
	}
	funderAddr, err := types.DecodeAddress(funder.GetAddress())
	if err != nil {
		t.Fatal(err)
	}
	kind.register()

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatal(err)
	}
	var genesis [rotatinghybrid.GenesisHashSize]byte
	copy(genesis[:], sp.GenesisHash)
	var seed rotatinghybrid.Seed
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	defer seed.Zero()
	payload, address, err := kind.newKeyPayload(&seed, genesis)
	if err != nil {
		t.Fatal(err)
	}
	payload.ZeroSecrets()
	account, _ := types.DecodeAddress(address)
	if err := funder.FundMicroAlgosAndWait(address, 1_000_000); err != nil {
		t.Fatalf("fund rotating account: %v", err)
	}

	rk, _ := rotatingkey.Lookup(kind.keyType)
	argumentBytes := uint64(rk.MaxArgumentBytes)
	profile, err := lsigresource.Materialize(uint64(rk.MaxProgramBytes), &argumentBytes, nil,
		lsigresource.DefaultOpcodeProfile(uint64(rk.MaxOpcodeCost)))
	if err != nil {
		t.Fatal(err)
	}
	stageOps, err := coresigning.GetRotatingStageOps(kind.keyType)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{
		base64.StdEncoding.EncodeToString(genesis[:]): "itestnet",
	})
	if err != nil {
		// Built-in networks map themselves; a custom mapping is only needed
		// for LocalNet.
		resolver = apconfig.DefaultGenesisHashNetworkResolver()
	}
	reader := chainread.Reader{
		Resolver: func() apconfig.GenesisHashNetworkResolver { return resolver },
		AlgodConfig: func(string) (*apconfig.AlgodNetworkConfig, error) {
			return &apconfig.AlgodNetworkConfig{Server: testnet.AlgodURL, Token: testnet.AlgodToken}, nil
		},
		MakeClient: func(server, token string) (*algod.Client, error) { return algod.MakeClient(server, token) },
	}
	session := keystore.NewKeySession(&rotatingSeedStore{keyType: kind.keyType, seed: bytes.Clone(seed[:]), genesis: genesis[:]})
	session.InitializeSession()
	approve := true
	tables := stagetable.NewStore(storepaths.NewPaths(t.TempDir()))
	releases := &signersigning.ReleaseMemory{}
	svc := &signersigning.Service{
		Planner: &signersigning.Planner{GenesisHashResolver: resolver, Snapshot: func() signersigning.PlannerRuntimeSnapshot {
			return signersigning.PlannerRuntimeSnapshot{
				KeyFiles:    map[string]string{address: "keys/" + address + ".key"},
				KeyTypes:    map[string]string{address: kind.keyType},
				KeyMetadata: map[string]signersigning.PlannerKeyMetadata{address: {Category: keys.CategoryRotatingLsig, LogicSigResources: &profile}},
			}
		}},
		Approval:                      &signersigning.ApprovalService{UserAutoApprove: &approve},
		GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "rotating spend" },
		IsUnlocked:                    func() bool { return true },
		PolicyFor:                     func(string) *policy.Config { return policy.DefaultConfig() },
		Rotating: &signersigning.RotatingDeps{
			Chain:    reader,
			Tables:   tables,
			Locks:    &signersigning.RotatingLocks{},
			Releases: releases,
		},
	}
	secret := &coresigning.RotatingKeyMaterial{Seed: bytes.Clone(seed[:]), GenesisHash: genesis[:]}
	defer secret.Zero()
	ctx := context.Background()

	newSpend := func(t *testing.T) types.Transaction {
		t.Helper()
		sp, err := testnet.GetSuggestedParams()
		if err != nil {
			t.Fatal(err)
		}
		return types.Transaction{
			Type: types.PaymentTx,
			Header: types.Header{
				Sender:      account,
				Fee:         types.MicroAlgos(sp.MinFee),
				FirstValid:  sp.FirstRoundValid,
				LastValid:   sp.FirstRoundValid + 100,
				GenesisID:   sp.GenesisID,
				GenesisHash: genesis,
			},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: funderAddr, Amount: 1000},
		}
	}
	submit := func(t *testing.T, signed *signerapi.RotatingSignResponse) error {
		t.Helper()
		var raw bytes.Buffer
		for _, h := range signed.Signed {
			b, err := hex.DecodeString(h)
			if err != nil {
				t.Fatal(err)
			}
			raw.Write(b)
		}
		_, err := testnet.Client.SendRawTransaction(raw.Bytes()).Do(ctx)
		return err
	}
	authorizerIs := func(t *testing.T, stage uint64) {
		t.Helper()
		want, err := stageOps.StageAddress(secret, stage)
		if err != nil {
			t.Fatal(err)
		}
		info, err := testnet.Client.AccountInformation(address).Do(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if info.AuthAddr != want.String() {
			t.Fatalf("authorizer %s, want stage %d %s", info.AuthAddr, stage, want)
		}
	}

	for spend := uint64(0); spend < 3; spend++ {
		prep, svcErr := svc.PrepareRotatingWithContext(ctx, signerapi.RotatingPrepareRequest{
			Account: address, TxnBytesHex: txnutil.EncodeWithPrefixHex(newSpend(t)),
		}, session)
		if svcErr != nil {
			t.Fatalf("spend %d prepare: %v", spend, svcErr)
		}
		if prep.Stage != spend || prep.Target != spend+1 {
			t.Fatalf("spend %d prepare = stage %d target %d", spend, prep.Stage, prep.Target)
		}
		signed, svcErr := svc.SignRotatingWithContext(ctx, signerapi.RotatingSignRequest{
			Account: address, Transactions: prep.Transactions,
		}, session)
		if svcErr != nil {
			t.Fatalf("spend %d sign: %v", spend, svcErr)
		}
		if signed.Stage != spend || signed.Target != spend+1 {
			t.Fatalf("spend %d released stage %d target %d", spend, signed.Stage, signed.Target)
		}
		if err := submit(t, signed); err != nil {
			t.Fatalf("spend %d submit: %v", spend, err)
		}
		if _, err := testnet.WaitForConfirmation(signed.TxID, 10); err != nil {
			t.Fatalf("spend %d confirm %s: %v", spend, signed.TxID, err)
		}
		authorizerIs(t, spend+1)
		if rec, ok := releases.Get(address); !ok || rec.Stage != spend || rec.TxID != signed.TxID {
			t.Fatalf("spend %d release memory = %+v, %v", spend, rec, ok)
		}
		t.Logf("spend %d: stage %d released, txid %s, authorizer now stage %d", spend, signed.Stage, signed.TxID, spend+1)
	}

	// Restore: the table is the only file the signer kept, and it is a
	// cache. Delete it and keep signing; prepare scans the account's stages
	// from 0 and finds stage 3.
	table, err := tables.Table(account, genesis[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tables.Delete(address); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(table.Path()); !os.IsNotExist(statErr) {
		t.Fatal("stage table not deleted")
	}
	prep, svcErr := svc.PrepareRotatingWithContext(ctx, signerapi.RotatingPrepareRequest{
		Account: address, TxnBytesHex: txnutil.EncodeWithPrefixHex(newSpend(t)),
	}, session)
	if svcErr != nil {
		t.Fatalf("prepare after table loss: %v", svcErr)
	}
	if prep.Stage != 3 || prep.Target != 4 {
		t.Fatalf("prepare after table loss = stage %d target %d", prep.Stage, prep.Target)
	}

	// Two different releases from stage 3: both are signed (there is no
	// limit per stage), both rekey to stage 4, and only the first to land is
	// accepted by the ledger; the other is dead because its authorizer is
	// gone, not because it is a duplicate.
	otherSpend := newSpend(t)
	otherSpend.Note = []byte("second release from the same stage")
	otherPrep, svcErr := svc.PrepareRotatingWithContext(ctx, signerapi.RotatingPrepareRequest{
		Account: address, TxnBytesHex: txnutil.EncodeWithPrefixHex(otherSpend),
	}, session)
	if svcErr != nil {
		t.Fatalf("second prepare from stage 3: %v", svcErr)
	}
	if otherPrep.Stage != 3 || otherPrep.RekeyTo != prep.RekeyTo {
		t.Fatalf("second prepare = stage %d rekey %s, want stage 3 and the same target", otherPrep.Stage, otherPrep.RekeyTo)
	}
	first, svcErr := svc.SignRotatingWithContext(ctx, signerapi.RotatingSignRequest{Account: address, Transactions: prep.Transactions}, session)
	if svcErr != nil {
		t.Fatalf("first sign from stage 3: %v", svcErr)
	}
	second, svcErr := svc.SignRotatingWithContext(ctx, signerapi.RotatingSignRequest{Account: address, Transactions: otherPrep.Transactions}, session)
	if svcErr != nil {
		t.Fatalf("second sign from stage 3: %v", svcErr)
	}
	if first.TxID == second.TxID {
		t.Fatal("the two releases are the same transaction")
	}
	if err := submit(t, first); err != nil {
		t.Fatalf("submit first: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(first.TxID, 10); err != nil {
		t.Fatalf("confirm first: %v", err)
	}
	authorizerIs(t, 4)
	err = submit(t, second)
	if err == nil {
		t.Fatal("the ledger accepted a second release from a stage that no longer controls the account")
	}
	if msg := strings.ToLower(err.Error()); !strings.Contains(msg, "should have been authorized") && !strings.Contains(msg, "auth") {
		t.Fatalf("second release rejected for an unexpected reason: %v", err)
	}
	t.Logf("second release from stage 3 rejected by the ledger: %v", err)

	// Signing a stale stage-3 group now fails at the signer too: the
	// authorizer is stage 4, and the group's rekey target names stage 4,
	// which fixes the signing stage as 3.
	if _, svcErr := svc.SignRotatingWithContext(ctx, signerapi.RotatingSignRequest{Account: address, Transactions: otherPrep.Transactions}, session); svcErr == nil || svcErr.Kind != signersigning.ErrorRotatingStageChanged {
		t.Fatalf("stale group after the account moved: %v, want rotating_stage_changed", svcErr)
	}
}
