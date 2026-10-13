// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatinghybrid/signerops"
	"github.com/aplane-algo/aplane/lsig/rotatinghybrid/stage"
	"github.com/aplane-algo/aplane/test/integration/harness"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// rotatingStage is one derived stage of the test account.
type rotatingStage struct {
	keys    *signerops.StageKeys
	program stage.Program
}

// rotatingSpend describes one spend from the rotating account. The zero
// value of each override keeps the protocol-conforming default.
type rotatingSpend struct {
	signer      *rotatingStage
	authorizer  types.Address // on-chain authorizer, for SignedTxn.AuthAddr
	receiver    types.Address
	amount      uint64
	rekeyTo     types.Address
	closeTo     types.Address
	window      uint64
	totalFee    uint64
	falconFrom  *rotatingStage // sign argument 0 with another stage's key
	ed25519From *rotatingStage // sign argument 1 with another stage's key
	swapArgs    bool
}

type rotatingAccount struct {
	t       *testing.T
	testnet *harness.TestnetConfig
	address types.Address
	stages  map[uint64]*rotatingStage
	deriver *rotatinghybrid.Deriver
}

// TestRotatingHybridOnChain runs the stage program on a real network with
// keys from the Phase 1 derivation. It has no signer integration: the test
// signs stage transactions directly. Each run uses a fresh random seed.
func TestRotatingHybridOnChain(t *testing.T) {
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("funding account: %v", err)
	}
	acct := newRotatingAccount(t, testnet)
	defer acct.zero()
	funderAddr, err := types.DecodeAddress(funder.GetAddress())
	if err != nil {
		t.Fatal(err)
	}

	s0, s1, s2, s3 := acct.stage(0), acct.stage(1), acct.stage(2), acct.stage(3)
	t.Logf("account %s; stage program sizes %d/%d/%d/%d",
		acct.address, len(s0.program.Bytecode), len(s1.program.Bytecode), len(s2.program.Bytecode), len(s3.program.Bytecode))
	if err := funder.FundMicroAlgosAndWait(acct.address.String(), 1_000_000); err != nil {
		t.Fatalf("fund rotating account: %v", err)
	}

	// The account address is stage 0's program address, so stage 0 starts
	// in control with no AuthAddr set.
	acct.requireAuthorizer(types.ZeroAddress)

	t.Run("fee below two minimum fees is refused", func(t *testing.T) {
		raw, _ := acct.build(rotatingSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s1.program.Address, totalFee: 1999,
		})
		_, err := testnet.Client.SendRawTransaction(raw).Do(context.Background())
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "fee") {
			t.Fatalf("fee 1999 error = %v, want a fee rejection", err)
		}
	})

	t.Run("accept: spend from stage 0 rotates to stage 1", func(t *testing.T) {
		acct.submitOK(rotatingSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s1.program.Address, window: stage.MaxValidityWindow,
		})
		acct.requireAuthorizer(s1.program.Address)
	})

	t.Run("accept: spend from stage 1 rotates to stage 2", func(t *testing.T) {
		acct.submitOK(rotatingSpend{
			signer: s1, authorizer: s1.program.Address, receiver: funderAddr, amount: 1000, rekeyTo: s2.program.Address,
		})
		acct.requireAuthorizer(s2.program.Address)
	})

	t.Run("dead stage cannot spend", func(t *testing.T) {
		raw, _ := acct.build(rotatingSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s3.program.Address,
		})
		_, err := testnet.Client.SendRawTransaction(raw).Do(context.Background())
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "authorized") {
			t.Fatalf("dead stage spend error = %v, want an authorization mismatch", err)
		}
	})

	t.Run("accept: rotate-only zero payment to self", func(t *testing.T) {
		acct.submitOK(rotatingSpend{
			signer: s2, authorizer: s2.program.Address, receiver: acct.address, amount: 0, rekeyTo: s3.program.Address,
		})
		acct.requireAuthorizer(s3.program.Address)
	})

	// Freshness of the rekey target is a signer guarantee, not an on-chain
	// one: the program accepts a rekey to the current authorizer.
	t.Run("accept: rekey to current authorizer is not enforced on-chain", func(t *testing.T) {
		acct.submitOK(rotatingSpend{
			signer: s3, authorizer: s3.program.Address, receiver: funderAddr, amount: 1000, rekeyTo: s3.program.Address,
		})
		acct.requireAuthorizer(s3.program.Address)
	})

	other := acct.stage(9)
	live := rotatingSpend{
		signer: s3, authorizer: s3.program.Address, receiver: funderAddr, amount: 1000, rekeyTo: other.program.Address,
	}
	rejects := map[string]func(rotatingSpend) rotatingSpend{
		"no rekey":          func(s rotatingSpend) rotatingSpend { s.rekeyTo = types.ZeroAddress; return s },
		"rekey to sender":   func(s rotatingSpend) rotatingSpend { s.rekeyTo = acct.address; return s },
		"close-out":         func(s rotatingSpend) rotatingSpend { s.closeTo = funderAddr; return s },
		"window of 101":     func(s rotatingSpend) rotatingSpend { s.window = stage.MaxValidityWindow + 1; return s },
		"wrong Falcon key":  func(s rotatingSpend) rotatingSpend { s.falconFrom = other; return s },
		"wrong Ed25519 key": func(s rotatingSpend) rotatingSpend { s.ed25519From = other; return s },
		"arguments swapped": func(s rotatingSpend) rotatingSpend { s.swapArgs = true; return s },
	}
	for name, mutate := range rejects {
		t.Run("reject: "+name, func(t *testing.T) {
			raw, _ := acct.build(mutate(live))
			_, err := testnet.Client.SendRawTransaction(raw).Do(context.Background())
			if err == nil {
				t.Fatal("submission unexpectedly succeeded")
			}
			lower := strings.ToLower(err.Error())
			if !strings.Contains(lower, "rejected by logic") && !strings.Contains(lower, "logic eval") {
				t.Fatalf("failed for a non-LogicSig reason: %v", err)
			}
		})
	}
	acct.requireAuthorizer(s3.program.Address)

	// Measure both program shapes. Each case uses a fresh account whose
	// stage 0 has the wanted shape, simulated rather than submitted.
	for _, salted := range []bool{false, true} {
		t.Run(fmt.Sprintf("measure: opcode cost and group plan (salted=%v)", salted), func(t *testing.T) {
			m := newRotatingAccountWithStage0(t, testnet, salted)
			defer m.zero()
			if err := funder.FundMicroAlgosAndWait(m.address.String(), 200_000); err != nil {
				t.Fatalf("fund measurement account: %v", err)
			}
			first := m.stage(0)
			_, group := m.build(rotatingSpend{
				signer: first, receiver: funderAddr, amount: 1000, rekeyTo: m.stage(1).program.Address,
			})

			want := uint64(stage.OpcodeCost)
			wantSize := stage.UnsaltedProgramSize
			if salted {
				want, wantSize = stage.SaltedOpcodeCost, stage.SaltedProgramSize
			}
			if len(first.program.Bytecode) != wantSize {
				t.Fatalf("program is %d bytes, want %d", len(first.program.Bytecode), wantSize)
			}
			report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), testnet.Client, harness.OpcodeCeilingValidation{
				Name:          "rotating hybrid stage",
				FinalProgram:  first.program.Bytecode,
				Profile:       lsigresource.DefaultOpcodeProfile(want),
				RequiredPaths: []lsigresource.AuthorizationPath{lsigresource.PathDefault},
				Vectors: []harness.OpcodeCeilingVector{{
					Name: "rotating spend", Path: lsigresource.PathDefault, SignedTxns: group, LSigIndex: 0,
				}},
			})
			if err != nil {
				t.Fatalf("opcode ceiling: %v", err)
			}
			observed := report.Paths[lsigresource.PathDefault].MaximumObserved
			if observed != want {
				t.Fatalf("observed opcode cost %d, computed %d", observed, want)
			}

			consensus, err := lsigresource.CurrentConsensus()
			if err != nil {
				t.Fatal(err)
			}
			plan, err := lsigresource.Solve(consensus, lsigresource.PlanInput{
				TransactionCount: 1,
				LogicSigs: []lsigresource.Usage{{
					ProgramBytes: uint64(wantSize), ArgumentBytes: stage.MaxArgumentBytes, MaxOpcodeCost: want,
				}},
				Dummy: lsigresource.Usage{ProgramBytes: uint64(len(group[1].Lsig.Logic)), MaxOpcodeCost: 1},
			})
			if err != nil {
				t.Fatalf("solve: %v", err)
			}
			if plan.GroupSize != 2 || plan.ChargedProgramBytes != 0 {
				t.Fatalf("plan = %+v, want group of 2 with no program surcharge", plan)
			}
			t.Logf("measured: program %d bytes, opcode cost %d, group %d, fee 2000 microAlgos",
				wantSize, observed, plan.GroupSize)
		})
	}
}

// newRotatingAccountWithStage0 draws fresh seeds until stage 0's program has
// the wanted shape; about half of all programs need salt.
func newRotatingAccountWithStage0(t *testing.T, testnet *harness.TestnetConfig, salted bool) *rotatingAccount {
	t.Helper()
	for range 64 {
		acct := newRotatingAccount(t, testnet)
		if acct.stage(0).program.Salted == salted {
			return acct
		}
		acct.zero()
	}
	t.Fatalf("no account with salted=%v stage 0 in 64 tries", salted)
	return nil
}

func newRotatingAccount(t *testing.T, testnet *harness.TestnetConfig) *rotatingAccount {
	t.Helper()
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
	d, err := rotatinghybrid.NewDeriver(&seed, genesis)
	if err != nil {
		t.Fatal(err)
	}
	acct := &rotatingAccount{t: t, testnet: testnet, stages: map[uint64]*rotatingStage{}, deriver: d}
	acct.address = acct.stage(0).program.Address
	return acct
}

func (a *rotatingAccount) stage(i uint64) *rotatingStage {
	a.t.Helper()
	if s, ok := a.stages[i]; ok {
		return s
	}
	keys, program, err := signerops.DeriveStage(a.deriver, i)
	if err != nil {
		a.t.Fatalf("derive stage %d: %v", i, err)
	}
	s := &rotatingStage{keys: keys, program: program}
	a.stages[i] = s
	return s
}

func (a *rotatingAccount) zero() {
	for _, s := range a.stages {
		s.keys.Zero()
	}
	a.deriver.Zero()
}

// build returns the encoded signed group and its decoded form: the spend at
// index 0, signed by the stage LogicSig, and one dummy that pools the
// argument budget.
func (a *rotatingAccount) build(spend rotatingSpend) ([]byte, []types.SignedTxn) {
	a.t.Helper()
	sp, err := a.testnet.GetSuggestedParams()
	if err != nil {
		a.t.Fatal(err)
	}
	window := spend.window
	if window == 0 {
		window = 50
	}
	sp.LastRoundValid = sp.FirstRoundValid + types.Round(window)
	sp.FlatFee = true

	txn, err := transaction.MakePaymentTxn(
		a.address.String(), spend.receiver.String(), spend.amount, nil, "", sp,
	)
	if err != nil {
		a.t.Fatal(err)
	}
	txn.RekeyTo = spend.rekeyTo
	txn.CloseRemainderTo = spend.closeTo
	txn.Fee = 2000
	if spend.totalFee != 0 {
		txn.Fee = types.MicroAlgos(spend.totalFee)
	}

	dummies, err := signing.CreateDummyTransactions(1, sp)
	if err != nil {
		a.t.Fatal(err)
	}
	group := []types.Transaction{txn, dummies[0]}
	gid, err := algocrypto.ComputeGroupID(group)
	if err != nil {
		a.t.Fatal(err)
	}
	for i := range group {
		group[i].Group = gid
	}

	txID := algocrypto.TransactionID(group[0])
	falconSigner, edSigner := spend.signer, spend.signer
	if spend.falconFrom != nil {
		falconSigner = spend.falconFrom
	}
	if spend.ed25519From != nil {
		edSigner = spend.ed25519From
	}
	falconSig, _, err := falconSigner.keys.Sign(txID)
	if err != nil {
		a.t.Fatal(err)
	}
	_, edSig, err := edSigner.keys.Sign(txID)
	if err != nil {
		a.t.Fatal(err)
	}
	args := [][]byte{falconSig, edSig}
	if spend.swapArgs {
		args = [][]byte{edSig, falconSig}
	}

	signed := types.SignedTxn{
		Txn:  group[0],
		Lsig: types.LogicSig{Logic: spend.signer.program.Bytecode, Args: args},
	}
	if spend.authorizer != types.ZeroAddress && spend.authorizer != a.address {
		signed.AuthAddr = spend.authorizer
	}
	dummy, err := signing.SignDummyTransaction(group[1])
	if err != nil {
		a.t.Fatal(err)
	}

	stxns := []types.SignedTxn{signed, dummy}
	var raw bytes.Buffer
	for _, s := range stxns {
		raw.Write(msgpack.Encode(s))
	}
	return raw.Bytes(), stxns
}

func (a *rotatingAccount) submitOK(spend rotatingSpend) {
	a.t.Helper()
	raw, group := a.build(spend)
	if _, err := a.testnet.Client.SendRawTransaction(raw).Do(context.Background()); err != nil {
		a.t.Fatalf("submit: %v", err)
	}
	txid := algocrypto.GetTxID(group[0].Txn)
	if _, err := a.testnet.WaitForConfirmation(txid, 10); err != nil {
		a.t.Fatalf("confirm %s: %v", txid, err)
	}
}

// requireAuthorizer checks the account's on-chain AuthAddr; the zero address
// means none is set and the account address itself authorizes.
func (a *rotatingAccount) requireAuthorizer(want types.Address) {
	a.t.Helper()
	info, err := a.testnet.Client.AccountInformation(a.address.String()).Do(context.Background())
	if err != nil {
		a.t.Fatal(err)
	}
	got := types.ZeroAddress
	if info.AuthAddr != "" {
		if got, err = types.DecodeAddress(info.AuthAddr); err != nil {
			a.t.Fatal(err)
		}
	}
	if got != want {
		a.t.Fatalf("authorizer = %s, want %s", got, want)
	}
}
