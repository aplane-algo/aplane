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
	"github.com/aplane-algo/aplane/internal/crypto/wots"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingtriple/signerops"
	"github.com/aplane-algo/aplane/lsig/rotatingtriple/stage"
	"github.com/aplane-algo/aplane/test/integration/harness"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// tripleDummies is the number of resource dummies a triple stage spend
// needs: its three signatures need four pooled transactions (the worst-case
// opcode cost needs three).
const tripleDummies = 3

type tripleStage struct {
	keys    *signerops.StageKeys
	program stage.Program
}

type tripleSpend struct {
	signer       *tripleStage
	authorizer   types.Address
	receiver     types.Address
	amount       uint64
	rekeyTo      types.Address
	closeTo      types.Address
	window       uint64
	totalFee     uint64
	wotsFrom     *tripleStage // sign argument 0 with another stage's key
	edFrom       *tripleStage // sign argument 1 with another stage's key
	falconFrom   *tripleStage // sign argument 2 with another stage's key
	swapArgs     bool
	dropFalcon   bool
	damageWots   int // flip one bit of the WOTS signature at this byte, when > 0
	damageFalcon int // flip one bit of the Falcon signature at this byte, when > 0
}

type tripleAccount struct {
	t       *testing.T
	testnet *harness.TestnetConfig
	address types.Address
	stages  map[uint64]*tripleStage
	deriver *rotatinghybrid.Deriver
}

// TestRotatingTripleOnChain runs the triple hybrid stage program on a real
// network with keys from its derivation. Each run uses a fresh random seed.
func TestRotatingTripleOnChain(t *testing.T) {
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("funding account: %v", err)
	}
	acct := newTripleAccount(t, testnet)
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
	acct.requireAuthorizer(types.ZeroAddress)

	t.Run("fee below four minimum fees is refused", func(t *testing.T) {
		raw, _ := acct.build(tripleSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s1.program.Address, totalFee: 3999,
		})
		_, err := testnet.Client.SendRawTransaction(raw).Do(context.Background())
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "fee") {
			t.Fatalf("fee 3999 error = %v, want a fee rejection", err)
		}
	})

	t.Run("accept: spend from stage 0 rotates to stage 1", func(t *testing.T) {
		acct.submitOK(tripleSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s1.program.Address, window: stage.MaxValidityWindow,
		})
		acct.requireAuthorizer(s1.program.Address)
	})

	t.Run("accept: spend from stage 1 rotates to stage 2", func(t *testing.T) {
		acct.submitOK(tripleSpend{
			signer: s1, authorizer: s1.program.Address, receiver: funderAddr, amount: 1000, rekeyTo: s2.program.Address,
		})
		acct.requireAuthorizer(s2.program.Address)
	})

	t.Run("dead stage cannot spend", func(t *testing.T) {
		raw, _ := acct.build(tripleSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s3.program.Address,
		})
		_, err := testnet.Client.SendRawTransaction(raw).Do(context.Background())
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "authorized") {
			t.Fatalf("dead stage spend error = %v, want an authorization mismatch", err)
		}
	})

	t.Run("accept: rotate-only zero payment to self", func(t *testing.T) {
		acct.submitOK(tripleSpend{
			signer: s2, authorizer: s2.program.Address, receiver: acct.address, amount: 0, rekeyTo: s3.program.Address,
		})
		acct.requireAuthorizer(s3.program.Address)
	})

	other := acct.stage(9)
	live := tripleSpend{
		signer: s3, authorizer: s3.program.Address, receiver: funderAddr, amount: 1000, rekeyTo: other.program.Address,
	}
	rejects := map[string]func(tripleSpend) tripleSpend{
		"no rekey":          func(s tripleSpend) tripleSpend { s.rekeyTo = types.ZeroAddress; return s },
		"rekey to sender":   func(s tripleSpend) tripleSpend { s.rekeyTo = acct.address; return s },
		"close-out":         func(s tripleSpend) tripleSpend { s.closeTo = funderAddr; return s },
		"window of 101":     func(s tripleSpend) tripleSpend { s.window = stage.MaxValidityWindow + 1; return s },
		"wrong WOTS key":    func(s tripleSpend) tripleSpend { s.wotsFrom = other; return s },
		"wrong Ed25519 key": func(s tripleSpend) tripleSpend { s.edFrom = other; return s },
		"wrong Falcon key":  func(s tripleSpend) tripleSpend { s.falconFrom = other; return s },
		"no Falcon signature": func(s tripleSpend) tripleSpend {
			s.dropFalcon = true
			return s
		},
		"damaged Falcon signature": func(s tripleSpend) tripleSpend {
			s.damageFalcon = 40
			return s
		},
		"arguments swapped": func(s tripleSpend) tripleSpend { s.swapArgs = true; return s },
		"damaged first chain element": func(s tripleSpend) tripleSpend {
			s.damageWots = 1
			return s
		},
		"damaged last chain element": func(s tripleSpend) tripleSpend {
			s.damageWots = wots.SignatureSize - 1
			return s
		},
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

	// Measure both program shapes. The node's budget report must equal the
	// cost model for the spend's TxID and stay under the declared ceiling.
	for _, salted := range []bool{false, true} {
		t.Run(fmt.Sprintf("measure: opcode cost and group plan (salted=%v)", salted), func(t *testing.T) {
			m := newTripleAccountWithStage0(t, testnet, salted)
			defer m.zero()
			if err := funder.FundMicroAlgosAndWait(m.address.String(), 200_000); err != nil {
				t.Fatalf("fund measurement account: %v", err)
			}
			first := m.stage(0)
			_, group := m.build(tripleSpend{
				signer: first, receiver: funderAddr, amount: 1000, rekeyTo: m.stage(1).program.Address,
			})
			wantSize := stage.UnsaltedProgramSize
			if salted {
				wantSize = stage.SaltedProgramSize
			}
			if len(first.program.Bytecode) != wantSize {
				t.Fatalf("program is %d bytes, want %d", len(first.program.Bytecode), wantSize)
			}
			txID := algocrypto.TransactionID(group[0].Txn)
			steps, err := wots.VerifySteps(txID)
			if err != nil {
				t.Fatal(err)
			}
			want := stage.OpcodeCost(steps)
			if salted {
				want++
			}
			report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), testnet.Client, harness.OpcodeCeilingValidation{
				Name:          "rotating triple stage",
				FinalProgram:  first.program.Bytecode,
				Profile:       lsigresource.DefaultOpcodeProfile(stage.MaxOpcodeCost),
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
				t.Fatalf("observed opcode cost %d, cost model %d for %d chain steps", observed, want, steps)
			}
			if observed > stage.MaxOpcodeCost {
				t.Fatalf("observed %d exceeds the declared ceiling %d", observed, stage.MaxOpcodeCost)
			}

			consensus, err := lsigresource.CurrentConsensus()
			if err != nil {
				t.Fatal(err)
			}
			plan, err := lsigresource.Solve(consensus, lsigresource.PlanInput{
				TransactionCount: 1,
				LogicSigs: []lsigresource.Usage{{
					ProgramBytes: uint64(wantSize), ArgumentBytes: stage.MaxArgumentBytes, MaxOpcodeCost: stage.MaxOpcodeCost,
				}},
				Dummy: lsigresource.Usage{ProgramBytes: uint64(len(group[1].Lsig.Logic)), MaxOpcodeCost: 1},
			})
			if err != nil {
				t.Fatalf("solve: %v", err)
			}
			if plan.GroupSize != tripleDummies+1 || plan.ChargedProgramBytes != 0 {
				t.Fatalf("plan = %+v, want group of %d with no program surcharge", plan, tripleDummies+1)
			}
			t.Logf("measured: program %d bytes, opcode cost %d (%d steps; ceiling %d), group %d",
				wantSize, observed, steps, stage.MaxOpcodeCost, plan.GroupSize)
		})
	}
}

func newTripleAccountWithStage0(t *testing.T, testnet *harness.TestnetConfig, salted bool) *tripleAccount {
	t.Helper()
	for range 64 {
		acct := newTripleAccount(t, testnet)
		if acct.stage(0).program.Salted == salted {
			return acct
		}
		acct.zero()
	}
	t.Fatalf("no account with salted=%v stage 0 in 64 tries", salted)
	return nil
}

func newTripleAccount(t *testing.T, testnet *harness.TestnetConfig) *tripleAccount {
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
	d, err := signerops.NewDeriver(&seed, genesis)
	if err != nil {
		t.Fatal(err)
	}
	acct := &tripleAccount{t: t, testnet: testnet, stages: map[uint64]*tripleStage{}, deriver: d}
	acct.address = acct.stage(0).program.Address
	return acct
}

func (a *tripleAccount) stage(i uint64) *tripleStage {
	a.t.Helper()
	if s, ok := a.stages[i]; ok {
		return s
	}
	keys, program, err := signerops.DeriveStage(a.deriver, i)
	if err != nil {
		a.t.Fatalf("derive stage %d: %v", i, err)
	}
	s := &tripleStage{keys: keys, program: program}
	a.stages[i] = s
	return s
}

func (a *tripleAccount) zero() {
	for _, s := range a.stages {
		s.keys.Zero()
	}
	a.deriver.Zero()
}

// build returns the encoded signed group and its decoded form: the spend at
// index 0, signed by the stage LogicSig, and the dummies that pool the
// argument and opcode budgets.
func (a *tripleAccount) build(spend tripleSpend) ([]byte, []types.SignedTxn) {
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

	txn, err := transaction.MakePaymentTxn(a.address.String(), spend.receiver.String(), spend.amount, nil, "", sp)
	if err != nil {
		a.t.Fatal(err)
	}
	txn.RekeyTo = spend.rekeyTo
	txn.CloseRemainderTo = spend.closeTo
	txn.Fee = types.MicroAlgos(1000 * (tripleDummies + 1))
	if spend.totalFee != 0 {
		txn.Fee = types.MicroAlgos(spend.totalFee)
	}

	dummies, err := signing.CreateDummyTransactions(tripleDummies, sp)
	if err != nil {
		a.t.Fatal(err)
	}
	group := append([]types.Transaction{txn}, dummies...)
	gid, err := algocrypto.ComputeGroupID(group)
	if err != nil {
		a.t.Fatal(err)
	}
	for i := range group {
		group[i].Group = gid
	}

	txID := algocrypto.TransactionID(group[0])
	wotsSigner, edSigner := spend.signer, spend.signer
	if spend.wotsFrom != nil {
		wotsSigner = spend.wotsFrom
	}
	if spend.edFrom != nil {
		edSigner = spend.edFrom
	}
	falconSigner := spend.signer
	if spend.falconFrom != nil {
		falconSigner = spend.falconFrom
	}
	wotsSig, _, _, err := wotsSigner.keys.Sign(txID)
	if err != nil {
		a.t.Fatal(err)
	}
	_, edSig, _, err := edSigner.keys.Sign(txID)
	if err != nil {
		a.t.Fatal(err)
	}
	_, _, falconSig, err := falconSigner.keys.Sign(txID)
	if err != nil {
		a.t.Fatal(err)
	}
	if spend.damageWots > 0 {
		wotsSig[spend.damageWots] ^= 0x01
	}
	if spend.damageFalcon > 0 {
		falconSig[spend.damageFalcon] ^= 0x01
	}
	args := [][]byte{wotsSig, edSig, falconSig}
	if spend.swapArgs {
		args = [][]byte{edSig, wotsSig, falconSig}
	}
	if spend.dropFalcon {
		args = args[:2]
	}

	signed := types.SignedTxn{
		Txn:  group[0],
		Lsig: types.LogicSig{Logic: spend.signer.program.Bytecode, Args: args},
	}
	if spend.authorizer != types.ZeroAddress && spend.authorizer != a.address {
		signed.AuthAddr = spend.authorizer
	}
	stxns := []types.SignedTxn{signed}
	for _, d := range group[1:] {
		dummy, err := signing.SignDummyTransaction(d)
		if err != nil {
			a.t.Fatal(err)
		}
		stxns = append(stxns, dummy)
	}
	var raw bytes.Buffer
	for _, s := range stxns {
		raw.Write(msgpack.Encode(s))
	}
	return raw.Bytes(), stxns
}

func (a *tripleAccount) submitOK(spend tripleSpend) {
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

func (a *tripleAccount) requireAuthorizer(want types.Address) {
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
