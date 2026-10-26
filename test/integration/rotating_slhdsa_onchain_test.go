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
	"github.com/aplane-algo/aplane/internal/crypto/slhdsa"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/signerops"
	"github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/stage"
	"github.com/aplane-algo/aplane/test/integration/harness"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// slhTripleDummies supplies the twelve pooled opcode units required by the ceiling.
const slhTripleDummies = 11

type slhTripleStage struct {
	keys    *signerops.StageKeys
	program stage.Program
}

type slhTripleSpend struct {
	signer       *slhTripleStage
	authorizer   types.Address
	receiver     types.Address
	amount       uint64
	rekeyTo      types.Address
	closeTo      types.Address
	window       uint64
	totalFee     uint64
	slhFrom      *slhTripleStage // sign argument 0 with another stage's key
	edFrom       *slhTripleStage // sign argument 1 with another stage's key
	falconFrom   *slhTripleStage // sign argument 2 with another stage's key
	swapArgs     bool
	dropFalcon   bool
	damageSLH    int // flip one bit of the SLH-DSA signature at this byte, when > 0
	slhLength    int // resize the valid SLH-DSA signature to this many bytes, when > 0
	damageFalcon int // flip one bit of the Falcon signature at this byte, when > 0
}

type slhTripleAccount struct {
	t       *testing.T
	testnet *harness.TestnetConfig
	address types.Address
	stages  map[uint64]*slhTripleStage
	deriver *rotatinghybrid.Deriver
}

// TestRotatingSLHTripleOnChain runs the slhTriple hybrid stage program on a real
// network with keys from its derivation. Each run uses a fresh random seed.
func TestRotatingSLHTripleOnChain(t *testing.T) {
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("funding account: %v", err)
	}
	acct := newSLHTripleAccount(t, testnet)
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

	t.Run("fee below twelve minimum fees is refused", func(t *testing.T) {
		raw, _ := acct.build(slhTripleSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s1.program.Address, totalFee: 11999,
		})
		_, err := testnet.Client.SendRawTransaction(raw).Do(context.Background())
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "fee") {
			t.Fatalf("fee 11999 error = %v, want a fee rejection", err)
		}
	})

	t.Run("accept: spend from stage 0 rotates to stage 1", func(t *testing.T) {
		acct.submitOK(slhTripleSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s1.program.Address, window: stage.MaxValidityWindow,
		})
		acct.requireAuthorizer(s1.program.Address)
	})

	t.Run("accept: spend from stage 1 rotates to stage 2", func(t *testing.T) {
		acct.submitOK(slhTripleSpend{
			signer: s1, authorizer: s1.program.Address, receiver: funderAddr, amount: 1000, rekeyTo: s2.program.Address,
		})
		acct.requireAuthorizer(s2.program.Address)
	})

	t.Run("dead stage cannot spend", func(t *testing.T) {
		raw, _ := acct.build(slhTripleSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s3.program.Address,
		})
		_, err := testnet.Client.SendRawTransaction(raw).Do(context.Background())
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "authorized") {
			t.Fatalf("dead stage spend error = %v, want an authorization mismatch", err)
		}
	})

	t.Run("accept: rotate-only zero payment to self", func(t *testing.T) {
		acct.submitOK(slhTripleSpend{
			signer: s2, authorizer: s2.program.Address, receiver: acct.address, amount: 0, rekeyTo: s3.program.Address,
		})
		acct.requireAuthorizer(s3.program.Address)
	})

	other := acct.stage(9)
	live := slhTripleSpend{
		signer: s3, authorizer: s3.program.Address, receiver: funderAddr, amount: 1000, rekeyTo: other.program.Address,
	}
	rejects := map[string]func(slhTripleSpend) slhTripleSpend{
		"no rekey":          func(s slhTripleSpend) slhTripleSpend { s.rekeyTo = types.ZeroAddress; return s },
		"rekey to sender":   func(s slhTripleSpend) slhTripleSpend { s.rekeyTo = acct.address; return s },
		"close-out":         func(s slhTripleSpend) slhTripleSpend { s.closeTo = funderAddr; return s },
		"window of 101":     func(s slhTripleSpend) slhTripleSpend { s.window = stage.MaxValidityWindow + 1; return s },
		"wrong SLH-DSA key": func(s slhTripleSpend) slhTripleSpend { s.slhFrom = other; return s },
		"wrong Ed25519 key": func(s slhTripleSpend) slhTripleSpend { s.edFrom = other; return s },
		"wrong Falcon key":  func(s slhTripleSpend) slhTripleSpend { s.falconFrom = other; return s },
		"no Falcon signature": func(s slhTripleSpend) slhTripleSpend {
			s.dropFalcon = true
			return s
		},
		"damaged Falcon signature": func(s slhTripleSpend) slhTripleSpend {
			s.damageFalcon = 40
			return s
		},
		"arguments swapped": func(s slhTripleSpend) slhTripleSpend { s.swapArgs = true; return s },
		"damaged first chain element": func(s slhTripleSpend) slhTripleSpend {
			s.damageSLH = 1
			return s
		},
		"damaged last HT authentication node": func(s slhTripleSpend) slhTripleSpend {
			s.damageSLH = slhdsa.SignatureSize - 1
			return s
		},
		"SLH-DSA signature one byte long": func(s slhTripleSpend) slhTripleSpend {
			s.slhLength = slhdsa.SignatureSize + 1
			return s
		},
		"SLH-DSA signature one byte short": func(s slhTripleSpend) slhTripleSpend {
			s.slhLength = slhdsa.SignatureSize - 1
			return s
		},
	}
	for _, offset := range []int{1, 16, 32, stage.ForsChunkSize - 1, stage.ForsChunkSize, stage.ForsChunkSize + 560, stage.ForsChunkSize + 704, stage.ForsChunkSize + 6*704} {
		rejects[fmt.Sprintf("damaged SLH byte %d", offset)] = func(s slhTripleSpend) slhTripleSpend { s.damageSLH = offset; return s }
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
			m := newSLHTripleAccountWithStage0(t, testnet, salted)
			defer m.zero()
			if err := funder.FundMicroAlgosAndWait(m.address.String(), 200_000); err != nil {
				t.Fatalf("fund measurement account: %v", err)
			}
			first := m.stage(0)
			_, group := m.build(slhTripleSpend{
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
			sig := append(append(append([]byte{}, group[0].Lsig.Args[0]...), group[0].Lsig.Args[1]...), group[0].Lsig.Args[2]...)
			pk := first.keys.PublicKeys()
			stats, err := slhdsa.VerifyStats(&slhdsa.PublicKey{Seed: pk.Seed, Root: pk.Root}, append([]byte{0, 0}, txID...), sig)
			if err != nil {
				t.Fatal(err)
			}
			steps := stats.Chain
			want := stage.OpcodeCost(steps)
			report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), testnet.Client, harness.OpcodeCeilingValidation{
				Name:          "rotating slhTriple stage",
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
			if plan.GroupSize != slhTripleDummies+1 || plan.ChargedProgramBytes != 0 {
				t.Fatalf("plan = %+v, want group of %d with no program surcharge", plan, slhTripleDummies+1)
			}
			t.Logf("measured: program %d bytes, opcode cost %d (%d steps; ceiling %d), group %d",
				wantSize, observed, steps, stage.MaxOpcodeCost, plan.GroupSize)
		})
	}
}

func newSLHTripleAccountWithStage0(t *testing.T, testnet *harness.TestnetConfig, salted bool) *slhTripleAccount {
	t.Helper()
	for range 64 {
		acct := newSLHTripleAccount(t, testnet)
		if acct.stage(0).program.Salted == salted {
			return acct
		}
		acct.zero()
	}
	t.Fatalf("no account with salted=%v stage 0 in 64 tries", salted)
	return nil
}

func newSLHTripleAccount(t *testing.T, testnet *harness.TestnetConfig) *slhTripleAccount {
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
	acct := &slhTripleAccount{t: t, testnet: testnet, stages: map[uint64]*slhTripleStage{}, deriver: d}
	acct.address = acct.stage(0).program.Address
	return acct
}

func (a *slhTripleAccount) stage(i uint64) *slhTripleStage {
	a.t.Helper()
	if s, ok := a.stages[i]; ok {
		return s
	}
	keys, program, err := signerops.DeriveStage(a.deriver, i)
	if err != nil {
		a.t.Fatalf("derive stage %d: %v", i, err)
	}
	s := &slhTripleStage{keys: keys, program: program}
	a.stages[i] = s
	return s
}

func (a *slhTripleAccount) zero() {
	for _, s := range a.stages {
		s.keys.Zero()
	}
	a.deriver.Zero()
}

// build returns the encoded signed group and its decoded form: the spend at
// index 0, signed by the stage LogicSig, and the dummies that pool the
// argument and opcode budgets.
func (a *slhTripleAccount) build(spend slhTripleSpend) ([]byte, []types.SignedTxn) {
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
	txn.Fee = types.MicroAlgos(1000 * (slhTripleDummies + 1))
	if spend.totalFee != 0 {
		txn.Fee = types.MicroAlgos(spend.totalFee)
	}

	dummies, err := signing.CreateDummyTransactions(slhTripleDummies, sp)
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
	slhSigner, edSigner := spend.signer, spend.signer
	if spend.slhFrom != nil {
		slhSigner = spend.slhFrom
	}
	if spend.edFrom != nil {
		edSigner = spend.edFrom
	}
	falconSigner := spend.signer
	if spend.falconFrom != nil {
		falconSigner = spend.falconFrom
	}
	slhSig, _, _, err := slhSigner.keys.Sign(txID)
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
	if spend.damageSLH > 0 {
		slhSig[spend.damageSLH] ^= 0x01
	}
	if spend.slhLength > len(slhSig) {
		slhSig = append(slhSig, make([]byte, spend.slhLength-len(slhSig))...)
	} else if spend.slhLength > 0 {
		slhSig = slhSig[:spend.slhLength]
	}
	if spend.damageFalcon > 0 {
		falconSig[spend.damageFalcon] ^= 0x01
	}
	args := [][]byte{slhSig[:stage.ForsChunkSize], slhSig[stage.ForsChunkSize : stage.ForsChunkSize+stage.FirstHTChunkSize], slhSig[stage.ForsChunkSize+stage.FirstHTChunkSize:], edSig, falconSig}
	if spend.swapArgs {
		args[0], args[3] = args[3], args[0]
	}
	if spend.dropFalcon {
		args = args[:4]
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

func (a *slhTripleAccount) submitOK(spend slhTripleSpend) {
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

func (a *slhTripleAccount) requireAuthorizer(want types.Address) {
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
