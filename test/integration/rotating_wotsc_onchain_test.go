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
	"github.com/aplane-algo/aplane/internal/crypto/wotsc"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/signerops"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/stage"
	"github.com/aplane-algo/aplane/test/integration/harness"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// wotscDummies supplies the pooled argument bytes: 2,115 bytes need a group
// of three.
const wotscDummies = 2

type wotscStage struct {
	keys    *signerops.StageKeys
	program stage.Program
}

type wotscSpend struct {
	signer       *wotscStage
	authorizer   types.Address
	receiver     types.Address
	amount       uint64
	rekeyTo      types.Address
	closeTo      types.Address
	window       uint64
	totalFee     uint64
	leaf         *uint32     // default: the TxID's pick, as the signer makes it
	hashFrom     *wotscStage // sign the WOTS+C argument with another stage's key
	edFrom       *wotscStage // sign the Ed25519 argument with another stage's key
	falconFrom   *wotscStage // sign the Falcon argument with another stage's key
	swapArgs     bool
	dropFalcon   bool
	damageHash   int // flip one bit of the WOTS+C signature at this byte, when > 0
	hashLength   int // resize the valid WOTS+C signature to this many bytes, when > 0
	setLeaf      *uint32
	damageFalcon int // flip one bit of the Falcon signature at this byte, when > 0
}

type wotscAccount struct {
	t       *testing.T
	testnet *harness.TestnetConfig
	address types.Address
	stages  map[uint64]*wotscStage
	deriver *rotatinghybrid.Deriver
}

// TestRotatingWOTSCTripleOnChain runs the WOTS+C stage program on a real network
// with keys from its derivation. Each run uses a fresh random seed.
func TestRotatingWOTSCTripleOnChain(t *testing.T) {
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("funding account: %v", err)
	}
	acct := newWOTSCAccount(t, testnet)
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

	t.Run("fee below the group minimum is refused", func(t *testing.T) {
		underpaid := uint64(1000*(wotscDummies+1) - 1)
		raw, _ := acct.build(wotscSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s1.program.Address, totalFee: underpaid,
		})
		_, err := testnet.Client.SendRawTransaction(raw).Do(context.Background())
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "fee") {
			t.Fatalf("fee %d error = %v, want a fee rejection", underpaid, err)
		}
	})

	t.Run("accept: spend from stage 0 rotates to stage 1", func(t *testing.T) {
		acct.submitOK(wotscSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s1.program.Address, window: stage.MaxValidityWindow,
		})
		acct.requireAuthorizer(s1.program.Address)
	})

	t.Run("accept: spend from stage 1 rotates to stage 2", func(t *testing.T) {
		acct.submitOK(wotscSpend{
			signer: s1, authorizer: s1.program.Address, receiver: funderAddr, amount: 1000, rekeyTo: s2.program.Address,
		})
		acct.requireAuthorizer(s2.program.Address)
	})

	t.Run("dead stage cannot spend", func(t *testing.T) {
		raw, _ := acct.build(wotscSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s3.program.Address,
		})
		_, err := testnet.Client.SendRawTransaction(raw).Do(context.Background())
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "authorized") {
			t.Fatalf("dead stage spend error = %v, want an authorization mismatch", err)
		}
	})

	t.Run("accept: rotate-only zero payment to self", func(t *testing.T) {
		acct.submitOK(wotscSpend{
			signer: s2, authorizer: s2.program.Address, receiver: acct.address, amount: 0, rekeyTo: s3.program.Address,
		})
		acct.requireAuthorizer(s3.program.Address)
	})

	other := acct.stage(9)
	live := wotscSpend{
		signer: s3, authorizer: s3.program.Address, receiver: funderAddr, amount: 1000, rekeyTo: other.program.Address,
	}
	leafOutside := uint32(wotsc.Leaves)
	rejects := map[string]func(wotscSpend) wotscSpend{
		"no rekey":          func(s wotscSpend) wotscSpend { s.rekeyTo = types.ZeroAddress; return s },
		"rekey to sender":   func(s wotscSpend) wotscSpend { s.rekeyTo = acct.address; return s },
		"close-out":         func(s wotscSpend) wotscSpend { s.closeTo = funderAddr; return s },
		"window of 101":     func(s wotscSpend) wotscSpend { s.window = stage.MaxValidityWindow + 1; return s },
		"wrong WOTS+C key":  func(s wotscSpend) wotscSpend { s.hashFrom = other; return s },
		"wrong Ed25519 key": func(s wotscSpend) wotscSpend { s.edFrom = other; return s },
		"wrong Falcon key":  func(s wotscSpend) wotscSpend { s.falconFrom = other; return s },
		"no Falcon signature": func(s wotscSpend) wotscSpend {
			s.dropFalcon = true
			return s
		},
		"damaged Falcon signature": func(s wotscSpend) wotscSpend {
			s.damageFalcon = 40
			return s
		},
		"arguments swapped":      func(s wotscSpend) wotscSpend { s.swapArgs = true; return s },
		"leaf outside the tree":  func(s wotscSpend) wotscSpend { s.setLeaf = &leafOutside; return s },
		"signature one too long": func(s wotscSpend) wotscSpend { s.hashLength = wotsc.SignatureSize + 1; return s },
		"signature one too short": func(s wotscSpend) wotscSpend {
			s.hashLength = wotsc.SignatureSize - 1
			return s
		},
	}
	for _, offset := range []int{1, 4, 19, 20, 35, 531, 532, wotsc.SignatureSize - 1} {
		rejects[fmt.Sprintf("damaged WOTS+C byte %d", offset)] = func(s wotscSpend) wotscSpend { s.damageHash = offset; return s }
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

	// Every accepted run must cost exactly the same on the node, whatever the
	// program's salt, the leaf or the digest: the fixed digit sum fixes the
	// number of chain steps.
	for _, salted := range []bool{false, true} {
		t.Run(fmt.Sprintf("measure: opcode cost and group plan (salted=%v)", salted), func(t *testing.T) {
			m := newWOTSCAccountWithStage0(t, testnet, salted)
			defer m.zero()
			if err := funder.FundMicroAlgosAndWait(m.address.String(), 200_000); err != nil {
				t.Fatalf("fund measurement account: %v", err)
			}
			first := m.stage(0)
			wantSize := stage.UnsaltedProgramSize
			if salted {
				wantSize = stage.SaltedProgramSize
			}
			if len(first.program.Bytecode) != wantSize {
				t.Fatalf("program is %d bytes, want %d", len(first.program.Bytecode), wantSize)
			}
			next := m.stage(1).program.Address
			var group []types.SignedTxn
			for i, leaf := range []uint32{0, 1, 31, 32, 62, 63} {
				_, group = m.build(wotscSpend{
					signer: first, receiver: funderAddr, amount: uint64(1000 + i), rekeyTo: next, leaf: &leaf,
				})
				report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), testnet.Client, harness.OpcodeCeilingValidation{
					Name:          "rotating WOTS+C stage",
					FinalProgram:  first.program.Bytecode,
					Profile:       lsigresource.DefaultOpcodeProfile(uint64(stage.MaxOpcodeCost)),
					RequiredPaths: []lsigresource.AuthorizationPath{lsigresource.PathDefault},
					Vectors: []harness.OpcodeCeilingVector{{
						Name: "rotating spend", Path: lsigresource.PathDefault, SignedTxns: group, LSigIndex: 0,
					}},
				})
				if err != nil {
					t.Fatalf("leaf %d: opcode ceiling: %v", leaf, err)
				}
				observed := report.Paths[lsigresource.PathDefault].MaximumObserved
				t.Logf("leaf %d: observed opcode cost %d", leaf, observed)
				if observed != uint64(stage.MaxOpcodeCost) {
					t.Fatalf("leaf %d: observed opcode cost %d, cost model %d", leaf, observed, stage.MaxOpcodeCost)
				}
			}

			consensus, err := lsigresource.CurrentConsensus()
			if err != nil {
				t.Fatal(err)
			}
			plan, err := lsigresource.Solve(consensus, lsigresource.PlanInput{
				TransactionCount: 1,
				LogicSigs: []lsigresource.Usage{{
					ProgramBytes: uint64(wantSize), ArgumentBytes: uint64(stage.MaxArgumentBytes), MaxOpcodeCost: uint64(stage.MaxOpcodeCost),
				}},
				Dummy: lsigresource.Usage{ProgramBytes: uint64(len(group[1].Lsig.Logic)), MaxOpcodeCost: signing.DummyOpcodeCost},
			})
			if err != nil {
				t.Fatalf("solve: %v", err)
			}
			if plan.GroupSize != wotscDummies+1 || plan.ChargedProgramBytes != 0 {
				t.Fatalf("plan = %+v, want group of %d with no program surcharge", plan, wotscDummies+1)
			}
			t.Logf("measured: program %d bytes, opcode cost %d, group %d", wantSize, stage.MaxOpcodeCost, plan.GroupSize)
		})
	}
}

func newWOTSCAccountWithStage0(t *testing.T, testnet *harness.TestnetConfig, salted bool) *wotscAccount {
	t.Helper()
	for range 64 {
		acct := newWOTSCAccount(t, testnet)
		if acct.stage(0).program.Salted == salted {
			return acct
		}
		acct.zero()
	}
	t.Fatalf("no account with salted=%v stage 0 in 64 tries", salted)
	return nil
}

func newWOTSCAccount(t *testing.T, testnet *harness.TestnetConfig) *wotscAccount {
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
	acct := &wotscAccount{t: t, testnet: testnet, stages: map[uint64]*wotscStage{}, deriver: d}
	acct.address = acct.stage(0).program.Address
	return acct
}

func (a *wotscAccount) stage(i uint64) *wotscStage {
	a.t.Helper()
	if s, ok := a.stages[i]; ok {
		return s
	}
	keys, program, err := signerops.DeriveStage(a.deriver, i)
	if err != nil {
		a.t.Fatalf("derive stage %d: %v", i, err)
	}
	s := &wotscStage{keys: keys, program: program}
	a.stages[i] = s
	return s
}

func (a *wotscAccount) zero() {
	for _, s := range a.stages {
		s.keys.Zero()
	}
	a.deriver.Zero()
}

// build returns the encoded signed group and its decoded form: the spend at
// index 0, signed by the stage LogicSig, and the dummies that pool the
// argument budget.
func (a *wotscAccount) build(spend wotscSpend) ([]byte, []types.SignedTxn) {
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
	txn.Fee = types.MicroAlgos(1000 * (wotscDummies + 1))
	if spend.totalFee != 0 {
		txn.Fee = types.MicroAlgos(spend.totalFee)
	}

	dummies, err := signing.CreateDummyTransactions(wotscDummies, sp)
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
	leaf := uint32(txID[0]) % wotsc.Leaves
	if spend.leaf != nil {
		leaf = *spend.leaf
	}
	hashSigner, edSigner, falconSigner := spend.signer, spend.signer, spend.signer
	if spend.hashFrom != nil {
		hashSigner = spend.hashFrom
	}
	if spend.edFrom != nil {
		edSigner = spend.edFrom
	}
	if spend.falconFrom != nil {
		falconSigner = spend.falconFrom
	}
	hashSig, _, _, err := hashSigner.keys.Sign(leaf, txID)
	if err != nil {
		a.t.Fatal(err)
	}
	_, edSig, _, err := edSigner.keys.Sign(leaf, txID)
	if err != nil {
		a.t.Fatal(err)
	}
	_, _, falconSig, err := falconSigner.keys.Sign(leaf, txID)
	if err != nil {
		a.t.Fatal(err)
	}
	if spend.setLeaf != nil {
		hashSig[0], hashSig[1], hashSig[2], hashSig[3] = byte(*spend.setLeaf>>24), byte(*spend.setLeaf>>16), byte(*spend.setLeaf>>8), byte(*spend.setLeaf)
	}
	if spend.damageHash > 0 {
		hashSig[spend.damageHash] ^= 0x01
	}
	if spend.hashLength > len(hashSig) {
		hashSig = append(hashSig, make([]byte, spend.hashLength-len(hashSig))...)
	} else if spend.hashLength > 0 {
		hashSig = hashSig[:spend.hashLength]
	}
	if spend.damageFalcon > 0 {
		falconSig[spend.damageFalcon] ^= 0x01
	}
	args := [][]byte{hashSig, edSig, falconSig}
	if spend.swapArgs {
		args[0], args[1] = args[1], args[0]
	}
	if spend.dropFalcon {
		args = args[:len(args)-1]
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

func (a *wotscAccount) submitOK(spend wotscSpend) {
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

func (a *wotscAccount) requireAuthorizer(want types.Address) {
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
