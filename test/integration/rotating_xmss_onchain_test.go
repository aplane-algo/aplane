// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/xmss"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingxmsstriple/stage"
	"github.com/aplane-algo/aplane/test/integration/harness"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

// xmssDummies is the number of resource dummies an XMSS stage spend needs:
// its worst-case opcode cost and its arguments each need five pooled
// transactions.
const xmssDummies = 4

type xmssTree struct {
	seeds xmss.Seeds
	tree  *xmss.Tree
	pk    xmss.PublicKey
}

type xmssStage struct {
	index   uint64
	tree    *xmssTree
	ed      ed25519.PrivateKey
	falcon  falcongo.KeyPair
	keys    *stage.PublicKeys
	program stage.Program
	next    uint32 // next unused leaf of the stage's range
}

type xmssSpend struct {
	signer       *xmssStage
	authorizer   types.Address
	receiver     types.Address
	amount       uint64
	rekeyTo      types.Address
	closeTo      types.Address
	window       uint64
	totalFee     uint64
	leaf         *uint32    // sign with this leaf instead of the stage's next one
	unbounded    bool       // sign with RFC 8391's randomizer, ignoring the checksum cap
	edFrom       *xmssStage // sign argument 1 with another stage's key
	falconFrom   *xmssStage // sign argument 2 with another stage's key
	swapArgs     bool
	dropFalcon   bool
	damageXmss   int // flip one bit of the XMSS signature at this byte, when > 0
	xmssLength   int // resize the valid XMSS signature to this many bytes, when > 0
	damageFalcon int // flip one bit of the Falcon signature at this byte, when > 0
}

type xmssAccount struct {
	t       *testing.T
	testnet *harness.TestnetConfig
	address types.Address
	trees   map[uint64]*xmssTree
	owned   map[*xmssTree]bool // trees this account generated and may zero
	stages  map[uint64]*xmssStage
}

// TestRotatingXmssOnChain runs the XMSS triple stage program on a real
// network. Trees use fresh random seeds; the Ed25519 and Falcon keys of
// each stage are random too (derivation arrives with the signer provider).
func TestRotatingXmssOnChain(t *testing.T) {
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("funding account: %v", err)
	}
	acct := newXmssAccount(t, testnet, nil)
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

	t.Run("fee below five minimum fees is refused", func(t *testing.T) {
		raw, _ := acct.build(xmssSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s1.program.Address, totalFee: 1000*(xmssDummies+1) - 1,
		})
		_, err := testnet.Client.SendRawTransaction(raw).Do(context.Background())
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "fee") {
			t.Fatalf("low fee error = %v, want a fee rejection", err)
		}
	})

	t.Run("accept: spend from stage 0 rotates to stage 1", func(t *testing.T) {
		acct.submitOK(xmssSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s1.program.Address, window: stage.MaxValidityWindow,
		})
		acct.requireAuthorizer(s1.program.Address)
	})

	t.Run("accept: spend from stage 1 rotates to stage 2", func(t *testing.T) {
		acct.submitOK(xmssSpend{
			signer: s1, authorizer: s1.program.Address, receiver: funderAddr, amount: 1000, rekeyTo: s2.program.Address,
		})
		acct.requireAuthorizer(s2.program.Address)
	})

	t.Run("dead stage cannot spend", func(t *testing.T) {
		raw, _ := acct.build(xmssSpend{
			signer: s0, receiver: funderAddr, amount: 1000, rekeyTo: s3.program.Address,
		})
		_, err := testnet.Client.SendRawTransaction(raw).Do(context.Background())
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "authorized") {
			t.Fatalf("dead stage spend error = %v, want an authorization mismatch", err)
		}
	})

	t.Run("accept: rotate-only zero payment to self", func(t *testing.T) {
		acct.submitOK(xmssSpend{
			signer: s2, authorizer: s2.program.Address, receiver: acct.address, amount: 0, rekeyTo: s3.program.Address,
		})
		acct.requireAuthorizer(s3.program.Address)
	})

	other := acct.stage(9)
	live := xmssSpend{
		signer: s3, authorizer: s3.program.Address, receiver: funderAddr, amount: 1000, rekeyTo: other.program.Address,
	}
	below, above := uint32(s3.keys.Lo-1), uint32(s3.keys.Hi)
	rejects := map[string]func(xmssSpend) xmssSpend{
		"no rekey":                   func(s xmssSpend) xmssSpend { s.rekeyTo = types.ZeroAddress; return s },
		"rekey to sender":            func(s xmssSpend) xmssSpend { s.rekeyTo = acct.address; return s },
		"close-out":                  func(s xmssSpend) xmssSpend { s.closeTo = funderAddr; return s },
		"window of 101":              func(s xmssSpend) xmssSpend { s.window = stage.MaxValidityWindow + 1; return s },
		"leaf below the stage range": func(s xmssSpend) xmssSpend { s.leaf = &below; return s },
		"leaf above the stage range": func(s xmssSpend) xmssSpend { s.leaf = &above; return s },
		"wrong Ed25519 key":          func(s xmssSpend) xmssSpend { s.edFrom = other; return s },
		"wrong Falcon key":           func(s xmssSpend) xmssSpend { s.falconFrom = other; return s },
		"no Falcon signature":        func(s xmssSpend) xmssSpend { s.dropFalcon = true; return s },
		"damaged Falcon signature":   func(s xmssSpend) xmssSpend { s.damageFalcon = 40; return s },
		"arguments swapped":          func(s xmssSpend) xmssSpend { s.swapArgs = true; return s },
		"index byte changed":         func(s xmssSpend) xmssSpend { s.damageXmss = xmss.IndexSize - 1; return s },
		"damaged randomizer":         func(s xmssSpend) xmssSpend { s.damageXmss = xmss.IndexSize; return s },
		"damaged first chain element": func(s xmssSpend) xmssSpend {
			s.damageXmss = xmss.IndexSize + xmss.N
			return s
		},
		"damaged last chain element": func(s xmssSpend) xmssSpend {
			s.damageXmss = xmss.IndexSize + xmss.N + xmss.WotsSignatureSize - 1
			return s
		},
		"damaged first path node": func(s xmssSpend) xmssSpend {
			s.damageXmss = xmss.IndexSize + xmss.N + xmss.WotsSignatureSize
			return s
		},
		"damaged last path node":        func(s xmssSpend) xmssSpend { s.damageXmss = xmss.SignatureSize - 1; return s },
		"XMSS signature one byte long":  func(s xmssSpend) xmssSpend { s.xmssLength = xmss.SignatureSize + 1; return s },
		"XMSS signature one byte short": func(s xmssSpend) xmssSpend { s.xmssLength = xmss.SignatureSize - 1; return s },
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

	// A valid RFC 8391 signature whose hashed message has a checksum just
	// above the cap is rejected by the stage's checksum assertion, and by
	// nothing else: a checksum of 512 to 527 runs 555 chain steps, which
	// the five-transaction budget still covers, so only the assertion can
	// reject it. The bounded signer, signing the very same transaction,
	// finds a randomizer within the cap.
	t.Run("reject: valid signature with checksum above the cap", func(t *testing.T) {
		leaf := uint32(s3.keys.Lo) + 40
		for amount := uint64(1000); ; amount++ {
			raw, group := acct.build(xmssSpend{
				signer: s3, authorizer: s3.program.Address, receiver: funderAddr, amount: amount,
				rekeyTo: other.program.Address, leaf: &leaf, unbounded: true,
			})
			txID := algocrypto.TransactionID(group[0].Txn)
			rfcSig := group[0].Lsig.Args[0]
			sum, err := xmss.MessageChecksum(&s3.tree.pk, txID, rfcSig)
			if err != nil {
				t.Fatal(err)
			}
			if sum <= stage.MaxChecksum || sum > stage.MaxChecksum+16 {
				continue
			}
			steps, err := xmss.VerifySteps(&s3.tree.pk, txID, rfcSig)
			if err != nil {
				t.Fatal(err)
			}
			if steps != 555 || stage.OpcodeCost(steps) > uint64(xmssDummies+1)*lsigresource.SingleTransactionOpcodeCeiling {
				t.Fatalf("checksum %d runs %d steps costing %d: not within the group's budget, so the test could not isolate the assertion", sum, steps, stage.OpcodeCost(steps))
			}
			if err := xmss.Verify(&s3.tree.pk, txID, rfcSig); err != nil {
				t.Fatalf("the RFC signature is not valid off-chain: %v", err)
			}
			_, err = testnet.Client.SendRawTransaction(raw).Do(context.Background())
			if err == nil {
				t.Fatalf("checksum %d above the cap was accepted", sum)
			}
			lower := strings.ToLower(err.Error())
			if !strings.Contains(lower, "assert failed") || strings.Contains(lower, "budget") {
				t.Fatalf("checksum %d rejected for another reason than the assertion: %v", sum, err)
			}
			boundedSig, err := xmss.SignBounded(&s3.tree.seeds, s3.tree.tree, leaf, txID, stage.MaxChecksum)
			if err != nil {
				t.Fatal(err)
			}
			boundedSum, err := xmss.MessageChecksum(&s3.tree.pk, txID, boundedSig)
			if err != nil {
				t.Fatal(err)
			}
			if boundedSum > stage.MaxChecksum || bytes.Equal(boundedSig[xmss.IndexSize:xmss.IndexSize+xmss.N], rfcSig[xmss.IndexSize:xmss.IndexSize+xmss.N]) {
				t.Fatalf("bounded signer gave checksum %d with the RFC randomizer", boundedSum)
			}
			if err := xmss.Verify(&s3.tree.pk, txID, boundedSig); err != nil {
				t.Fatal(err)
			}
			t.Logf("RFC checksum %d (%d steps) rejected by the assertion; bounded signer found checksum %d for the same transaction", sum, steps, boundedSum)
			break
		}
		acct.requireAuthorizer(s3.program.Address)
	})

	t.Run("accept: last stage of tree 0 rotates into tree 1", func(t *testing.T) {
		last, first := acct.stage(stage.StagesPerTree-1), acct.stage(stage.StagesPerTree)
		if last.tree == first.tree || first.keys.Lo != 0 || last.keys.Hi != xmss.Leaves {
			t.Fatalf("stages %d and %d do not straddle the tree boundary", last.index, first.index)
		}
		acct.submitOK(xmssSpend{
			signer: s3, authorizer: s3.program.Address, receiver: funderAddr, amount: 1000, rekeyTo: last.program.Address,
		})
		acct.requireAuthorizer(last.program.Address)
		acct.submitOK(xmssSpend{
			signer: last, authorizer: last.program.Address, receiver: funderAddr, amount: 1000, rekeyTo: first.program.Address,
		})
		acct.requireAuthorizer(first.program.Address)
	})

	// Measure both program shapes. The node's budget report must equal the
	// cost model for the spend's chain steps and stay under the declared
	// ceiling. The measurement accounts share tree 0 and differ in their
	// Ed25519 and Falcon keys, which is what the salt depends on.
	for _, salted := range []bool{false, true} {
		t.Run(fmt.Sprintf("measure: opcode cost and group plan (salted=%v)", salted), func(t *testing.T) {
			m := newXmssAccountWithStage0(t, testnet, acct.trees[0], salted)
			defer m.zero()
			if err := funder.FundMicroAlgosAndWait(m.address.String(), 200_000); err != nil {
				t.Fatalf("fund measurement account: %v", err)
			}
			first := m.stage(0)
			// Leaf 7 for the salted shape: the path walk must cost the same
			// whichever side each level's sibling is on. The amount is
			// searched until the signature runs the most chain steps the
			// cap admits, so the ceiling itself is what gets measured.
			leaf := uint32(0)
			if salted {
				leaf = 7
			}
			var group []types.SignedTxn
			for amount := uint64(1000); ; amount++ {
				_, group = m.build(xmssSpend{
					signer: first, receiver: funderAddr, amount: amount, rekeyTo: m.stage(1).program.Address, leaf: &leaf,
				})
				steps, err := xmss.VerifySteps(&first.tree.pk, algocrypto.TransactionID(group[0].Txn), group[0].Lsig.Args[0])
				if err != nil {
					t.Fatal(err)
				}
				if steps == stage.MaxAcceptedSteps {
					break
				}
			}
			wantSize := stage.UnsaltedProgramSize
			if salted {
				wantSize = stage.SaltedProgramSize
			}
			if len(first.program.Bytecode) != wantSize {
				t.Fatalf("program is %d bytes, want %d", len(first.program.Bytecode), wantSize)
			}
			txID := algocrypto.TransactionID(group[0].Txn)
			steps, err := xmss.VerifySteps(&first.tree.pk, txID, group[0].Lsig.Args[0])
			if err != nil {
				t.Fatal(err)
			}
			want := stage.OpcodeCost(steps)
			report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), testnet.Client, harness.OpcodeCeilingValidation{
				Name:          "rotating xmss stage",
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
			t.Logf("measured: program %d bytes, opcode cost %d for %d chain steps (model %d; ceiling %d)",
				wantSize, observed, steps, want, stage.MaxOpcodeCost)
			if observed != want {
				t.Fatalf("observed opcode cost %d, cost model %d for %d chain steps", observed, want, steps)
			}
			if observed != stage.MaxOpcodeCost {
				t.Fatalf("observed %d at the step ceiling is not the declared ceiling %d", observed, stage.MaxOpcodeCost)
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
			if plan.GroupSize != xmssDummies+1 || plan.ChargedProgramBytes != 0 {
				t.Fatalf("plan = %+v, want group of %d with no program surcharge", plan, xmssDummies+1)
			}
		})
	}
}

func newXmssTree(t *testing.T) *xmssTree {
	t.Helper()
	tr := &xmssTree{}
	for _, b := range [][]byte{tr.seeds.SKSeed[:], tr.seeds.SKPRF[:], tr.seeds.PubSeed[:]} {
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
	}
	tr.tree = xmss.GenerateTree(&tr.seeds)
	tr.pk = xmss.PublicKey{Root: tr.tree.Root(), Seed: tr.seeds.PubSeed}
	return tr
}

// newXmssAccount creates an account whose tree 0 is tree0, or a fresh one.
func newXmssAccount(t *testing.T, testnet *harness.TestnetConfig, tree0 *xmssTree) *xmssAccount {
	t.Helper()
	acct := &xmssAccount{t: t, testnet: testnet, trees: map[uint64]*xmssTree{}, owned: map[*xmssTree]bool{}, stages: map[uint64]*xmssStage{}}
	if tree0 == nil {
		tree0 = newXmssTree(t)
		acct.owned[tree0] = true
	}
	acct.trees[0] = tree0
	acct.address = acct.stage(0).program.Address
	return acct
}

// newXmssAccountWithStage0 regenerates stage 0's Ed25519 and Falcon keys
// until its program has the requested salting.
func newXmssAccountWithStage0(t *testing.T, testnet *harness.TestnetConfig, tree0 *xmssTree, salted bool) *xmssAccount {
	t.Helper()
	acct := &xmssAccount{t: t, testnet: testnet, trees: map[uint64]*xmssTree{0: tree0}, owned: map[*xmssTree]bool{}, stages: map[uint64]*xmssStage{}}
	for range 64 {
		delete(acct.stages, 0)
		if acct.stage(0).program.Salted == salted {
			acct.address = acct.stage(0).program.Address
			return acct
		}
	}
	t.Fatalf("no account with salted=%v stage 0 in 64 tries", salted)
	return nil
}

func (a *xmssAccount) tree(n uint64) *xmssTree {
	a.t.Helper()
	if tr, ok := a.trees[n]; ok {
		return tr
	}
	tr := newXmssTree(a.t)
	a.trees[n] = tr
	a.owned[tr] = true
	return tr
}

func (a *xmssAccount) stage(i uint64) *xmssStage {
	a.t.Helper()
	if s, ok := a.stages[i]; ok {
		return s
	}
	treeNo, lo, hi := stage.RangeFor(i)
	s := &xmssStage{index: i, tree: a.tree(treeNo)}
	var edSeed [ed25519.SeedSize]byte
	if _, err := rand.Read(edSeed[:]); err != nil {
		a.t.Fatal(err)
	}
	s.ed = ed25519.NewKeyFromSeed(edSeed[:])
	var falconSeed [48]byte
	if _, err := rand.Read(falconSeed[:]); err != nil {
		a.t.Fatal(err)
	}
	kp, err := falcongo.GenerateKeyPair(falconSeed[:])
	if err != nil {
		a.t.Fatal(err)
	}
	s.falcon = kp
	s.keys = &stage.PublicKeys{Root: s.tree.pk.Root, Seed: s.tree.pk.Seed, Lo: lo, Hi: hi}
	copy(s.keys.Ed25519[:], s.ed.Public().(ed25519.PublicKey))
	copy(s.keys.Falcon[:], kp.PublicKey[:])
	s.program, err = stage.Build(s.keys)
	if err != nil {
		a.t.Fatalf("build stage %d program: %v", i, err)
	}
	a.stages[i] = s
	return s
}

// zero wipes the secret seeds of the trees this account generated. A tree
// shared from another account stays usable for that account.
func (a *xmssAccount) zero() {
	for tr := range a.owned {
		tr.seeds.Zero()
	}
}

// build returns the encoded signed group and its decoded form: the spend at
// index 0, signed by the stage LogicSig, and the dummies that pool the
// argument and opcode budgets.
func (a *xmssAccount) build(spend xmssSpend) ([]byte, []types.SignedTxn) {
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
	txn.Fee = types.MicroAlgos(1000 * (xmssDummies + 1))
	if spend.totalFee != 0 {
		txn.Fee = types.MicroAlgos(spend.totalFee)
	}

	dummies, err := signing.CreateDummyTransactions(xmssDummies, sp)
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
	signer := spend.signer
	leaf := uint32(signer.keys.Lo) + signer.next
	if spend.leaf != nil {
		leaf = *spend.leaf
	} else {
		signer.next++
	}
	var xmssSig []byte
	if spend.unbounded {
		xmssSig, err = xmss.Sign(&signer.tree.seeds, signer.tree.tree, leaf, txID)
	} else {
		xmssSig, err = xmss.SignBounded(&signer.tree.seeds, signer.tree.tree, leaf, txID, stage.MaxChecksum)
	}
	if err != nil {
		a.t.Fatal(err)
	}
	edSigner, falconSigner := signer, signer
	if spend.edFrom != nil {
		edSigner = spend.edFrom
	}
	if spend.falconFrom != nil {
		falconSigner = spend.falconFrom
	}
	edSig := ed25519.Sign(edSigner.ed, txID)
	falconSig, err := falconSigner.falcon.Sign(txID)
	if err != nil {
		a.t.Fatal(err)
	}
	if spend.damageXmss > 0 {
		xmssSig[spend.damageXmss] ^= 0x01
	}
	if spend.xmssLength > len(xmssSig) {
		xmssSig = append(xmssSig, make([]byte, spend.xmssLength-len(xmssSig))...)
	} else if spend.xmssLength > 0 {
		xmssSig = xmssSig[:spend.xmssLength]
	}
	if spend.damageFalcon > 0 {
		falconSig[spend.damageFalcon] ^= 0x01
	}
	args := [][]byte{xmssSig, edSig, falconSig}
	if spend.swapArgs {
		args = [][]byte{edSig, xmssSig, falconSig}
	}
	if spend.dropFalcon {
		args = args[:2]
	}

	signed := types.SignedTxn{
		Txn:  group[0],
		Lsig: types.LogicSig{Logic: signer.program.Bytecode, Args: args},
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

func (a *xmssAccount) submitOK(spend xmssSpend) {
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

func (a *xmssAccount) requireAuthorizer(want types.Address) {
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
