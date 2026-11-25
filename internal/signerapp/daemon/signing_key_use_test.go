// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
	falconkeygen "github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// holdingNonRotatingStore hands out fresh copies of non-rotating key material
// and parks the load matching holdAddr until the test releases it, exposing
// the loaded secret slice so the test can assert zeroing before KeyUse ends.
type holdingNonRotatingStore struct {
	keys     map[string]func() (*coresigning.KeyMaterial, []byte)
	holdAddr string
	loads    atomic.Int32
	held     chan heldSeed
	resume   chan struct{}
	parked   atomic.Pointer[[]byte]
}

func (s *holdingNonRotatingStore) Get(ctx context.Context, addr string) (*coresigning.KeyMaterial, error) {
	s.loads.Add(1)
	build, ok := s.keys[addr]
	if !ok {
		return nil, keystore.ErrKeyNotFound
	}
	km, secret := build()
	if addr == s.holdAddr {
		s.parked.Store(&secret)
		s.held <- heldSeed{ctx: ctx}
		<-s.resume
	}
	return km, nil
}

type nonRotatingDaemonFixture struct {
	server            *Signer
	ir                *productruntime.Runtime
	genesis           types.Digest
	edAddr            string
	edPriv            ed25519.PrivateKey
	edPub             ed25519.PublicKey
	boundedAddr       string
	boundedMeta       *boundedmeta.Metadata
	boundedBytecode   []byte
	boundedSpendPub   []byte
	boundedSpendPriv  []byte
	boundedCosignPub  []byte
	boundedCosignPriv []byte
	cosignerKeyID     string
	cosignerEdPub     ed25519.PublicKey
	cosignerEdPriv    ed25519.PrivateKey
}

func newNonRotatingDaemonFixture(t *testing.T, role noderole.Role) *nonRotatingDaemonFixture {
	t.Helper()
	RegisterProviders()
	falconkeygen.RegisterWitnessKeygen()

	server, cleanup := setupTestSigner(t)
	t.Cleanup(cleanup)
	ir := server.productRuntime()
	ir.Config().SetUserAutoApprove(true)
	if ir.Approval() == nil {
		ir.SetApprovalCoordinator(signerapproval.New(func() bool { return false }, nil, nil))
	}

	rawGenesis, err := base64.StdEncoding.DecodeString(testnetGenesisB64)
	if err != nil {
		t.Fatal(err)
	}
	var genesis types.Digest
	copy(genesis[:], rawGenesis)

	edPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	edPub := edPriv.Public().(ed25519.PublicKey)
	var edAddr types.Address
	copy(edAddr[:], edPub)

	spendPub, spendPriv, err := signerops.New().GenerateKeypair(bytes.Repeat([]byte{0x42}, 64))
	if err != nil {
		t.Fatal(err)
	}
	cosignPub, cosignPriv, err := signerops.New().GenerateKeypair(bytes.Repeat([]byte{0x43}, 64))
	if err != nil {
		t.Fatal(err)
	}
	bytecode := []byte{0x06, 0x20, 0x01, 0x01, 0x22, 0x42, 0x43}
	lsigAddr, err := (algocrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}).Address()
	if err != nil {
		t.Fatal(err)
	}
	boundedAddr := lsigAddr.String()
	cosignID, err := witness.ID(witness.Falcon1024V1, cosignPub)
	if err != nil {
		t.Fatal(err)
	}
	metadata := &boundedmeta.Metadata{
		Contract:               boundedmeta.Contract,
		BaseSignatureArgLayout: boundedmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{boundedmeta.DefaultCosignerSignatureMaxSize}},
		SpendEffects:           []string{boundedmeta.SpendEffectPay},
		MaxFee:                 new(uint64(10_000)),
		Rekey:                  boundedmeta.RekeyRefused,
		Layer3Policy:           boundedmeta.Layer3PolicyCustom,
		Cosigner: &boundedmeta.CosignerAuthorization{
			Contract:         boundedmeta.CosignerContractV1,
			ComponentKeyType: witness.Falcon1024V1,
			PublicKeyHex:     hex.EncodeToString(cosignPub),
			ComponentKeyID:   cosignID,
			SignatureMaxSize: boundedmeta.DefaultCosignerSignatureMaxSize,
			RequiredOn:       []string{boundedmeta.PathSpend},
		},
		ArgumentLayout: []boundedmeta.ArgumentSlot{
			{Index: 0, Name: "base_signature_0", Source: boundedmeta.ArgSourceBaseSignature, MaxSize: boundedmeta.DefaultCosignerSignatureMaxSize, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgRequired, ListedRekey: boundedmeta.ArgRequired}},
			{Index: 1, Name: boundedmeta.CosignerSignatureSlot, Source: boundedmeta.ArgSourceCosigner, MaxSize: boundedmeta.DefaultCosignerSignatureMaxSize, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgForbidden, ListedRekey: boundedmeta.ArgForbidden}},
		},
	}
	if err := metadata.Validate(); err != nil {
		t.Fatal(err)
	}

	cosignEdPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	cosignEdPub := cosignEdPriv.Public().(ed25519.PublicKey)
	cosignerKeyID, err := witness.ID(witness.Ed25519V1, cosignEdPub)
	if err != nil {
		t.Fatal(err)
	}

	if role == noderole.RoleCosigner {
		doc := policytest.MustDocument(noderole.RoleCosigner, policy.DefaultKey, `{
			"transfer_policy": {
				"routes": [{
					"id": "allow_all_test",
					"networks": ["*"],
					"sources": ["*"],
					"assets": ["*"],
					"destinations": ["*"]
				}]
			}
		}`)
		np, err := policyruntime.Compile(noderole.RoleCosigner, server.config, []policy.StoredDocument{{Key: policy.DefaultKey, Bytes: []byte(doc)}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		ir.SetVerifiedPolicyState(np, nil, nil)
	} else {
		cfg := &policy.Config{TransactionTypes: policytest.AllowAllTypes()}
		ir.SetVerifiedPolicyState(&policyruntime.NodePolicy{Role: noderole.RoleSigner, Default: cfg}, nil, nil)
	}

	return &nonRotatingDaemonFixture{
		server:            server,
		ir:                ir,
		genesis:           genesis,
		edAddr:            edAddr.String(),
		edPriv:            edPriv,
		edPub:             edPub,
		boundedAddr:       boundedAddr,
		boundedMeta:       metadata,
		boundedBytecode:   bytecode,
		boundedSpendPub:   spendPub,
		boundedSpendPriv:  spendPriv,
		boundedCosignPub:  cosignPub,
		boundedCosignPriv: cosignPriv,
		cosignerKeyID:     cosignerKeyID,
		cosignerEdPub:     cosignEdPub,
		cosignerEdPriv:    cosignEdPriv,
	}
}

func (fx *nonRotatingDaemonFixture) newStore(holdAddr string) *holdingNonRotatingStore {
	return &holdingNonRotatingStore{
		holdAddr: holdAddr,
		held:     make(chan heldSeed, 1),
		resume:   make(chan struct{}),
		keys: map[string]func() (*coresigning.KeyMaterial, []byte){
			fx.edAddr: func() (*coresigning.KeyMaterial, []byte) {
				account, err := algocrypto.AccountFromPrivateKey(append(ed25519.PrivateKey(nil), fx.edPriv...))
				if err != nil {
					panic(err)
				}
				return &coresigning.KeyMaterial{
					Type:      "ed25519",
					Category:  keys.CategoryEd25519,
					PublicKey: append([]byte(nil), fx.edPub...),
					Value:     account,
				}, []byte(account.PrivateKey)
			},
			fx.boundedAddr: func() (*coresigning.KeyMaterial, []byte) {
				priv := append([]byte(nil), fx.boundedSpendPriv...)
				return &coresigning.KeyMaterial{
					Type:                 "test.bounded-cosigner.v1",
					Category:             keys.CategoryDSALsig,
					BaseKeyType:          "aplane.falcon1024.v1",
					PublicKey:            append([]byte(nil), fx.boundedSpendPub...),
					Bytecode:             append([]byte(nil), fx.boundedBytecode...),
					BoundedAuthorization: boundedmeta.Clone(fx.boundedMeta),
					Value:                &coresigning.LsigKeyMaterial{PrivateKey: priv},
				}, priv
			},
			fx.cosignerKeyID: func() (*coresigning.KeyMaterial, []byte) {
				priv := append([]byte(nil), fx.cosignerEdPriv...)
				return &coresigning.KeyMaterial{
					Type:      witness.Ed25519V1,
					Category:  keys.CategoryWitness,
					PublicKey: append([]byte(nil), fx.cosignerEdPub...),
					Value: &coresigning.WitnessKeyMaterial{
						WitnessKeyID: fx.cosignerKeyID,
						PublicKey:    append([]byte(nil), fx.cosignerEdPub...),
						PrivateKey:   priv,
					},
				}, priv
			},
		},
	}
}

func (fx *nonRotatingDaemonFixture) newService(audit signingAudit) *signersigning.Service {
	svc := fx.server.newSigningServiceWithAudit(fx.ir, audit)
	svc.Planner.Snapshot = func() signersigning.PlannerRuntimeSnapshot {
		return signersigning.PlannerRuntimeSnapshot{
			KeyFiles: map[string]string{
				fx.edAddr:      fx.edAddr + ".key",
				fx.boundedAddr: fx.boundedAddr + ".key",
			},
			KeyTypes: map[string]string{
				fx.edAddr:      "ed25519",
				fx.boundedAddr: "test.bounded-cosigner.v1",
			},
			KeyMetadata: map[string]signersigning.PlannerKeyMetadata{
				fx.boundedAddr: {
					BaseKeyType:          "aplane.falcon1024.v1",
					PublicKeyHex:         hex.EncodeToString(fx.boundedSpendPub),
					BoundedAuthorization: boundedmeta.Clone(fx.boundedMeta),
				},
			},
		}
	}
	svc.HoldsCosignerKey = func(id string) bool { return id == fx.cosignerKeyID }
	return svc
}

func (fx *nonRotatingDaemonFixture) paymentTxn(t *testing.T, sender, receiver string, amount uint64) types.Transaction {
	t.Helper()
	from, err := types.DecodeAddress(sender)
	if err != nil {
		t.Fatal(err)
	}
	to, err := types.DecodeAddress(receiver)
	if err != nil {
		t.Fatal(err)
	}
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      from,
			Fee:         1_000,
			FirstValid:  100,
			LastValid:   200,
			GenesisID:   "testnet-v1.0",
			GenesisHash: fx.genesis,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: to,
			Amount:   types.MicroAlgos(amount),
		},
	}
}

func (fx *nonRotatingDaemonFixture) ordinaryRequest(t *testing.T) signerapi.GroupSignRequest {
	t.Helper()
	txn := fx.paymentTxn(t, fx.edAddr, types.Address{0x61}.String(), 100)
	return signerapi.GroupSignRequest{
		RequestID: "daemon-ordinary",
		Requests: []signerapi.SignRequest{{
			AuthAddress: fx.edAddr,
			TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
		}},
	}
}

func (fx *nonRotatingDaemonFixture) boundedComponentRequest(t *testing.T) signerapi.ComponentRequest {
	t.Helper()
	txn := fx.paymentTxn(t, fx.boundedAddr, types.Address{0x62}.String(), 100)
	return signerapi.ComponentRequest{
		RequestID:     "daemon-bounded",
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		Targets: []signerapi.ComponentTarget{{
			TargetIndex: 0,
			Kind:        signerapi.ComponentTargetKindBoundedBase,
			AuthAddress: fx.boundedAddr,
		}},
	}
}

func (fx *nonRotatingDaemonFixture) cosignerComponentRequest(t *testing.T) signerapi.ComponentRequest {
	t.Helper()
	txn := fx.paymentTxn(t, types.Address{0x63}.String(), types.Address{0x64}.String(), 100)
	return signerapi.ComponentRequest{
		RequestID:     "daemon-cosigner",
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		Targets: []signerapi.ComponentTarget{{
			TargetIndex:  0,
			Kind:         signerapi.ComponentTargetKindCosigner,
			ComponentKey: fx.cosignerKeyID,
		}},
	}
}

func (fx *nonRotatingDaemonFixture) assemblyRequest(t *testing.T, svc *signersigning.Service, session *keystore.KeySession) signerapi.AssemblyRequest {
	t.Helper()
	boundedTxn := fx.paymentTxn(t, fx.boundedAddr, types.Address{0x65}.String(), 100)
	passthroughTxn := fx.paymentTxn(t, fx.edAddr, types.Address{0x66}.String(), 50)
	txns := []types.Transaction{boundedTxn, passthroughTxn}
	gid, err := algocrypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatal(err)
	}
	txns[0].Group, txns[1].Group = gid, gid
	rawHex := []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])}

	compResp, compErr := svc.PrepareBoundedComponentWithContext(context.Background(), signerapi.ComponentRequest{
		RequestID:     "prep-assembly-base",
		GroupBytesHex: rawHex,
		Targets: []signerapi.ComponentTarget{{
			TargetIndex: 0,
			Kind:        signerapi.ComponentTargetKindBoundedBase,
			AuthAddress: fx.boundedAddr,
		}},
		ContextualPositions: []signerapi.ComponentContextPosition{{
			TargetIndex: 1,
			AuthAddress: fx.edAddr,
		}},
	}, session)
	if compErr != nil || len(compResp.Components) != 1 {
		t.Fatalf("PrepareBoundedComponentWithContext() = (%+v, %v)", compResp, compErr)
	}
	group, err := canonical.DecodeGroupHex(rawHex)
	if err != nil {
		t.Fatal(err)
	}
	cosignerMsg := message.ComponentMessage(message.RoleCosigner, group.Entries[0].TxID)
	cosignerSig, err := signerops.New().Sign(fx.boundedCosignPriv, cosignerMsg[:])
	if err != nil {
		t.Fatal(err)
	}
	ptSig := ed25519.Sign(fx.edPriv, txnutil.EncodeWithPrefix(txns[1]))
	var sigArr types.Signature
	copy(sigArr[:], ptSig)
	ptSigned := msgpack.Encode(types.SignedTxn{Txn: txns[1], Sig: sigArr})

	return signerapi.AssemblyRequest{
		RequestID:     "daemon-assemble",
		GroupBytesHex: rawHex,
		Targets: []signerapi.AssemblyTarget{{
			TargetIndex:       0,
			AuthAddress:       fx.boundedAddr,
			BaseSignatures:    compResp.Components[0].BaseSignatures,
			AssemblyReceipt:   compResp.Components[0].AssemblyReceipt,
			CosignerSignature: hex.EncodeToString(cosignerSig),
		}},
		Passthrough: []signerapi.AssemblyPassthroughItem{{
			TargetIndex:  1,
			SignedTxnHex: hex.EncodeToString(ptSigned),
		}},
	}
}

// Every non-rotating GetKeyWithContext load site (/sign, bounded-base
// /sign/component, cosigner /sign/component, /sign/assemble bounded target,
// and /sign/assemble local passthrough) must be a registered key use that the
// real Runtime.Lock cancels and waits for until the loaded key is zeroed and
// the key use releases, and the request must answer locked with no output.
func TestLockWaitsForEveryNonRotatingKeyLoad(t *testing.T) {
	type lockCase struct {
		name     string
		role     noderole.Role
		holdAddr func(*nonRotatingDaemonFixture) string
		prepare  func(*testing.T, *nonRotatingDaemonFixture) func(*signersigning.Service, *keystore.KeySession) (bool, *signersigning.ServiceError)
	}

	cases := []lockCase{
		{
			name:     "ordinary_sign",
			role:     noderole.RoleSigner,
			holdAddr: func(fx *nonRotatingDaemonFixture) string { return fx.edAddr },
			prepare: func(t *testing.T, fx *nonRotatingDaemonFixture) func(*signersigning.Service, *keystore.KeySession) (bool, *signersigning.ServiceError) {
				req := fx.ordinaryRequest(t)
				return func(svc *signersigning.Service, session *keystore.KeySession) (bool, *signersigning.ServiceError) {
					res, err := svc.SignGroupWithContext(context.Background(), req, session)
					return res != nil, err
				}
			},
		},
		{
			name:     "bounded_component",
			role:     noderole.RoleSigner,
			holdAddr: func(fx *nonRotatingDaemonFixture) string { return fx.boundedAddr },
			prepare: func(t *testing.T, fx *nonRotatingDaemonFixture) func(*signersigning.Service, *keystore.KeySession) (bool, *signersigning.ServiceError) {
				req := fx.boundedComponentRequest(t)
				return func(svc *signersigning.Service, session *keystore.KeySession) (bool, *signersigning.ServiceError) {
					res, err := svc.PrepareBoundedComponentWithContext(context.Background(), req, session)
					return res != nil, err
				}
			},
		},
		{
			name:     "cosigner_component",
			role:     noderole.RoleCosigner,
			holdAddr: func(fx *nonRotatingDaemonFixture) string { return fx.cosignerKeyID },
			prepare: func(t *testing.T, fx *nonRotatingDaemonFixture) func(*signersigning.Service, *keystore.KeySession) (bool, *signersigning.ServiceError) {
				req := fx.cosignerComponentRequest(t)
				return func(svc *signersigning.Service, session *keystore.KeySession) (bool, *signersigning.ServiceError) {
					res, err := svc.SignComponentsWithContext(context.Background(), req, session)
					return res != nil, err
				}
			},
		},
		{
			name:     "assemble_bounded_target",
			role:     noderole.RoleSigner,
			holdAddr: func(fx *nonRotatingDaemonFixture) string { return fx.boundedAddr },
			prepare: func(t *testing.T, fx *nonRotatingDaemonFixture) func(*signersigning.Service, *keystore.KeySession) (bool, *signersigning.ServiceError) {
				prepSession := keystore.NewKeySession(fx.newStore(""))
				prepSession.InitializeSession()
				defer prepSession.Destroy()
				req := fx.assemblyRequest(t, fx.newService(&signingAuditLogger{log: fx.server.auditLog}), prepSession)
				return func(svc *signersigning.Service, session *keystore.KeySession) (bool, *signersigning.ServiceError) {
					res, err := svc.AssembleWithContext(context.Background(), req, session)
					return res != nil, err
				}
			},
		},
		{
			name:     "assemble_local_passthrough",
			role:     noderole.RoleSigner,
			holdAddr: func(fx *nonRotatingDaemonFixture) string { return fx.edAddr },
			prepare: func(t *testing.T, fx *nonRotatingDaemonFixture) func(*signersigning.Service, *keystore.KeySession) (bool, *signersigning.ServiceError) {
				prepSession := keystore.NewKeySession(fx.newStore(""))
				prepSession.InitializeSession()
				defer prepSession.Destroy()
				req := fx.assemblyRequest(t, fx.newService(&signingAuditLogger{log: fx.server.auditLog}), prepSession)
				return func(svc *signersigning.Service, session *keystore.KeySession) (bool, *signersigning.ServiceError) {
					res, err := svc.AssembleWithContext(context.Background(), req, session)
					return res != nil, err
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newNonRotatingDaemonFixture(t, tc.role)
			run := tc.prepare(t, fx)
			svc := fx.newService(&signingAuditLogger{log: fx.server.auditLog})
			store := fx.newStore(tc.holdAddr(fx))
			locked := make(chan struct{})
			end := &windowEnd{}
			innerKeyUse := svc.KeyUse
			svc.KeyUse = func(ctx context.Context) (context.Context, func()) {
				useCtx, release := innerKeyUse(ctx)
				return useCtx, func() {
					if secret := store.parked.Load(); secret != nil && !end.ended.Swap(true) {
						end.zeroed.Store(allZero(*secret))
						select {
						case <-locked:
							end.lockDone.Store(true)
						default:
						}
					}
					release()
				}
			}
			session := keystore.NewKeySession(store)
			session.InitializeSession()
			t.Cleanup(session.Destroy)

			var resumeOnce sync.Once
			resume := func() { resumeOnce.Do(func() { close(store.resume) }) }
			defer resume()

			type outcome struct {
				gotOutput bool
				err       *signersigning.ServiceError
			}
			done := make(chan outcome, 1)
			go func() {
				got, err := run(svc, session)
				done <- outcome{gotOutput: got, err: err}
			}()

			var held heldSeed
			select {
			case held = <-store.held:
			case res := <-done:
				t.Fatalf("request finished before parked key load: output=%v err=%v", res.gotOutput, res.err)
			case <-time.After(30 * time.Second):
				t.Fatal("request never reached parked key load")
			}

			go func() {
				fx.ir.Lock()
				close(locked)
			}()

			select {
			case <-held.ctx.Done():
			case <-locked:
				t.Fatal("Lock finished while the request held loaded key material")
			case <-time.After(30 * time.Second):
				t.Fatal("Lock never cancelled the load: it is not a registered key use")
			}

			// Keep the load parked briefly: a lock that did not drain this
			// key use would finish well within 100ms.
			select {
			case <-locked:
				t.Fatal("Lock finished while the request still held the key use")
			case <-time.After(100 * time.Millisecond):
			}

			resume()
			select {
			case <-locked:
			case <-time.After(30 * time.Second):
				t.Fatal("Lock never finished after the request released the key use")
			}

			switch {
			case !end.ended.Load():
				t.Fatal("the parked load's key use never ended")
			case end.lockDone.Load():
				t.Fatal("Lock finished before the parked load's key use ended")
			case !end.zeroed.Load():
				t.Fatal("the parked load's key use ended before loaded key material was zeroed")
			}

			select {
			case res := <-done:
				if res.gotOutput || res.err == nil || res.err.Kind != signersigning.ErrorLocked {
					t.Fatalf("result = (output=%v, err=%v), want (false, ErrorLocked)", res.gotOutput, res.err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("request never returned after Lock")
			}
		})
	}
}

// Human operator approval runs before KeyUse registration, so Lock() never
// blocks waiting on an operator prompt for /sign or bounded /sign/component.
func TestLockDoesNotWaitForNonRotatingApprovalPrompt(t *testing.T) {
	paths := []struct {
		name    string
		prepare func(*testing.T, *nonRotatingDaemonFixture) func(*signersigning.Service, *keystore.KeySession) (bool, *signersigning.ServiceError)
	}{
		{"ordinary_sign", func(t *testing.T, fx *nonRotatingDaemonFixture) func(*signersigning.Service, *keystore.KeySession) (bool, *signersigning.ServiceError) {
			req := fx.ordinaryRequest(t)
			return func(svc *signersigning.Service, session *keystore.KeySession) (bool, *signersigning.ServiceError) {
				res, err := svc.SignGroupWithContext(context.Background(), req, session)
				return res != nil, err
			}
		}},
		{"bounded_component", func(t *testing.T, fx *nonRotatingDaemonFixture) func(*signersigning.Service, *keystore.KeySession) (bool, *signersigning.ServiceError) {
			req := fx.boundedComponentRequest(t)
			return func(svc *signersigning.Service, session *keystore.KeySession) (bool, *signersigning.ServiceError) {
				res, err := svc.PrepareBoundedComponentWithContext(context.Background(), req, session)
				return res != nil, err
			}
		}},
	}

	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			fx := newNonRotatingDaemonFixture(t, noderole.RoleSigner)
			fx.ir.Config().SetUserAutoApprove(false)
			run := path.prepare(t, fx)
			svc := fx.newService(&signingAuditLogger{log: fx.server.auditLog})
			store := fx.newStore("")
			session := keystore.NewKeySession(store)
			session.InitializeSession()
			t.Cleanup(session.Destroy)

			inPrompt := make(chan struct{})
			unblockPrompt := make(chan struct{})
			var unblockOnce sync.Once
			defer unblockOnce.Do(func() { close(unblockPrompt) })

			svc.Approval.HasClient = func() bool { return true }
			svc.Approval.RequestSigningApprovalPrompt = func(context.Context, signerapproval.Prompt, time.Duration) (signerapproval.SignResponse, error) {
				close(inPrompt)
				<-unblockPrompt
				return signerapproval.SignResponse{Approved: true}, nil
			}

			type outcome struct {
				gotOutput bool
				err       *signersigning.ServiceError
			}
			done := make(chan outcome, 1)
			go func() {
				got, err := run(svc, session)
				done <- outcome{gotOutput: got, err: err}
			}()

			select {
			case <-inPrompt:
			case res := <-done:
				t.Fatalf("request finished before approval prompt: output=%v err=%v", res.gotOutput, res.err)
			case <-time.After(10 * time.Second):
				t.Fatal("request never reached approval prompt")
			}

			locked := make(chan struct{})
			go func() {
				fx.ir.Lock()
				close(locked)
			}()
			select {
			case <-locked:
			case <-time.After(5 * time.Second):
				t.Fatal("Lock blocked on an approval prompt (KeyUse must not span approval)")
			}

			unblockOnce.Do(func() { close(unblockPrompt) })
			select {
			case res := <-done:
				if res.gotOutput || res.err == nil || res.err.Kind != signersigning.ErrorLocked {
					t.Fatalf("result = (output=%v, err=%v), want (false, ErrorLocked)", res.gotOutput, res.err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("request never finished after prompt unblocked")
			}
			if store.loads.Load() != 0 {
				t.Fatalf("store loads = %d, want 0 after lock during approval", store.loads.Load())
			}
		})
	}
}

type auditInterruptLogger struct {
	signingAudit
	onApprove      func()
	approved       atomic.Int32
	withheld       atomic.Int32
	withheldReason atomic.Pointer[string]
}

func (l *auditInterruptLogger) LogSignApproved(record signersigning.SignedRecord) {
	l.approved.Add(1)
	if l.signingAudit != nil {
		l.signingAudit.LogSignApproved(record)
	}
	if l.onApprove != nil {
		l.onApprove()
	}
}

func (l *auditInterruptLogger) LogSignWithheld(record signersigning.SignedRecord, reason string) {
	l.withheld.Add(1)
	r := reason
	l.withheldReason.Store(&r)
	if l.signingAudit != nil {
		l.signingAudit.LogSignWithheld(record, reason)
	}
}

// End-to-end check on the real productruntime.Runtime: for every audited
// non-rotating signing path,
//  1. calling ir.Lock() while LogSignApproved is running must not deadlock
//     (proving endKeyUse already ran before the blocking audit write) and must
//     withhold signatures as ErrorLocked with LogSignWithheld;
//  2. a recovery + PromoteRecoveryToUnlocked round-trip inside LogSignApproved
//     leaves the runtime unlocked in a new session, and the post-audit session
//     recheck must still withhold signatures as ErrorLocked with LogSignWithheld.
func TestNonRotatingSignStopsAtLockOrRecoveryDuringAuditWrite(t *testing.T) {
	paths := []struct {
		name string
		role noderole.Role
		run  func(*testing.T, *nonRotatingDaemonFixture, *signersigning.Service, *keystore.KeySession) (bool, *signersigning.ServiceError)
	}{
		{"ordinary_sign", noderole.RoleSigner, func(t *testing.T, fx *nonRotatingDaemonFixture, svc *signersigning.Service, session *keystore.KeySession) (bool, *signersigning.ServiceError) {
			res, err := svc.SignGroupWithContext(context.Background(), fx.ordinaryRequest(t), session)
			return res != nil, err
		}},
		{"bounded_component", noderole.RoleSigner, func(t *testing.T, fx *nonRotatingDaemonFixture, svc *signersigning.Service, session *keystore.KeySession) (bool, *signersigning.ServiceError) {
			res, err := svc.PrepareBoundedComponentWithContext(context.Background(), fx.boundedComponentRequest(t), session)
			return res != nil, err
		}},
		{"cosigner_component", noderole.RoleCosigner, func(t *testing.T, fx *nonRotatingDaemonFixture, svc *signersigning.Service, session *keystore.KeySession) (bool, *signersigning.ServiceError) {
			res, err := svc.SignComponentsWithContext(context.Background(), fx.cosignerComponentRequest(t), session)
			return res != nil, err
		}},
	}

	interrupts := []struct {
		name string
		do   func(*productruntime.Runtime) error
	}{
		{"lock_during_audit", func(ir *productruntime.Runtime) error {
			ir.Lock()
			return nil
		}},
		{"recovery_round_trip_during_audit", func(ir *productruntime.Runtime) error {
			ir.EnterRecovery(nil)
			if !ir.PromoteRecoveryToUnlocked() {
				return fmt.Errorf("PromoteRecoveryToUnlocked() = false")
			}
			return nil
		}},
	}

	for _, path := range paths {
		for _, intr := range interrupts {
			t.Run(path.name+"/"+intr.name, func(t *testing.T) {
				fx := newNonRotatingDaemonFixture(t, path.role)
				var once sync.Once
				var intrErr error
				audit := &auditInterruptLogger{
					signingAudit: &signingAuditLogger{log: fx.server.auditLog},
					onApprove: func() {
						once.Do(func() {
							done := make(chan error, 1)
							go func() { done <- intr.do(fx.ir) }()
							select {
							case intrErr = <-done:
							case <-time.After(5 * time.Second):
								intrErr = fmt.Errorf("%s blocked waiting on audit write (KeyUse was still held)", intr.name)
							}
						})
					},
				}
				svc := fx.newService(audit)
				session := keystore.NewKeySession(fx.newStore(""))
				session.InitializeSession()
				t.Cleanup(session.Destroy)

				gotOutput, err := path.run(t, fx, svc, session)
				if intrErr != nil {
					t.Fatal(intrErr)
				}
				if gotOutput || err == nil || err.Kind != signersigning.ErrorLocked {
					t.Fatalf("run() = (output=%v, err=%v), want (false, ErrorLocked)", gotOutput, err)
				}
				if audit.approved.Load() != 1 || audit.withheld.Load() != 1 {
					t.Fatalf("audit approved=%d withheld=%d, want 1/1", audit.approved.Load(), audit.withheld.Load())
				}
				if reason := audit.withheldReason.Load(); reason == nil || !strings.HasPrefix(*reason, "signature withheld after it was recorded as signed: ") {
					t.Fatalf("withheld reason = %v, want standard prefix", reason)
				}
			})
		}
	}
}

type blockingConsole struct {
	match   string
	parked  chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingConsole) Printf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	if strings.Contains(line, c.match) {
		c.once.Do(func() {
			close(c.parked)
			<-c.release
		})
	}
}

func (c *blockingConsole) Println(...any) {}
func (c *blockingConsole) Sync()          {}

// A stalled stdout/console while printing progress or summary lines after
// signing must neither hold a KeyUse (blocking Runtime.Lock from clearing the
// keyring) nor return a signature once stdout resumes after the lock.
func TestStalledConsoleDoesNotBlockLockOrLeakSignature(t *testing.T) {
	cases := []struct {
		name    string
		match   string
		prepare func(*testing.T, *nonRotatingDaemonFixture) func(*signersigning.Service, *keystore.KeySession) (bool, *signersigning.ServiceError)
	}{
		{
			name:  "ordinary_sign/per_txn",
			match: "signed (",
			prepare: func(t *testing.T, fx *nonRotatingDaemonFixture) func(*signersigning.Service, *keystore.KeySession) (bool, *signersigning.ServiceError) {
				req := fx.ordinaryRequest(t)
				return func(svc *signersigning.Service, session *keystore.KeySession) (bool, *signersigning.ServiceError) {
					res, err := svc.SignGroupWithContext(context.Background(), req, session)
					return res != nil, err
				}
			},
		},
		{
			name:  "ordinary_sign/summary",
			match: "Successfully signed",
			prepare: func(t *testing.T, fx *nonRotatingDaemonFixture) func(*signersigning.Service, *keystore.KeySession) (bool, *signersigning.ServiceError) {
				req := fx.ordinaryRequest(t)
				return func(svc *signersigning.Service, session *keystore.KeySession) (bool, *signersigning.ServiceError) {
					res, err := svc.SignGroupWithContext(context.Background(), req, session)
					return res != nil, err
				}
			},
		},
		{
			name:  "bounded_component/summary",
			match: "bounded-cosigner base component",
			prepare: func(t *testing.T, fx *nonRotatingDaemonFixture) func(*signersigning.Service, *keystore.KeySession) (bool, *signersigning.ServiceError) {
				req := fx.boundedComponentRequest(t)
				return func(svc *signersigning.Service, session *keystore.KeySession) (bool, *signersigning.ServiceError) {
					res, err := svc.PrepareBoundedComponentWithContext(context.Background(), req, session)
					return res != nil, err
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newNonRotatingDaemonFixture(t, noderole.RoleSigner)
			run := tc.prepare(t, fx)
			audit := &auditInterruptLogger{signingAudit: &signingAuditLogger{log: fx.server.auditLog}}
			svc := fx.newService(audit)
			con := &blockingConsole{
				match:   tc.match,
				parked:  make(chan struct{}),
				release: make(chan struct{}),
			}
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(con.release) }) }
			defer unblock()

			svc.Executor.Console = con
			svc.Console = con

			session := keystore.NewKeySession(fx.newStore(""))
			session.InitializeSession()
			t.Cleanup(session.Destroy)

			type outcome struct {
				gotOutput bool
				err       *signersigning.ServiceError
			}
			done := make(chan outcome, 1)
			go func() {
				got, err := run(svc, session)
				done <- outcome{gotOutput: got, err: err}
			}()

			select {
			case <-con.parked:
			case res := <-done:
				t.Fatalf("request finished before console print matching %q: output=%v err=%v", tc.match, res.gotOutput, res.err)
			case <-time.After(10 * time.Second):
				t.Fatalf("request never reached console print matching %q", tc.match)
			}

			locked := make(chan struct{})
			go func() {
				fx.ir.Lock()
				close(locked)
			}()
			select {
			case <-locked:
			case <-time.After(5 * time.Second):
				t.Fatal("Lock blocked on a stalled console write (KeyUse must end before console output)")
			}
			if fx.ir.IsUnlocked() {
				t.Fatal("runtime is still unlocked after Lock() returned")
			}
			if _, err := fx.ir.SnapshotKeySession().GetKeyWithContext(context.Background(), fx.edAddr); !errors.Is(err, keystore.ErrStoreLocked) {
				t.Fatalf("SnapshotKeySession after Lock = %v, want ErrStoreLocked", err)
			}

			unblock()
			select {
			case res := <-done:
				if res.gotOutput || res.err == nil || res.err.Kind != signersigning.ErrorLocked {
					t.Fatalf("result after lock during stalled console = (output=%v, err=%v), want (false, ErrorLocked)", res.gotOutput, res.err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("request never finished after console unblocked")
			}
			if audit.approved.Load() != 1 || audit.withheld.Load() != 1 {
				t.Fatalf("audit approved=%d withheld=%d, want 1/1", audit.approved.Load(), audit.withheld.Load())
			}
			if reason := audit.withheldReason.Load(); reason == nil || !strings.HasPrefix(*reason, "signature withheld after it was recorded as signed: ") {
				t.Fatalf("withheld reason = %v, want standard prefix", reason)
			}
		})
	}
}
