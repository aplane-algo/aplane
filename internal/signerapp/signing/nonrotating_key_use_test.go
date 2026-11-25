// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/externalcheck"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

var nonRotatingProvidersOnce sync.Once

func ensureNonRotatingTestProviders() {
	nonRotatingProvidersOnce.Do(func() {
		ed25519signerreg.RegisterSigner()
		lsigsignerreg.RegisterSigner()
	})
}

type mapKeyStore struct {
	mu      sync.Mutex
	keys    map[string]func() *coresigning.KeyMaterial
	loads   atomic.Int32
	onGet   func(ctx context.Context, addr string)
	lastKey atomic.Pointer[[]byte]
}

func (s *mapKeyStore) Get(ctx context.Context, addr string) (*coresigning.KeyMaterial, error) {
	s.loads.Add(1)
	if s.onGet != nil {
		s.onGet(ctx, addr)
	}
	s.mu.Lock()
	build := s.keys[addr]
	s.mu.Unlock()
	if build == nil {
		return nil, keystore.ErrKeyNotFound
	}
	km := build()
	if secret := secretSliceOf(km); len(secret) > 0 {
		s.lastKey.Store(&secret)
	}
	return km, nil
}

func secretSliceOf(km *coresigning.KeyMaterial) []byte {
	if km == nil {
		return nil
	}
	switch v := km.Value.(type) {
	case algocrypto.Account:
		return []byte(v.PrivateKey)
	case *coresigning.LsigKeyMaterial:
		return v.PrivateKey
	case *coresigning.WitnessKeyMaterial:
		return v.PrivateKey
	default:
		return nil
	}
}

func bytesAllZero(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

type hookAuditLogger struct {
	testAuditLogger
	onApprove func(SignedRecord)
	onFail    func(authAddress, txnSender, reason string)
}

func (l *hookAuditLogger) LogSignApproved(record SignedRecord) {
	l.testAuditLogger.LogSignApproved(record)
	if l.onApprove != nil {
		l.onApprove(record)
	}
}

func (l *hookAuditLogger) LogSignFailed(authAddress, txnSender, reason string) {
	l.testAuditLogger.LogSignFailed(authAddress, txnSender, reason)
	if l.onFail != nil {
		l.onFail(authAddress, txnSender, reason)
	}
}

type nonRotatingFixture struct {
	edAddr            string
	edPriv            ed25519.PrivateKey
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
	store             *mapKeyStore
	session           *keystore.KeySession
}

func newNonRotatingFixture(t *testing.T) *nonRotatingFixture {
	t.Helper()
	ensureNonRotatingTestProviders()

	edPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize))
	edPub := edPriv.Public().(ed25519.PublicKey)
	var edAddr types.Address
	copy(edAddr[:], edPub)

	spendPub, spendPriv := testFalconComponentKeypair(t, 0x31)
	cosignPub, cosignPriv := testFalconComponentKeypair(t, 0x32)
	bytecode := []byte{0x06, 0x20, 0x01, 0x01, 0x22, 0x31, 0x32}
	boundedAddr := logicSigAddressForTest(t, bytecode)
	metadata := boundedCosignerTestMetadata(t, cosignPub)

	cosignEdPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	cosignEdPub := cosignEdPriv.Public().(ed25519.PublicKey)
	cosignerKeyID, err := witness.ID(witness.Ed25519V1, cosignEdPub)
	if err != nil {
		t.Fatal(err)
	}

	store := &mapKeyStore{
		keys: map[string]func() *coresigning.KeyMaterial{
			edAddr.String(): func() *coresigning.KeyMaterial {
				account, err := algocrypto.AccountFromPrivateKey(append(ed25519.PrivateKey(nil), edPriv...))
				if err != nil {
					panic(err)
				}
				return &coresigning.KeyMaterial{
					Type:      "ed25519",
					Category:  keys.CategoryEd25519,
					PublicKey: append([]byte(nil), edPub...),
					Value:     account,
				}
			},
			boundedAddr: func() *coresigning.KeyMaterial {
				return &coresigning.KeyMaterial{
					Type:                 "test.bounded-cosigner.v1",
					Category:             keys.CategoryDSALsig,
					BaseKeyType:          "aplane.falcon1024.v1",
					PublicKey:            append([]byte(nil), spendPub...),
					Bytecode:             append([]byte(nil), bytecode...),
					BoundedAuthorization: boundedmeta.Clone(metadata),
					Value:                &coresigning.LsigKeyMaterial{PrivateKey: append([]byte(nil), spendPriv...)},
				}
			},
			cosignerKeyID: func() *coresigning.KeyMaterial {
				return &coresigning.KeyMaterial{
					Type:      witness.Ed25519V1,
					Category:  keys.CategoryWitness,
					PublicKey: append([]byte(nil), cosignEdPub...),
					Value: &coresigning.WitnessKeyMaterial{
						WitnessKeyID: cosignerKeyID,
						PublicKey:    append([]byte(nil), cosignEdPub...),
						PrivateKey:   append([]byte(nil), cosignEdPriv...),
					},
				}
			},
		},
	}
	session := keystore.NewKeySession(store)
	session.InitializeSession()
	t.Cleanup(session.Destroy)

	return &nonRotatingFixture{
		edAddr:            edAddr.String(),
		edPriv:            edPriv,
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
		store:             store,
		session:           session,
	}
}

func (f *nonRotatingFixture) planner() *Planner {
	return &Planner{
		VerifySignableKeys: func(_ PlannerRuntimeSnapshot, reqs []signerapi.SignRequest, passthrough, foreign map[int]bool) (int, *ServiceError) {
			count := 0
			for i := range reqs {
				if !passthrough[i] && !foreign[i] {
					count++
				}
			}
			return count, nil
		},
		Snapshot: func() PlannerRuntimeSnapshot {
			return PlannerRuntimeSnapshot{
				KeyFiles: map[string]string{
					f.edAddr:      f.edAddr + ".key",
					f.boundedAddr: f.boundedAddr + ".key",
				},
				KeyTypes: map[string]string{
					f.edAddr:      "ed25519",
					f.boundedAddr: "test.bounded-cosigner.v1",
				},
				KeyMetadata: map[string]PlannerKeyMetadata{
					f.boundedAddr: {
						BaseKeyType:          "aplane.falcon1024.v1",
						PublicKeyHex:         hex.EncodeToString(f.boundedSpendPub),
						BoundedAuthorization: boundedmeta.Clone(f.boundedMeta),
					},
				},
			}
		},
	}
}

func (f *nonRotatingFixture) ordinarySign(t *testing.T, svc *Service, ctx context.Context) (bool, *ServiceError) {
	t.Helper()
	txn := paymentTransaction(t, f.edAddr, types.Address{0x55}.String(), 100)
	txn.Fee = 1_000
	txn.GenesisHash = testDigest(t, apconfig.AlgorandTestnetGenesisHash)
	req := signerapi.GroupSignRequest{
		RequestID: "req-ordinary",
		Requests: []signerapi.SignRequest{{
			AuthAddress: f.edAddr,
			TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
		}},
	}
	res, err := svc.SignGroupWithContext(ctx, req, f.session)
	return res != nil && len(res.Signed) == 1, err
}

func (f *nonRotatingFixture) boundedComponentSign(t *testing.T, svc *Service, ctx context.Context) (bool, *ServiceError) {
	t.Helper()
	txn := paymentTransaction(t, f.boundedAddr, types.Address{0x56}.String(), 100)
	txn.Fee = 1_000
	txn.GenesisHash = testDigest(t, apconfig.AlgorandTestnetGenesisHash)
	req := signerapi.ComponentRequest{
		RequestID:     "req-bounded",
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		Targets: []signerapi.ComponentTarget{{
			TargetIndex: 0,
			Kind:        signerapi.ComponentTargetKindBoundedBase,
			AuthAddress: f.boundedAddr,
		}},
	}
	res, err := svc.PrepareBoundedComponentWithContext(ctx, req, f.session)
	return res != nil && len(res.Components) == 1, err
}

func (f *nonRotatingFixture) cosignerComponentSign(t *testing.T, svc *Service, ctx context.Context) (bool, *ServiceError) {
	t.Helper()
	sender := types.Address{0x57}.String()
	receiver := types.Address{0x58}.String()
	txn := paymentTransaction(t, sender, receiver, 100)
	txn.Fee = 1_000
	txn.GenesisHash = testDigest(t, apconfig.AlgorandTestnetGenesisHash)
	req := signerapi.ComponentRequest{
		RequestID:     "req-cosigner",
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		Targets: []signerapi.ComponentTarget{{
			TargetIndex:  0,
			Kind:         signerapi.ComponentTargetKindCosigner,
			ComponentKey: f.cosignerKeyID,
		}},
	}
	res, err := svc.SignComponentsWithContext(ctx, req, f.session)
	return res != nil && len(res.Components) == 1, err
}

func (f *nonRotatingFixture) assemblyRequest(t *testing.T, withPassthrough bool) signerapi.AssemblyRequest {
	t.Helper()
	txn := paymentTransaction(t, f.boundedAddr, types.Address{0x59}.String(), 100)
	txn.Fee = 1_000
	txns := []types.Transaction{txn}
	if withPassthrough {
		ptTxn := paymentTransaction(t, f.edAddr, types.Address{0x5a}.String(), 50)
		ptTxn.Fee = 1_000
		txns = append(txns, ptTxn)
		gid, err := algocrypto.ComputeGroupID(txns)
		if err != nil {
			t.Fatal(err)
		}
		for i := range txns {
			txns[i].Group = gid
		}
	}
	rawHex := make([]string, len(txns))
	for i, tx := range txns {
		rawHex[i] = txnutil.EncodeWithPrefixHex(tx)
	}
	group, err := canonical.DecodeGroupHex(rawHex)
	if err != nil {
		t.Fatal(err)
	}
	signFalcon := func(priv, msg []byte) string {
		sig, err := signerops.New().Sign(priv, msg)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(sig)
	}
	txID := group.Entries[0].TxID
	receiptMsg, err := boundedAssemblyReceiptMessage(f.boundedAddr, txID[:], f.boundedMeta, nil)
	if err != nil {
		t.Fatal(err)
	}
	cosignerMsg := message.ComponentMessage(message.RoleCosigner, txID)
	req := signerapi.AssemblyRequest{
		RequestID:     "req-assemble",
		GroupBytesHex: rawHex,
		Targets: []signerapi.AssemblyTarget{{
			TargetIndex:       0,
			AuthAddress:       f.boundedAddr,
			BaseSignatures:    []string{signFalcon(f.boundedSpendPriv, txID[:])},
			AssemblyReceipt:   signFalcon(f.boundedSpendPriv, receiptMsg[:]),
			CosignerSignature: signFalcon(f.boundedCosignPriv, cosignerMsg[:]),
		}},
	}
	if withPassthrough {
		sig := ed25519.Sign(f.edPriv, txnutil.EncodeWithPrefix(txns[1]))
		var sigArr types.Signature
		copy(sigArr[:], sig)
		signedBytes := msgpack.Encode(types.SignedTxn{Txn: txns[1], Sig: sigArr})
		req.Passthrough = []signerapi.AssemblyPassthroughItem{{
			TargetIndex:  1,
			SignedTxnHex: hex.EncodeToString(signedBytes),
		}}
	}
	return req
}

func (f *nonRotatingFixture) newService(t *testing.T, audit AuditApproveLogger, unlocked *atomic.Bool) *Service {
	t.Helper()
	return &Service{
		Planner:                       f.planner(),
		Approval:                      &ApprovalService{UserAutoApprove: true},
		Executor:                      &Executor{},
		AuditLog:                      audit,
		GenerateTxnDescriptionFromTxn: describeAs("txn"),
		IsUnlocked:                    unlocked.Load,
		HoldsCosignerKey:              holdsAllCosignerKeys,
		PolicyFor: func(selector string) *policy.Config {
			if selector == f.cosignerKeyID {
				return wildcardCosignerPolicy(t)
			}
			return &policy.Config{TransactionTypes: policytest.AllowAllTypes()}
		},
	}
}

// Every audited non-rotating signing path (ordinary /sign, bounded-base
// /sign/component, and cosigner /sign/component) must:
//  1. release its key use before writing SIGN_APPROVED (so a stalled audit
//     disk cannot hold a lock's drain), and
//  2. recheck the session and caller context after SIGN_APPROVED, withholding
//     signatures and recording LogSignWithheld if a lock, recovery round-trip,
//     or caller cancel landed during the audit write.
func TestNonRotatingSigningEndsKeyUseBeforeAuditAndRechecksAfter(t *testing.T) {
	paths := []struct {
		name string
		run  func(*testing.T, *nonRotatingFixture, *Service, context.Context) (bool, *ServiceError)
	}{
		{"ordinary_sign", func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.ordinarySign(t, svc, ctx)
		}},
		{"bounded_component", func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.boundedComponentSign(t, svc, ctx)
		}},
		{"cosigner_component", func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.cosignerComponentSign(t, svc, ctx)
		}},
	}

	for _, path := range paths {
		t.Run(path.name+"/key_use_released_before_audit", func(t *testing.T) {
			f := newNonRotatingFixture(t)
			var unlocked atomic.Bool
			unlocked.Store(true)
			var keyUseActive atomic.Bool
			var keyUseCalls atomic.Int32
			var activeDuringAudit atomic.Bool

			audit := &hookAuditLogger{
				onApprove: func(SignedRecord) {
					if keyUseActive.Load() {
						activeDuringAudit.Store(true)
					}
				},
			}
			svc := f.newService(t, audit, &unlocked)
			svc.KeyUse = func(ctx context.Context) (context.Context, func()) {
				keyUseCalls.Add(1)
				keyUseActive.Store(true)
				return ctx, func() {
					keyUseActive.Store(false)
				}
			}

			ok, err := path.run(t, f, svc, context.Background())
			if err != nil || !ok {
				t.Fatalf("run() = (%v, %v), want success", ok, err)
			}
			if keyUseCalls.Load() != 1 {
				t.Fatalf("KeyUse calls = %d, want 1", keyUseCalls.Load())
			}
			if keyUseActive.Load() {
				t.Fatal("KeyUse was not released")
			}
			if activeDuringAudit.Load() {
				t.Fatal("KeyUse was still active when LogSignApproved ran")
			}
			if len(audit.approved) != 1 || len(audit.withheld) != 0 {
				t.Fatalf("audit approved=%d withheld=%d, want 1/0", len(audit.approved), len(audit.withheld))
			}
		})

		t.Run(path.name+"/session_ended_during_audit_withholds_signature", func(t *testing.T) {
			f := newNonRotatingFixture(t)
			var unlocked atomic.Bool
			unlocked.Store(true)
			audit := &hookAuditLogger{
				onApprove: func(SignedRecord) {
					// Simulates a lock or recovery+reconcile ending the request's session during the audit write.
					unlocked.Store(false)
				},
			}
			svc := f.newService(t, audit, &unlocked)
			svc.KeyUse = func(ctx context.Context) (context.Context, func()) { return ctx, func() {} }

			ok, err := path.run(t, f, svc, context.Background())
			if ok || err == nil || err.Kind != ErrorLocked {
				t.Fatalf("run() = (%v, %v), want nil + ErrorLocked", ok, err)
			}
			if len(audit.approved) != 1 || len(audit.withheld) != 1 {
				t.Fatalf("audit approved=%d withheld=%d, want 1/1", len(audit.approved), len(audit.withheld))
			}
			if audit.withheld[0].record.TxID != audit.approved[0].record.TxID {
				t.Fatalf("withheld TxID = %q, want approved TxID %q", audit.withheld[0].record.TxID, audit.approved[0].record.TxID)
			}
			if !strings.HasPrefix(audit.withheld[0].reason, "signature withheld after it was recorded as signed: ") {
				t.Fatalf("withheld reason = %q, want standard prefix", audit.withheld[0].reason)
			}
		})

		t.Run(path.name+"/caller_cancel_during_audit_withholds_signature", func(t *testing.T) {
			f := newNonRotatingFixture(t)
			var unlocked atomic.Bool
			unlocked.Store(true)
			ctx, cancel := context.WithCancel(context.Background())
			audit := &hookAuditLogger{
				onApprove: func(SignedRecord) {
					cancel()
				},
			}
			svc := f.newService(t, audit, &unlocked)
			svc.KeyUse = func(parent context.Context) (context.Context, func()) { return parent, func() {} }

			ok, err := path.run(t, f, svc, ctx)
			if ok || err == nil || err.Kind != ErrorUnavailable {
				t.Fatalf("run() = (%v, %v), want nil + ErrorUnavailable", ok, err)
			}
			if len(audit.approved) != 1 || len(audit.withheld) != 1 {
				t.Fatalf("audit approved=%d withheld=%d, want 1/1", len(audit.approved), len(audit.withheld))
			}
			if !strings.HasPrefix(audit.withheld[0].reason, "signature withheld after it was recorded as signed: ") {
				t.Fatalf("withheld reason = %q, want standard prefix", audit.withheld[0].reason)
			}
		})
	}
}

// KeyUse must start only after human operator approval returns, never spanning
// approval wait (otherwise Lock() would block waiting on an operator prompt).
func TestNonRotatingSigningNeverHoldsKeyUseDuringApproval(t *testing.T) {
	paths := []struct {
		name string
		run  func(*testing.T, *nonRotatingFixture, *Service, context.Context) (bool, *ServiceError)
	}{
		{"ordinary_sign", func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.ordinarySign(t, svc, ctx)
		}},
		{"bounded_component", func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.boundedComponentSign(t, svc, ctx)
		}},
	}

	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			f := newNonRotatingFixture(t)
			var unlocked atomic.Bool
			unlocked.Store(true)
			var keyUseCalls atomic.Int32
			var keyUseReleased atomic.Bool
			promptSawKeyUse := false
			prompted := false

			svc := f.newService(t, &testAuditLogger{}, &unlocked)
			svc.Approval = &ApprovalService{
				UserAutoApprove: false,
				HasClient:       func() bool { return true },
				KnownAddresses:  func() map[string]bool { return nil },
				RequestSigningApprovalPrompt: promptFromDecision(func(string, string, string, string, uint64, uint64, []signerapproval.Violation, time.Duration) (bool, error) {
					prompted = true
					if keyUseCalls.Load() != 0 {
						promptSawKeyUse = true
					}
					return true, nil
				}),
			}
			svc.KeyUse = func(ctx context.Context) (context.Context, func()) {
				keyUseCalls.Add(1)
				return ctx, func() { keyUseReleased.Store(true) }
			}

			ok, err := path.run(t, f, svc, context.Background())
			if err != nil || !ok {
				t.Fatalf("run() = (%v, %v), want success", ok, err)
			}
			if !prompted {
				t.Fatal("operator approval prompt was not called")
			}
			if promptSawKeyUse {
				t.Fatal("KeyUse was registered before operator approval returned")
			}
			if keyUseCalls.Load() != 1 || !keyUseReleased.Load() {
				t.Fatalf("keyUseCalls=%d released=%v, want 1 and true", keyUseCalls.Load(), keyUseReleased.Load())
			}
		})
	}
}

// If a lock+unlock or recovery+reconcile round-trip completes between the
// initial unlocked check and KeyUse registration, KeyUse returns a live
// context in the new session, and openKeyUse's post-registration IsUnlocked
// recheck must immediately release the key use without loading any key.
func TestNonRotatingSigningRefusesStaleSessionAfterKeyUseRegistration(t *testing.T) {
	paths := []struct {
		name           string
		auditAfterAppr bool
		run            func(*testing.T, *nonRotatingFixture, *Service, context.Context) (bool, *ServiceError)
	}{
		{"ordinary_sign", true, func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.ordinarySign(t, svc, ctx)
		}},
		{"bounded_component", true, func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.boundedComponentSign(t, svc, ctx)
		}},
		{"cosigner_component", false, func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.cosignerComponentSign(t, svc, ctx)
		}},
		{"assemble", false, func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			res, err := svc.AssembleWithContext(ctx, f.assemblyRequest(t, false), f.session)
			return res != nil, err
		}},
	}

	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			f := newNonRotatingFixture(t)
			var unlocked atomic.Bool
			unlocked.Store(true)
			var released atomic.Bool
			audit := &testAuditLogger{}
			svc := f.newService(t, audit, &unlocked)
			svc.KeyUse = func(ctx context.Context) (context.Context, func()) {
				// Simulate a full lock+unlock / recovery+reconcile round-trip:
				// KeyUse returns a live context for the new session, while this
				// request's session predicate (IsUnlocked) is now false.
				unlocked.Store(false)
				return ctx, func() { released.Store(true) }
			}

			ok, err := path.run(t, f, svc, context.Background())
			if ok || err == nil || err.Kind != ErrorLocked {
				t.Fatalf("run() = (%v, %v), want nil + ErrorLocked", ok, err)
			}
			if !released.Load() {
				t.Fatal("openKeyUse did not release KeyUse after post-registration session check failed")
			}
			if f.store.loads.Load() != 0 {
				t.Fatalf("store loads = %d, want 0", f.store.loads.Load())
			}
			if path.auditAfterAppr {
				if len(audit.rejected) != 1 || audit.rejected[0].reason != "session_ended_after_approval" {
					t.Fatalf("audit rejected = %+v, want one session_ended_after_approval entry", audit.rejected)
				}
			}
		})
	}
}

func TestAssembleWithContextKeyUseRefusalAndMidAssemblyCancel(t *testing.T) {
	t.Run("key_use_already_canceled", func(t *testing.T) {
		f := newNonRotatingFixture(t)
		var unlocked atomic.Bool
		unlocked.Store(true)
		svc := f.newService(t, nil, &unlocked)
		svc.KeyUse = refusedKeyUse(nil)

		res, err := svc.AssembleWithContext(context.Background(), f.assemblyRequest(t, true), f.session)
		if res != nil || err == nil || err.Kind != ErrorLocked {
			t.Fatalf("AssembleWithContext() = (%v, %v), want nil + ErrorLocked", res, err)
		}
		if f.store.loads.Load() != 0 {
			t.Fatalf("store loads = %d, want 0", f.store.loads.Load())
		}
	})

	t.Run("canceled_during_target_key_load", func(t *testing.T) {
		f := newNonRotatingFixture(t)
		var unlocked atomic.Bool
		unlocked.Store(true)
		var cancelUse context.CancelFunc
		var zeroedBeforeRelease atomic.Bool
		svc := f.newService(t, nil, &unlocked)
		svc.KeyUse = func(ctx context.Context) (context.Context, func()) {
			useCtx, cancel := context.WithCancel(ctx)
			cancelUse = cancel
			return useCtx, func() {
				if secret := f.store.lastKey.Load(); secret != nil && bytesAllZero(*secret) {
					zeroedBeforeRelease.Store(true)
				}
			}
		}
		f.store.onGet = func(_ context.Context, addr string) {
			if addr == f.boundedAddr {
				cancelUse()
			}
		}

		res, err := svc.AssembleWithContext(context.Background(), f.assemblyRequest(t, true), f.session)
		if res != nil || err == nil || err.Kind != ErrorLocked {
			t.Fatalf("AssembleWithContext() = (%v, %v), want nil + ErrorLocked", res, err)
		}
		if !zeroedBeforeRelease.Load() {
			t.Fatal("loaded bounded key was not zeroed before KeyUse released")
		}
		if f.store.loads.Load() != 1 {
			t.Fatalf("store loads = %d, want 1 (should stop before passthrough)", f.store.loads.Load())
		}
	})

	t.Run("canceled_during_passthrough_key_load", func(t *testing.T) {
		f := newNonRotatingFixture(t)
		var unlocked atomic.Bool
		unlocked.Store(true)
		var cancelUse context.CancelFunc
		var zeroedBeforeRelease atomic.Bool
		svc := f.newService(t, nil, &unlocked)
		svc.KeyUse = func(ctx context.Context) (context.Context, func()) {
			useCtx, cancel := context.WithCancel(ctx)
			cancelUse = cancel
			return useCtx, func() {
				if secret := f.store.lastKey.Load(); secret != nil && bytesAllZero(*secret) {
					zeroedBeforeRelease.Store(true)
				}
			}
		}
		f.store.onGet = func(_ context.Context, addr string) {
			if addr == f.edAddr {
				cancelUse()
			}
		}

		res, err := svc.AssembleWithContext(context.Background(), f.assemblyRequest(t, true), f.session)
		if res != nil || err == nil || err.Kind != ErrorLocked {
			t.Fatalf("AssembleWithContext() = (%v, %v), want nil + ErrorLocked", res, err)
		}
		if !zeroedBeforeRelease.Load() {
			t.Fatal("loaded passthrough key was not zeroed before KeyUse released")
		}
	})
}

// A non-canceled failure inside executeGroupSigning (such as a missing key on
// load) must release KeyUse before writing LogSignFailed to the audit log, so
// a stalled audit disk on a failing sign cannot hold a lock's drain.
func TestOrdinarySignFailureReleasesKeyUseBeforeAuditLog(t *testing.T) {
	f := newNonRotatingFixture(t)
	delete(f.store.keys, f.edAddr)

	var unlocked atomic.Bool
	unlocked.Store(true)
	var keyUseActive atomic.Bool
	var activeDuringFailAudit atomic.Bool
	var failAuditCalls atomic.Int32
	var gotAuth, gotSender, gotReason string

	audit := &hookAuditLogger{
		onFail: func(authAddress, txnSender, reason string) {
			failAuditCalls.Add(1)
			gotAuth, gotSender, gotReason = authAddress, txnSender, reason
			if keyUseActive.Load() {
				activeDuringFailAudit.Store(true)
			}
		},
	}
	svc := f.newService(t, audit, &unlocked)
	svc.Executor = &Executor{AuditLog: audit}
	svc.KeyUse = func(ctx context.Context) (context.Context, func()) {
		keyUseActive.Store(true)
		return ctx, func() { keyUseActive.Store(false) }
	}

	ok, err := f.ordinarySign(t, svc, context.Background())
	if ok || err == nil || err.Kind != ErrorInternal {
		t.Fatalf("ordinarySign() = (%v, %v), want false + ErrorInternal", ok, err)
	}
	if keyUseActive.Load() {
		t.Fatal("KeyUse was not released on signing failure")
	}
	if failAuditCalls.Load() != 1 {
		t.Fatalf("LogSignFailed calls = %d, want 1", failAuditCalls.Load())
	}
	if activeDuringFailAudit.Load() {
		t.Fatal("KeyUse was still active when LogSignFailed ran")
	}
	if gotAuth != f.edAddr || gotSender != f.edAddr || !strings.Contains(gotReason, "failed to load key") {
		t.Fatalf("LogSignFailed = (%q, %q, %q), want (%q, %q, failed to load key...)", gotAuth, gotSender, gotReason, f.edAddr, f.edAddr)
	}
}

// If the session ends during the last key load before cancellation propagates
// into useCtx, every audited signing route must stop before writing
// SIGN_APPROVED (with /sign and bounded components auditing
// session_ended_after_approval after releasing KeyUse), and /sign/assemble
// must still refuse at its post-release final session check.
func TestSessionEndDuringLoadStopsBeforeAuditAndAssemblyReturn(t *testing.T) {
	paths := []struct {
		name           string
		auditAfterAppr bool
		run            func(*testing.T, *nonRotatingFixture, *Service, context.Context) (bool, *ServiceError)
	}{
		{"ordinary_sign", true, func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.ordinarySign(t, svc, ctx)
		}},
		{"bounded_component", true, func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.boundedComponentSign(t, svc, ctx)
		}},
		{"cosigner_component", false, func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.cosignerComponentSign(t, svc, ctx)
		}},
		{"assemble", false, func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			res, err := svc.AssembleWithContext(ctx, f.assemblyRequest(t, true), f.session)
			return res != nil, err
		}},
	}

	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			f := newNonRotatingFixture(t)
			var unlocked atomic.Bool
			unlocked.Store(true)
			var keyUseActive atomic.Bool
			var released atomic.Bool
			audit := &testAuditLogger{}
			svc := f.newService(t, audit, &unlocked)
			svc.KeyUse = func(ctx context.Context) (context.Context, func()) {
				keyUseActive.Store(true)
				return ctx, func() {
					keyUseActive.Store(false)
					released.Store(true)
				}
			}
			f.store.onGet = func(context.Context, string) {
				// End the request's session without canceling useCtx, simulating a
				// session end whose context cancellation has not yet arrived.
				unlocked.Store(false)
			}

			ok, err := path.run(t, f, svc, context.Background())
			if ok || err == nil || err.Kind != ErrorLocked {
				t.Fatalf("run() = (%v, %v), want false + ErrorLocked", ok, err)
			}
			if !released.Load() || keyUseActive.Load() {
				t.Fatalf("released=%v keyUseActive=%v, want true and false", released.Load(), keyUseActive.Load())
			}
			if len(audit.approved) != 0 || len(audit.withheld) != 0 {
				t.Fatalf("audit approved=%d withheld=%d, want 0/0 (must stop before SIGN_APPROVED)", len(audit.approved), len(audit.withheld))
			}
			if path.auditAfterAppr {
				if len(audit.rejected) != 1 || audit.rejected[0].reason != "session_ended_after_approval" {
					t.Fatalf("audit rejected = %+v, want one session_ended_after_approval entry", audit.rejected)
				}
			}
		})
	}
}

// A client cancellation inside the key-use window cancels both requestCtx and
// the child useCtx; every route must report ErrorUnavailable (503), not
// ErrorLocked, and must not write session_ended_after_approval.
func TestNonRotatingSigningClientCancelInsideWindowReturns503WithoutSessionEndedAudit(t *testing.T) {
	paths := []struct {
		name string
		run  func(*testing.T, *nonRotatingFixture, *Service, context.Context) (bool, *ServiceError)
	}{
		{"ordinary_sign", func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.ordinarySign(t, svc, ctx)
		}},
		{"bounded_component", func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.boundedComponentSign(t, svc, ctx)
		}},
		{"cosigner_component", func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.cosignerComponentSign(t, svc, ctx)
		}},
		{"assemble", func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			res, err := svc.AssembleWithContext(ctx, f.assemblyRequest(t, true), f.session)
			return res != nil, err
		}},
	}

	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			f := newNonRotatingFixture(t)
			var unlocked atomic.Bool
			unlocked.Store(true)
			audit := &testAuditLogger{}
			svc := f.newService(t, audit, &unlocked)
			svc.KeyUse = func(ctx context.Context) (context.Context, func()) {
				useCtx, cancel := context.WithCancel(ctx)
				return useCtx, cancel
			}
			reqCtx, cancelReq := context.WithCancel(context.Background())
			defer cancelReq()
			f.store.onGet = func(context.Context, string) {
				cancelReq()
			}

			ok, err := path.run(t, f, svc, reqCtx)
			if ok || err == nil || err.Kind != ErrorUnavailable {
				t.Fatalf("run() = (%v, %v), want false + ErrorUnavailable", ok, err)
			}
			if len(audit.approved) != 0 || len(audit.rejected) != 0 {
				t.Fatalf("audit approved=%d rejected=%+v, want 0/0 on client cancel", len(audit.approved), audit.rejected)
			}
		})
	}
}

// Signing and assembly refuse with ErrorInternal when Service.KeyUse is nil,
// so no path can load key material unregistered.
func TestNonRotatingSigningRefusesNilKeyUse(t *testing.T) {
	paths := []struct {
		name string
		run  func(*testing.T, *nonRotatingFixture, *Service, context.Context) (bool, *ServiceError)
	}{
		{"ordinary_sign", func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.ordinarySign(t, svc, ctx)
		}},
		{"bounded_component", func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.boundedComponentSign(t, svc, ctx)
		}},
		{"cosigner_component", func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			return f.cosignerComponentSign(t, svc, ctx)
		}},
		{"assemble", func(t *testing.T, f *nonRotatingFixture, svc *Service, ctx context.Context) (bool, *ServiceError) {
			res, err := svc.AssembleWithContext(ctx, f.assemblyRequest(t, true), f.session)
			return res != nil, err
		}},
	}

	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			f := newNonRotatingFixture(t)
			var unlocked atomic.Bool
			unlocked.Store(true)
			audit := &testAuditLogger{}
			svc := f.newService(t, audit, &unlocked)
			svc.KeyUse = nil

			ok, err := path.run(t, f, svc, context.Background())
			if ok || err == nil || err.Kind != ErrorInternal {
				t.Fatalf("run() = (%v, %v), want false + ErrorInternal", ok, err)
			}
			if f.store.loads.Load() != 0 {
				t.Fatalf("store loads = %d, want 0", f.store.loads.Load())
			}
			if len(audit.rejected) != 0 {
				t.Fatalf("audit rejected = %+v, want 0 on unconfigured KeyUse", audit.rejected)
			}
		})
	}
}

// approveGroupWithPlanContext itself checks IsUnlocked after approval returns
// and records session_ended_after_approval (which rotating sign relies on,
// since it runs its own post-approval steps before opening a KeyUse).
func TestApproveGroupWithPlanRefusesWhenSessionEndedDuringApproval(t *testing.T) {
	f := newNonRotatingFixture(t)
	var unlocked atomic.Bool
	unlocked.Store(true)
	audit := &testAuditLogger{}
	svc := f.newService(t, audit, &unlocked)
	svc.Approval = &ApprovalService{
		UserAutoApprove: false,
		HasClient:       func() bool { return true },
		KnownAddresses:  func() map[string]bool { return nil },
		RequestSigningApprovalPrompt: promptFromDecision(func(string, string, string, string, uint64, uint64, []signerapproval.Violation, time.Duration) (bool, error) {
			unlocked.Store(false)
			return true, nil
		}),
	}
	txn := paymentTransaction(t, f.edAddr, types.Address{0x5b}.String(), 100)
	txn.Fee = 1_000
	txn.GenesisHash = testDigest(t, apconfig.AlgorandTestnetGenesisHash)
	req := signerapi.GroupSignRequest{
		RequestID: "req-approve-session-end",
		Requests: []signerapi.SignRequest{{
			AuthAddress: f.edAddr,
			TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
		}},
	}
	plan, planErr := svc.Planner.PlanGroup(req)
	if planErr != nil {
		t.Fatalf("PlanGroup() error = %v", planErr)
	}

	_, gateErr := svc.approveGroupWithPlanContext(context.Background(), req, plan)
	if gateErr == nil || gateErr.Kind != ErrorLocked {
		t.Fatalf("approveGroupWithPlanContext() error = %v, want ErrorLocked", gateErr)
	}
	if len(audit.rejected) != 1 || audit.rejected[0].reason != "session_ended_after_approval" {
		t.Fatalf("audit rejected = %+v, want one session_ended_after_approval entry", audit.rejected)
	}
}

type refusalExternalCheckRunner struct{}

func (refusalExternalCheckRunner) Run(context.Context, *policy.Config, externalcheck.Request) (*externalcheck.Summary, *externalcheck.Refusal) {
	return nil, &externalcheck.Refusal{
		CheckID: "check-1",
		Outcome: policy.ExternalCheckUnavailableOutcome,
		Unit:    "txn 1",
		Detail:  "denied",
	}
}

type rejectHookAuditLogger struct {
	testAuditLogger
	onReject func()
}

func (l *rejectHookAuditLogger) LogSignRejected(authAddress, txnSender, reason string) {
	l.testAuditLogger.LogSignRejected(authAddress, txnSender, reason)
	if l.onReject != nil {
		l.onReject()
	}
}

func (l *rejectHookAuditLogger) LogSignRejectedWithPolicyRule(authAddress, txnSender, reason, policyRuleID string) {
	l.testAuditLogger.LogSignRejectedWithPolicyRule(authAddress, txnSender, reason, policyRuleID)
	if l.onReject != nil {
		l.onReject()
	}
}

// External check refusals must release their key use before writing the
// rejection audit entry so a stalled audit disk cannot hold a lock's drain.
func TestExternalCheckRefusalReleasesKeyUseBeforeAuditLog(t *testing.T) {
	f := newNonRotatingFixture(t)
	var unlocked atomic.Bool
	unlocked.Store(true)
	var keyUseActive atomic.Bool
	var activeDuringRejectAudit atomic.Bool
	var rejectCalls atomic.Int32

	audit := &rejectHookAuditLogger{
		onReject: func() {
			rejectCalls.Add(1)
			if keyUseActive.Load() {
				activeDuringRejectAudit.Store(true)
			}
		},
	}
	cfg := wildcardCosignerPolicy(t)
	cfg.ExternalChecks = []policy.ExternalCheckV1{{ID: "check-1"}}
	svc := f.newService(t, audit, &unlocked)
	svc.PolicyFor = fixedPolicy(cfg)
	svc.ExternalChecks = refusalExternalCheckRunner{}
	svc.KeyUse = func(ctx context.Context) (context.Context, func()) {
		keyUseActive.Store(true)
		return ctx, func() { keyUseActive.Store(false) }
	}

	ok, err := f.cosignerComponentSign(t, svc, context.Background())
	if ok || err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("cosignerComponentSign() = (%v, %v), want false + ErrorForbidden", ok, err)
	}
	if keyUseActive.Load() {
		t.Fatal("KeyUse was not released after external check refusal")
	}
	if rejectCalls.Load() != 1 {
		t.Fatalf("rejection audit calls = %d, want 1", rejectCalls.Load())
	}
	if activeDuringRejectAudit.Load() {
		t.Fatal("KeyUse was still active when refuseExternalCheck wrote the audit entry")
	}
}

// A session end inside the key use of an approved /sign or bounded component
// is audited as session_ended_after_approval once per signed position, after
// the key use is released, and as nothing else.
func TestSessionEndInsideKeyUseIsAuditedOnceAfterRelease(t *testing.T) {
	twoBounded := func(t *testing.T, f *nonRotatingFixture, svc *Service) *ServiceError {
		a := paymentTransaction(t, f.boundedAddr, types.Address{0x61}.String(), 100)
		b := paymentTransaction(t, f.boundedAddr, types.Address{0x62}.String(), 100)
		a.Fee, b.Fee = 1_000, 1_000
		a.GenesisHash = testDigest(t, apconfig.AlgorandTestnetGenesisHash)
		b.GenesisHash = a.GenesisHash
		gid, err := algocrypto.ComputeGroupID([]types.Transaction{a, b})
		if err != nil {
			t.Fatal(err)
		}
		a.Group, b.Group = gid, gid
		_, signErr := svc.PrepareBoundedComponentWithContext(context.Background(), signerapi.ComponentRequest{
			RequestID:     "req-two-bounded",
			GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(a), txnutil.EncodeWithPrefixHex(b)},
			Targets: []signerapi.ComponentTarget{
				{TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: f.boundedAddr},
				{TargetIndex: 1, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: f.boundedAddr},
			},
		}, f.session)
		return signErr
	}
	ordinary := func(t *testing.T, f *nonRotatingFixture, svc *Service) *ServiceError {
		_, err := f.ordinarySign(t, svc, context.Background())
		return err
	}
	bounded := func(t *testing.T, f *nonRotatingFixture, svc *Service) *ServiceError {
		_, err := f.boundedComponentSign(t, svc, context.Background())
		return err
	}
	cases := []struct {
		name      string
		failLoad  bool
		positions int
		run       func(*testing.T, *nonRotatingFixture, *Service) *ServiceError
	}{
		{"ordinary/after_the_load", false, 1, ordinary},
		{"ordinary/the_load_fails", true, 1, ordinary},
		{"bounded/after_the_load", false, 1, bounded},
		{"bounded/the_load_fails", true, 1, bounded},
		{"bounded/before_the_second_target", false, 2, twoBounded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newNonRotatingFixture(t)
			var unlocked, active atomic.Bool
			unlocked.Store(true)
			var heldDuringAudit atomic.Bool
			audit := &rejectHookAuditLogger{onReject: func() {
				if active.Load() {
					heldDuringAudit.Store(true)
				}
			}}
			svc := f.newService(t, audit, &unlocked)
			svc.Executor.AuditLog = audit
			svc.KeyUse = func(ctx context.Context) (context.Context, func()) {
				active.Store(true)
				return ctx, func() { active.Store(false) }
			}
			f.store.onGet = func(_ context.Context, addr string) {
				unlocked.Store(false)
				if tc.failLoad {
					f.store.mu.Lock()
					delete(f.store.keys, addr)
					f.store.mu.Unlock()
				}
			}

			err := tc.run(t, f, svc)
			if err == nil || err.Kind != ErrorLocked {
				t.Fatalf("error = %v, want ErrorLocked", err)
			}
			if f.store.loads.Load() != 1 {
				t.Fatalf("key loads = %d, want 1", f.store.loads.Load())
			}
			if len(audit.rejected) != tc.positions {
				t.Fatalf("rejected = %+v, want %d entries", audit.rejected, tc.positions)
			}
			for _, entry := range audit.rejected {
				if entry.reason != "session_ended_after_approval" {
					t.Fatalf("rejected reason = %q, want session_ended_after_approval", entry.reason)
				}
			}
			if len(audit.approved) != 0 || len(audit.failed) != 0 || len(audit.withheld) != 0 {
				t.Fatalf("approved=%d failed=%d withheld=%d, want none", len(audit.approved), len(audit.failed), len(audit.withheld))
			}
			if heldDuringAudit.Load() {
				t.Fatal("the key use was still held during the audit write")
			}
		})
	}
}
