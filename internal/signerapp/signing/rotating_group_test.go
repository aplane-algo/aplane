// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// heldKeyFamily is a test-only native key type that signs with real
// Ed25519, so the rotating tests can verify owned slots' signatures without
// registering the production ed25519 provider, whose presence other tests in
// this binary do not expect.
const heldKeyFamily = "test.rotating-held.ed25519"

type heldKeyProvider struct{}

func (heldKeyProvider) RoutingFamily() string { return heldKeyFamily }
func (heldKeyProvider) LoadKeyMaterial(coresigning.ProviderKey) (*coresigning.KeyMaterial, error) {
	return nil, errors.New("not used")
}
func (heldKeyProvider) SignMessage(key *coresigning.KeyMaterial, message []byte) ([]byte, error) {
	priv, ok := key.Value.([]byte)
	if !ok || len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("held test key is not an ed25519 private key")
	}
	return ed25519.Sign(priv, message), nil
}
func (heldKeyProvider) ZeroKey(key *coresigning.KeyMaterial) {
	if key == nil {
		return
	}
	if priv, ok := key.Value.([]byte); ok {
		clear(priv)
	}
	key.Type, key.Value = "", nil
}

var registerHeldKeyProvider sync.Once

// holdAccount gives the fixture an ordinary credential the signer holds and
// signs with, and returns its address.
func (f *rotatingFixture) holdAccount(t testing.TB) types.Address {
	t.Helper()
	registerHeldKeyProvider.Do(func() { coresigning.Register(heldKeyProvider{}) })
	account := algocrypto.GenerateAccount()
	f.withMetadata(account.Address, heldKeyFamily, PlannerKeyMetadata{Category: keys.CategoryEd25519})
	if f.store.ordinary == nil {
		f.store.ordinary = map[string]ed25519.PrivateKey{}
	}
	f.store.ordinary[account.Address.String()] = account.PrivateKey
	if f.svc.Executor == nil {
		f.svc.Executor = &Executor{DecodeRuntimeArgs: DecodeHexRuntimeArgs}
	}
	return account.Address
}

// withMetadata overrides the planner snapshot's view of one address.
func (f *rotatingFixture) withMetadata(addr types.Address, keyType string, metadata PlannerKeyMetadata) {
	inner := f.svc.Planner.Snapshot
	f.svc.Planner.Snapshot = func() PlannerRuntimeSnapshot {
		snap := inner()
		snap.KeyFiles[addr.String()] = "keys/" + addr.String() + ".key"
		snap.KeyTypes[addr.String()] = keyType
		snap.KeyMetadata[addr.String()] = metadata
		return snap
	}
}

// payment is an ordinary account's transaction sharing the spend window.
func (f *rotatingFixture) payment(sender types.Address, firstValid, lastValid uint64) types.Transaction {
	txn := f.spend(firstValid, lastValid)
	txn.Sender = sender
	txn.Receiver = f.account
	txn.Amount = 5
	return txn
}

// slotRequests is the group form for txns, every slot signed by its sender.
func slotRequests(txns ...types.Transaction) []signerapi.SignRequest {
	out := make([]signerapi.SignRequest, len(txns))
	for i, txn := range txns {
		out[i] = signerapi.SignRequest{TxnBytesHex: txnutil.EncodeWithPrefixHex(txn)}
	}
	return out
}

func (f *rotatingFixture) prepareGroup(requests []signerapi.SignRequest) (*signerapi.RotatingPrepareResponse, *ServiceError) {
	return f.svc.PrepareRotatingWithContext(context.Background(), signerapi.RotatingPrepareRequest{
		Account: f.account.String(), Requests: requests,
	}, f.session)
}

func (f *rotatingFixture) signGroup(ctx context.Context, requests []signerapi.SignRequest) (*signerapi.RotatingSignResponse, *ServiceError) {
	return f.svc.SignRotatingWithContext(ctx, signerapi.RotatingSignRequest{
		Account: f.account.String(), Requests: requests,
	}, f.session)
}

// preparedSlots is the sign request for a prepared group: its user slots'
// prepared bytes with the authorization context sent to prepare.
func preparedSlots(prep *signerapi.RotatingPrepareResponse, sent []signerapi.SignRequest) []signerapi.SignRequest {
	out := make([]signerapi.SignRequest, len(sent))
	for i := range sent {
		out[i] = sent[i]
		out[i].TxnBytesHex = prep.Transactions[i]
	}
	return out
}

// preparedTxns decodes a prepared group.
func preparedTxns(t *testing.T, prep *signerapi.RotatingPrepareResponse) []types.Transaction {
	t.Helper()
	out := make([]types.Transaction, len(prep.Transactions))
	for i, h := range prep.Transactions {
		txn, err := txnutil.DecodePrefixedHex(h)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = txn
	}
	return out
}

// regroup is what a client that changes a user slot after prepare would
// send: the changed user slots under the group ID recomputed over them and
// the prepared dummies.
func regroup(t *testing.T, prep *signerapi.RotatingPrepareResponse, users []types.Transaction) []string {
	t.Helper()
	all := preparedTxns(t, prep)
	copy(all, users)
	for i := range all {
		all[i].Group = types.Digest{}
	}
	gid, err := algocrypto.ComputeGroupID(all)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(users))
	for i := range users {
		all[i].Group = gid
		out[i] = txnutil.EncodeWithPrefixHex(all[i])
	}
	return out
}

// TestRotatingGroupWithOwnedSlot runs a rotating spend grouped with a held
// account's payment, the rotating slot second, through prepare and sign for
// every rotating key type.
func TestRotatingGroupWithOwnedSlot(t *testing.T) {
	for _, kind := range rotatingTestTypes {
		t.Run(kind.keyType, func(t *testing.T) {
			f, audit := newSigningFixtureFor(t, kind)
			hot := f.holdAccount(t)
			window := [2]uint64{f.chain.round, f.chain.round + 100}
			sent := slotRequests(f.payment(hot, window[0], window[1]), f.spend(window[0], window[1]))
			prep, err := f.prepareGroup(sent)
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if len(prep.Rotations) != 1 || prep.Rotations[0].Index != 1 || prep.Rotations[0].Stage != 0 || prep.Rotations[0].Target != 1 {
				t.Fatalf("rotations %+v", prep.Rotations)
			}
			if prep.Stage != 0 || prep.Target != 1 || prep.RekeyTo != prep.Rotations[0].RekeyTo {
				t.Fatalf("scalar fields %d %d %s disagree with the rotation", prep.Stage, prep.Target, prep.RekeyTo)
			}
			if len(prep.OwnedIndexes) != 1 || prep.OwnedIndexes[0] != 0 {
				t.Fatalf("owned indexes %v", prep.OwnedIndexes)
			}
			// The owned slot's pooled budget counts: one dummy fewer than alone.
			wantDummies := max(kind.dummies-1, 0)
			if prep.Mutations == nil || prep.Mutations.DummiesAdded != wantDummies || prep.Mutations.OriginalCount != 2 || len(prep.Transactions) != 2+wantDummies {
				t.Fatalf("group of %d, mutations %+v; want %d dummies", len(prep.Transactions), prep.Mutations, wantDummies)
			}
			txns := preparedTxns(t, prep)
			if !txns[0].RekeyTo.IsZero() || txns[1].RekeyTo.String() != prep.Rotations[0].RekeyTo {
				t.Fatal("rekey set on the wrong slot")
			}

			resp, err := f.signGroup(context.Background(), preparedSlots(prep, sent))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if len(resp.Signed) != len(prep.Transactions) || len(resp.Rotations) != 1 || resp.Rotations[0].Index != 1 || resp.Rotations[0].TxID != resp.TxID {
				t.Fatalf("sign response %+v", resp)
			}
			var owned, spent types.SignedTxn
			decodeSigned(t, resp.Signed[0], &owned)
			decodeSigned(t, resp.Signed[1], &spent)
			if owned.Sig == (types.Signature{}) || len(owned.Lsig.Logic) != 0 || !bytes.Equal(txnutil.EncodeWithPrefix(owned.Txn), txnutil.EncodeWithPrefix(txns[0])) {
				t.Fatal("owned slot was not signed with its ed25519 key over the prepared bytes")
			}
			if !ed25519.Verify(hot[:], append([]byte("TX"), msgpack.Encode(owned.Txn)...), owned.Sig[:]) {
				t.Fatal("owned slot signature does not verify under the held key")
			}
			if len(spent.Lsig.Logic) == 0 || algocrypto.LogicSigAddress(spent.Lsig) != f.stageAddress(t, 0) {
				t.Fatal("rotating slot was not signed by stage 0")
			}
			if len(audit.releases) != 1 || audit.releases[0].TxID != resp.TxID {
				t.Fatalf("release audit %+v", audit.releases)
			}
			if audit.approved != 2 {
				t.Fatalf("approval audit entries %d, want one per signed slot", audit.approved)
			}
		})
	}
}

func decodeSigned(t *testing.T, h string, out *types.SignedTxn) {
	t.Helper()
	raw, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	if err := msgpack.Decode(raw, out); err != nil {
		t.Fatal(err)
	}
}

// TestRotatingSingleSlotFormsAgree proves the single-transaction form is
// the group form with one entry: both prepare the same canonical group, and
// the group form signs it.
func TestRotatingSingleSlotFormsAgree(t *testing.T) {
	f, _ := newSigningFixture(t)
	spend := f.spend(f.chain.round, f.chain.round+100)
	legacy := mustPrepare(t, f, spend)
	sent := slotRequests(spend)
	group, err := f.prepareGroup(sent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(legacy.Transactions, ",") != strings.Join(group.Transactions, ",") {
		t.Fatal("the two forms prepared different groups")
	}
	if len(group.Rotations) != 1 || group.Rotations[0].Index != 0 || len(group.OwnedIndexes) != 0 {
		t.Fatalf("single-slot group description %+v %v", group.Rotations, group.OwnedIndexes)
	}
	if _, err := f.signGroup(context.Background(), preparedSlots(group, sent)); err != nil {
		t.Fatalf("group-form sign of a single slot: %v", err)
	}
}

// TestRotatingBuilderIsDeterministic rebuilds a prepared group from its own
// user slots with finalized fees: the internal builder must reproduce it.
func TestRotatingBuilderIsDeterministic(t *testing.T) {
	f, _ := newSigningFixture(t)
	hot := f.holdAccount(t)
	window := [2]uint64{f.chain.round, f.chain.round + 100}
	prep, err := f.prepareGroup(slotRequests(f.payment(hot, window[0], window[1]), f.spend(window[0], window[1])))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := f.svc.Planner.Snapshot()
	slots, svcErr := normalizeRotatingSlots(snapshot, f.account, rotatingTestGenesis, preparedSlots(prep, make([]signerapi.SignRequest, 2)), rotatingSign)
	if svcErr != nil {
		t.Fatal(svcErr)
	}
	plan, svcErr := f.svc.buildRotatingPlan(snapshot, slots)
	if svcErr != nil {
		t.Fatal(svcErr)
	}
	for i, txn := range plan.AllTxns {
		if txnutil.EncodeWithPrefixHex(txn) != prep.Transactions[i] {
			t.Fatalf("rebuilt transaction %d differs", i+1)
		}
	}
}

func TestRotatingGroupAdmission(t *testing.T) {
	f, _ := newSigningFixture(t)
	hot := f.holdAccount(t)
	first, last := f.chain.round, f.chain.round+100
	spend := f.spend(first, last)
	pay := f.payment(hot, first, last)
	unheld := f.payment(types.Address{0xEE}, first, last)
	rekeyed := pay
	rekeyed.RekeyTo = types.Address{0xEF}
	window := pay
	window.LastValid = types.Round(last - 1)
	network := pay
	network.GenesisHash = types.Digest{0x42}
	grouped := pay
	grouped.Group = types.Digest{1}
	spendRekeyed := spend
	spendRekeyed.RekeyTo = types.Address{0xEF}
	rotatingSigner := slotRequests(pay, spend)
	rotatingSigner[0].AuthAddress = f.account.String()
	tests := []struct {
		name     string
		requests []signerapi.SignRequest
		want     string
	}{
		{"no rotating sender", slotRequests(pay), "no transaction is from the rotating account"},
		{"second rotating sender", slotRequests(spend, spend), "second transaction from the rotating account"},
		{"unheld owned sender", slotRequests(unheld, spend), "no key found"},
		{"owned slot signed by the rotating account", rotatingSigner, "rotating"},
		{"owned rekey", slotRequests(rekeyed, spend), "must not set rekey_to"},
		{"rotating rekey on prepare", slotRequests(pay, spendRekeyed), "the signer sets it"},
		{"window mismatch", slotRequests(window, spend), "share the rotating spend's rounds"},
		{"different network", slotRequests(network, spend), "different network"},
		{"pre-grouped owned slot", slotRequests(grouped, spend), "ungrouped"},
		{"rotating slot with an auth address", func() []signerapi.SignRequest {
			r := slotRequests(pay, spend)
			r[1].AuthAddress = hot.String()
			return r
		}(), "takes no auth_address"},
		{"rotating slot with LogicSig arguments", func() []signerapi.SignRequest {
			r := slotRequests(pay, spend)
			r[1].LsigArgs = map[string]string{"x": "01"}
			return r
		}(), "no LogicSig arguments"},
		{"passthrough slot", func() []signerapi.SignRequest {
			r := slotRequests(pay, spend)
			r[0] = signerapi.SignRequest{SignedTxnHex: "00"}
			return r
		}(), "signed_txn_hex"},
		{"foreign resource hint", func() []signerapi.SignRequest {
			r := slotRequests(pay, spend)
			r[0].LsigResources = &signerapi.LogicSigResourceUsage{ProgramBytes: 1}
			return r
		}(), "lsig_resources"},
		{"foreign PQ hint", func() []signerapi.SignRequest {
			r := slotRequests(pay, spend)
			r[0].PQScheme = nativefalcon.Scheme
			return r
		}(), "pq_scheme"},
		{"non-canonical encoding", func() []signerapi.SignRequest {
			r := slotRequests(pay, spend)
			r[0].TxnBytesHex += "00"
			return r
		}(), "transaction 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := f.prepareGroup(tt.requests)
			if err == nil || !strings.Contains(err.Message, tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRotatingGroupRefusesKeysThatCannotNest(t *testing.T) {
	first := uint64(1000)
	for name, tc := range map[string]struct {
		keyType  string
		metadata PlannerKeyMetadata
		want     string
	}{
		"witness":  {witness.Falcon1024V1, PlannerKeyMetadata{}, "transaction 1"},
		"bounded":  {"ed25519", PlannerKeyMetadata{Category: keys.CategoryEd25519, BoundedAuthorization: &boundedmeta.Metadata{}}, "bounded authorization"},
		"rotating": {"aplane.rotating-triple-wots.v1", PlannerKeyMetadata{}, "rotating"},
	} {
		t.Run(name, func(t *testing.T) {
			f, _ := newSigningFixture(t)
			other := algocrypto.GenerateAccount().Address
			f.withMetadata(other, tc.keyType, tc.metadata)
			_, err := f.prepareGroup(slotRequests(f.payment(other, first, first+100), f.spend(first, first+100)))
			if err == nil || !strings.Contains(err.Message, tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestRotatingGroupRekeyedOwnedSender signs an owned slot whose sender has
// no credential of its own: its auth_address names the held key it is
// rekeyed to, and that key signs.
func TestRotatingGroupRekeyedOwnedSender(t *testing.T) {
	f, _ := newSigningFixture(t)
	hot := f.holdAccount(t)
	sender := algocrypto.GenerateAccount().Address
	first, last := f.chain.round, f.chain.round+100
	sent := slotRequests(f.payment(sender, first, last), f.spend(first, last))
	sent[0].AuthAddress = hot.String()
	prep, err := f.prepareGroup(sent)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	resp, err := f.signGroup(context.Background(), preparedSlots(prep, sent))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	var owned types.SignedTxn
	decodeSigned(t, resp.Signed[0], &owned)
	if owned.AuthAddr != hot || owned.Sig == (types.Signature{}) {
		t.Fatalf("owned slot authorized by %s, want the held key %s", owned.AuthAddr, hot)
	}
}

// TestRotatingGroupFeesFollowOrdinaryAllocator puts a native-Falcon slot in
// the group. The ordinary allocator prefers it over every LogicSig slot, so
// it, not the rotating slot, pays the whole deficit: cross-subsidy under the
// shared rule, with no rotating exception.
func TestRotatingGroupFeesFollowOrdinaryAllocator(t *testing.T) {
	f, _ := newSigningFixture(t)
	pq := algocrypto.GenerateAccount().Address
	f.withMetadata(pq, nativefalcon.KeyType, PlannerKeyMetadata{Category: keys.CategoryNativePQ})
	first, last := f.chain.round, f.chain.round+100
	original := f.spend(first, last)
	prep, err := f.prepareGroup(slotRequests(f.payment(pq, first, last), original))
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	txns := preparedTxns(t, prep)
	if len(prep.Mutations.FeesModified) != 1 || prep.Mutations.FeesModified[0] != 0 {
		t.Fatalf("fees modified %v, want only the native-Falcon slot", prep.Mutations.FeesModified)
	}
	if txns[1].Fee != original.Fee || txns[0].Fee <= 1000 {
		t.Fatalf("fees: native-Falcon slot %d, rotating slot %d", txns[0].Fee, txns[1].Fee)
	}
	// Alone, the rotating slot pays its own deficit.
	alone := mustPrepare(t, f, original)
	if alone.Mutations.FeesModified[0] != 0 {
		t.Fatalf("alone, fees modified %v", alone.Mutations.FeesModified)
	}
}

// TestRotatingGroupSignRebuildChecks presents user-slot sign requests that
// do not rebuild to the presented group. Each is refused before approval
// and nothing is released.
func TestRotatingGroupSignRebuildChecks(t *testing.T) {
	f, audit := newSigningFixture(t)
	hot := f.holdAccount(t)
	first, last := f.chain.round, f.chain.round+100
	sent := slotRequests(f.payment(hot, first, last), f.spend(first, last))
	prep, err := f.prepareGroup(sent)
	if err != nil {
		t.Fatal(err)
	}
	prepared := preparedSlots(prep, sent)
	users := preparedTxns(t, prep)[:2]
	changed := append([]types.Transaction(nil), users...)
	changed[0].Amount = 6
	wrongTarget := append([]types.Transaction(nil), users...)
	wrongTarget[1].RekeyTo = f.stageAddress(t, 2)
	noTarget := append([]types.Transaction(nil), users...)
	noTarget[1].RekeyTo = types.Address{}
	tests := []struct {
		name     string
		requests func() []signerapi.SignRequest
		want     string
	}{
		{"owned slot changed without regrouping", func() []signerapi.SignRequest {
			r := append([]signerapi.SignRequest(nil), prepared...)
			r[0].TxnBytesHex = txnutil.EncodeWithPrefixHex(changed[0])
			return r
		}, "transaction 1"},
		{"rotating slot missing", func() []signerapi.SignRequest { return prepared[:1] }, "no transaction is from the rotating account"},
		{"owned slot missing", func() []signerapi.SignRequest { return prepared[1:] }, "transaction 1"},
		{"slots reordered", func() []signerapi.SignRequest {
			return []signerapi.SignRequest{prepared[1], prepared[0]}
		}, "transaction"},
		{"dummy presented as a user slot", func() []signerapi.SignRequest {
			return append(append([]signerapi.SignRequest(nil), prepared...), signerapi.SignRequest{TxnBytesHex: prep.Transactions[2]})
		}, "transaction 3"},
		{"inconsistent group IDs", func() []signerapi.SignRequest {
			r := append([]signerapi.SignRequest(nil), prepared...)
			one := users[0]
			one.Group = types.Digest{7}
			r[0].TxnBytesHex = txnutil.EncodeWithPrefixHex(one)
			return r
		}, "group ID"},
		{"non-canonical encoding", func() []signerapi.SignRequest {
			r := append([]signerapi.SignRequest(nil), prepared...)
			r[0].TxnBytesHex += "00"
			return r
		}, "canonical"},
		{"wrong rotation target", func() []signerapi.SignRequest {
			r := append([]signerapi.SignRequest(nil), prepared...)
			r[1].TxnBytesHex = regroup(t, prep, wrongTarget)[1]
			r[0].TxnBytesHex = regroup(t, prep, wrongTarget)[0]
			return r
		}, "not a stage of this account"},
		{"missing rotation target", func() []signerapi.SignRequest {
			r := append([]signerapi.SignRequest(nil), prepared...)
			r[1].TxnBytesHex = txnutil.EncodeWithPrefixHex(noTarget[1])
			return r
		}, "no rekey target"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := f.signGroup(context.Background(), tt.requests())
			if err == nil || !strings.Contains(err.Message, tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
	if len(audit.releases) != 0 {
		t.Fatalf("refused requests released %d signatures", len(audit.releases))
	}
	if _, ok := f.svc.Rotating.Releases.Get(f.account.String()); ok {
		t.Fatal("a refused request was remembered as a release")
	}
}

// TestRotatingLegacySignFormValidatesItsDummies sends the single-transaction
// form with a dummy altered or appended: the complete group is validated
// before it is normalized to one user slot.
func TestRotatingLegacySignFormValidatesItsDummies(t *testing.T) {
	f, audit := newSigningFixture(t)
	prep := mustPrepare(t, f, f.spend(f.chain.round, f.chain.round+100))
	if len(prep.Transactions) < 2 {
		t.Skip("key type needs no dummies")
	}
	txns := preparedTxns(t, prep)
	altered := append([]types.Transaction(nil), txns...)
	altered[len(altered)-1].Note = []byte{0x7f}
	extra := append(append([]types.Transaction(nil), txns...), txns[len(txns)-1])
	extra[len(extra)-1].Note = []byte{byte(len(txns))}
	for name, group := range map[string][]types.Transaction{"altered dummy": altered, "extra dummy": extra} {
		t.Run(name, func(t *testing.T) {
			for i := range group {
				group[i].Group = types.Digest{}
			}
			gid, err := algocrypto.ComputeGroupID(group)
			if err != nil {
				t.Fatal(err)
			}
			encoded := make([]string, len(group))
			for i := range group {
				group[i].Group = gid
				encoded[i] = txnutil.EncodeWithPrefixHex(group[i])
			}
			if _, svcErr := f.sign(t, encoded); svcErr == nil {
				t.Fatal("a legacy group with a non-canonical dummy suffix was signed")
			}
		})
	}
	if len(audit.releases) != 0 {
		t.Fatal("a refused legacy group was released")
	}
}

// TestRotatingGroupChangedOwnedSlotGetsFreshPolicy changes an owned slot
// after prepare and regroups it, as a client may. The rebuild accepts it, so
// policy judges what is presented: a per-key policy that refuses the change
// refuses the group, and no rotating signature is made.
func TestRotatingGroupChangedOwnedSlotGetsFreshPolicy(t *testing.T) {
	f, audit := newSigningFixture(t)
	hot := f.holdAccount(t)
	strict := policy.DefaultConfig()
	strict.RejectCloseRemainder = true
	f.svc.PolicyFor = keyedPolicy(map[string]*policy.Config{hot.String(): strict}, policy.DefaultConfig())
	first, last := f.chain.round, f.chain.round+100
	sent := slotRequests(f.payment(hot, first, last), f.spend(first, last))
	prep, err := f.prepareGroup(sent)
	if err != nil {
		t.Fatal(err)
	}
	users := preparedTxns(t, prep)[:2]
	users[0].CloseRemainderTo = f.account
	changed := preparedSlots(prep, sent)
	for i, h := range regroup(t, prep, users) {
		changed[i].TxnBytesHex = h
	}
	_, err = f.signGroup(context.Background(), changed)
	if err == nil || !strings.Contains(strings.ToLower(err.Message), "close") {
		t.Fatalf("changed owned slot: err = %v, want the close-out policy refusal", err)
	}
	if len(audit.releases) != 0 {
		t.Fatal("a policy-refused group was released")
	}
	// The unchanged group signs: the refusal was the presented change.
	if _, err := f.signGroup(context.Background(), preparedSlots(prep, sent)); err != nil {
		t.Fatalf("unchanged group: %v", err)
	}
}

// TestRotatingGroupOwnedPolicyRejectionSignsNothing refuses the owned slot
// by per-key policy: approval fails before any key is used.
func TestRotatingGroupOwnedPolicyRejectionSignsNothing(t *testing.T) {
	f, audit := newSigningFixture(t)
	hot := f.holdAccount(t)
	noPay := policy.DefaultConfig()
	noPay.TransactionTypes = policy.TransactionTypesV1{"*": policy.TransactionTypeAllow, "pay": policy.TransactionTypeReject}
	f.svc.PolicyFor = keyedPolicy(map[string]*policy.Config{hot.String(): noPay}, policy.DefaultConfig())
	first, last := f.chain.round, f.chain.round+100
	sent := slotRequests(f.payment(hot, first, last), f.spend(first, last))
	prep, err := f.prepareGroup(sent)
	if err != nil {
		t.Fatal(err)
	}
	// A key load before approval would surface as this failure instead of
	// the policy refusal.
	f.store.fail = map[string]error{hot.String(): errors.New("owned key was loaded before approval")}
	_, err = f.signGroup(context.Background(), preparedSlots(prep, sent))
	if err == nil || strings.Contains(err.Message, "loaded before approval") || !strings.Contains(err.Message, "pay") {
		t.Fatalf("err = %v, want the pay-type policy refusal", err)
	}
	if len(audit.releases) != 0 {
		t.Fatal("a policy-rejected group released a rotating signature")
	}
}

// TestRotatingGroupOwnedKeyFailureReleasesNothing makes the owned key fail
// to load after approval. The owned signature is made before the rotating
// one, so the failure leaves no rotating signature, no release record and,
// for a leaf family, no consumed leaf.
func TestRotatingGroupOwnedKeyFailureReleasesNothing(t *testing.T) {
	for _, kind := range []rotatingTestType{tripleTestType, xmssTestType} {
		t.Run(kind.keyType, func(t *testing.T) {
			f, audit := newSigningFixtureFor(t, kind)
			hot := f.holdAccount(t)
			first, last := f.chain.round, f.chain.round+100
			sent := slotRequests(f.payment(hot, first, last), f.spend(first, last))
			prep, err := f.prepareGroup(sent)
			if err != nil {
				t.Fatal(err)
			}
			f.store.fail = map[string]error{hot.String(): errors.New("disk on fire")}
			reads := f.chain.reads
			if _, err := f.signGroup(context.Background(), preparedSlots(prep, sent)); err == nil || !strings.Contains(err.Message, "transaction 1") {
				t.Fatalf("err = %v, want the owned slot's load failure", err)
			}
			if f.chain.reads != reads {
				t.Fatal("the rotating path ran after the owned key failed")
			}
			if len(audit.releases) != 0 {
				t.Fatal("an owned-key failure released a rotating signature")
			}
			if _, ok := f.svc.Rotating.Releases.Get(f.account.String()); ok {
				t.Fatal("an owned-key failure was remembered as a release")
			}
			// Nothing was consumed: the same group signs once the key loads.
			f.store.fail = nil
			if _, err := f.signGroup(context.Background(), preparedSlots(prep, sent)); err != nil {
				t.Fatalf("retry after the key recovered: %v", err)
			}
			if len(audit.releases) != 1 {
				t.Fatalf("retry released %d signatures", len(audit.releases))
			}
		})
	}
}

// cancellingChain cancels the sign request at its first chain read, which
// the rotating path makes under the account lock after the owned slots are
// signed.
type cancellingChain struct {
	base   *fakeRotatingChain
	cancel context.CancelFunc
}

func (c *cancellingChain) ReadAccount(ctx context.Context, genesis []byte, account types.Address) (chainread.AccountView, error) {
	c.cancel()
	if err := ctx.Err(); err != nil {
		return chainread.AccountView{}, err
	}
	return c.base.ReadAccount(ctx, genesis, account)
}

func TestRotatingGroupCancellationAfterOwnedSigningReleasesNothing(t *testing.T) {
	f, audit := newSigningFixture(t)
	hot := f.holdAccount(t)
	first, last := f.chain.round, f.chain.round+100
	sent := slotRequests(f.payment(hot, first, last), f.spend(first, last))
	prep, err := f.prepareGroup(sent)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.svc.Rotating.Chain = &cancellingChain{base: f.chain, cancel: cancel}
	if _, err := f.signGroup(ctx, preparedSlots(prep, sent)); err == nil {
		t.Fatal("a cancelled request returned signatures")
	}
	if len(audit.releases) != 0 {
		t.Fatal("a cancelled request released a rotating signature")
	}
	if _, ok := f.svc.Rotating.Releases.Get(f.account.String()); ok {
		t.Fatal("a cancelled request was remembered as a release")
	}
}

func TestRotatingApprovalNamesTheRotationAtItsIndex(t *testing.T) {
	plan := &PlanResult{
		AllTxns:            []types.Transaction{{Type: types.PaymentTx}, {Type: types.PaymentTx}},
		PassthroughIndices: map[int]bool{},
		ForeignIndices:     map[int]bool{},
		Rotating:           &rotatingPlanItem{Index: 1, Stage: 4, Target: 5, TargetAddress: types.Address{3}},
	}
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{}, {}}}
	desc, _, _ := BuildApprovalDescription(req, plan, plan.AllTxns, func(types.Transaction) string { return "txn" })
	parts := strings.SplitN(desc, "--- Transaction 2 of 2", 2)
	if len(parts) != 2 || strings.Contains(parts[0], "Rotation:") || !strings.Contains(parts[1], "stage 4 signs") {
		t.Fatalf("rotation not described on transaction 2:\n%s", desc)
	}
}

// TestRotatingSlotsKeepAppCallInfo checks that normalization keeps every
// slot's app-call metadata, the rotating slot's included, for the approval
// prompt.
func TestRotatingSlotsKeepAppCallInfo(t *testing.T) {
	f, _ := newSigningFixture(t)
	hot := f.holdAccount(t)
	first, last := f.chain.round, f.chain.round+100
	requests := slotRequests(f.payment(hot, first, last), f.spend(first, last))
	requests[0].AppCallInfo = &signerapi.AppCallInfo{Method: "owned()void"}
	requests[1].AppCallInfo = &signerapi.AppCallInfo{Method: "withdraw(uint64)void"}
	slots, err := normalizeRotatingSlots(f.svc.Planner.Snapshot(), f.account, rotatingTestGenesis, requests, rotatingPrepare)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"owned()void", "withdraw(uint64)void"} {
		if got := slots.Requests[i].AppCallInfo; got == nil || got.Method != want {
			t.Fatalf("slot %d app-call info = %+v, want method %q", i+1, got, want)
		}
	}
}

// genericLsigKeyType is the test key type of the owned generic LogicSig.
const genericLsigKeyType = "test.rotating-owned-generic.v1"

// holdGenericLsig gives the fixture a generic LogicSig account whose program
// approves only when its first argument is "secret", with that argument
// declared as a required runtime argument. It returns the account address
// and the program.
func (f *rotatingFixture) holdGenericLsig(t *testing.T) (types.Address, []byte) {
	t.Helper()
	// #pragma version 10; arg_0; pushbytes "secret"; ==
	program := append([]byte{0x0a, 0x2d, 0x80, 0x06}, append([]byte("secret"), 0x12)...)
	addr := algocrypto.AddressFromProgram(program)
	args := uint64(len("secret"))
	profile, err := lsigresource.Materialize(uint64(len(program)), &args, nil, lsigresource.DefaultOpcodeProfile(10))
	if err != nil {
		t.Fatal(err)
	}
	f.withMetadata(addr, genericLsigKeyType, PlannerKeyMetadata{Category: keys.CategoryGenericLsig, LogicSigResources: &profile})
	if f.store.generic == nil {
		f.store.generic = map[string]*coresigning.KeyMaterial{}
	}
	f.store.generic[addr.String()] = &coresigning.KeyMaterial{
		Type: genericLsigKeyType, Category: keys.CategoryGenericLsig, Bytecode: program,
		SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
		SigningArgs:            []lsigprovider.RuntimeArgDef{{Name: "secret", Type: "bytes", Required: true}},
	}
	if f.svc.Executor == nil {
		f.svc.Executor = &Executor{DecodeRuntimeArgs: DecodeHexRuntimeArgs}
	}
	return addr, program
}

// TestRotatingGroupOwnedGenericLogicSig groups a generic LogicSig whose
// program needs a runtime argument with a rotating spend. Its resource use
// counts in the plan, the ordinary allocator may charge it the deficit as a
// LogicSig participant, its lsig_args reach signing on the sign request, and
// leaving them out fails before any rotating signature.
func TestRotatingGroupOwnedGenericLogicSig(t *testing.T) {
	f, audit := newSigningFixture(t)
	lsigAddr, program := f.holdGenericLsig(t)
	first, last := f.chain.round, f.chain.round+100
	sent := slotRequests(f.payment(lsigAddr, first, last), f.spend(first, last))
	sent[0].LsigArgs = map[string]string{"secret": hex.EncodeToString([]byte("secret"))}
	prep, err := f.prepareGroup(sent)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	// Both LogicSigs are fee targets in request order, so the owned one,
	// first, pays the group's deficit.
	if len(prep.Mutations.FeesModified) != 1 || prep.Mutations.FeesModified[0] != 0 {
		t.Fatalf("fees modified %v, want the owned LogicSig, the first participant", prep.Mutations.FeesModified)
	}

	withoutArgs := preparedSlots(prep, sent)
	withoutArgs[0].LsigArgs = nil
	if _, err := f.signGroup(context.Background(), withoutArgs); err == nil || !strings.Contains(err.Message, "secret") {
		t.Fatalf("sign without the runtime argument: %v, want the missing-argument refusal", err)
	}
	if len(audit.releases) != 0 {
		t.Fatal("a refused owned LogicSig released a rotating signature")
	}

	resp, err := f.signGroup(context.Background(), preparedSlots(prep, sent))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	var owned types.SignedTxn
	decodeSigned(t, resp.Signed[0], &owned)
	if !bytes.Equal(owned.Lsig.Logic, program) || len(owned.Lsig.Args) != 1 || string(owned.Lsig.Args[0]) != "secret" {
		t.Fatalf("owned LogicSig signed with program %x args %q", owned.Lsig.Logic, owned.Lsig.Args)
	}
	if len(audit.releases) != 1 {
		t.Fatalf("releases %d, want 1", len(audit.releases))
	}
}
