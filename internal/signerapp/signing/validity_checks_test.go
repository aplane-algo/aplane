// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// The limits are the compiled consensus profile's own, so the cases are written
// from them: a literal here would pass or fail with the code's mistake.
func TestCheckTransactionBounds(t *testing.T) {
	profile, err := lsigresource.CurrentConsensus()
	if err != nil {
		t.Fatal(err)
	}
	// The absolute note maximum is above the size where a surcharge starts. A
	// check against the smaller one would refuse valid transactions.
	if profile.MaxAbsoluteTxnNoteBytes <= profile.MaxTxnNoteBytes {
		t.Fatalf("absolute note maximum %d is not above the surcharge threshold %d", profile.MaxAbsoluteTxnNoteBytes, profile.MaxTxnNoteBytes)
	}
	life := types.Round(profile.MaxTxnLife)
	window := func(first, last types.Round) types.Transaction {
		return types.Transaction{Type: types.PaymentTx, Header: types.Header{FirstValid: first, LastValid: last}}
	}
	note := func(size uint64) types.Transaction {
		txn := window(10, 20)
		txn.Note = make([]byte, size)
		return txn
	}
	for _, test := range []struct {
		name string
		txn  types.Transaction
		want string
	}{
		{name: "an ordinary window", txn: window(10, 20)},
		{name: "a window of one round", txn: window(10, 10)},
		{name: "the longest window", txn: window(10, 10+life)},
		{name: "one round too long", txn: window(10, 11+life), want: "is longer than the network's maximum"},
		{name: "a reversed window", txn: window(20, 10), want: "can never be valid"},
		{name: "reversed by one round", txn: window(11, 10), want: "can never be valid"},
		{name: "no note", txn: note(0)},
		{name: "a note at the surcharge threshold", txn: note(profile.MaxTxnNoteBytes)},
		{name: "a note that pays a surcharge", txn: note(profile.MaxTxnNoteBytes + 1)},
		{name: "the largest note", txn: note(profile.MaxAbsoluteTxnNoteBytes)},
		{name: "a note one byte too long", txn: note(profile.MaxAbsoluteTxnNoteBytes + 1), want: "above the network's maximum"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := checkTransactionBounds(&test.txn, profile)
			if test.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

// The planner refuses such a transaction before any key is looked up, so
// nothing reaches policy or approval. A lone transaction is the case that used
// to pass: the group check compares windows only across members.
func TestPlanGroupRefusesATransactionTheNetworkNeverAccepts(t *testing.T) {
	profile, err := lsigresource.CurrentConsensus()
	if err != nil {
		t.Fatal(err)
	}
	genesisHash := types.Digest{5}
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{
		base64.StdEncoding.EncodeToString(genesisHash[:]): "customnet_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizer := types.Address{8}
	payment := func(first, last types.Round, noteBytes uint64) types.Transaction {
		return types.Transaction{
			Type: types.PaymentTx,
			Header: types.Header{
				Sender: authorizer, Fee: 1_000, FirstValid: first, LastValid: last, GenesisHash: genesisHash,
				Note: make([]byte, noteBytes),
			},
		}
	}
	life := types.Round(profile.MaxTxnLife)
	sign := func(txn types.Transaction) signerapi.SignRequest {
		return signerapi.SignRequest{AuthAddress: authorizer.String(), TxnBytesHex: txnutil.EncodeWithPrefixHex(txn)}
	}
	foreign := func(txn types.Transaction) signerapi.SignRequest {
		// No auth address: another signer's position, here as context only.
		return signerapi.SignRequest{TxnBytesHex: txnutil.EncodeWithPrefixHex(txn)}
	}
	for _, test := range []struct {
		name     string
		requests []signerapi.SignRequest
		want     string
	}{
		{name: "a lone reversed window", requests: []signerapi.SignRequest{sign(payment(20, 10, 0))}, want: "transaction 1: last valid round 10 is before first valid round 20"},
		{name: "a lone window one round too long", requests: []signerapi.SignRequest{sign(payment(10, 11+life, 0))}, want: "transaction 1: validity window"},
		{name: "a lone note one byte too long", requests: []signerapi.SignRequest{sign(payment(10, 20, profile.MaxAbsoluteTxnNoteBytes+1))}, want: "transaction 1: note is"},
		// A member this signer doesn't sign still fails the whole group.
		{name: "a foreign member", requests: []signerapi.SignRequest{sign(payment(10, 20, 0)), foreign(payment(10, 11+life, 0))}, want: "transaction 2: validity window"},
	} {
		t.Run(test.name, func(t *testing.T) {
			planner := NewPlanner(stubPlannerDeps{keyTypes: map[string]string{authorizer.String(): "ed25519"}}, PlannerOptions{GenesisHashResolver: resolver})
			_, planErr := planner.PlanGroup(signerapi.GroupSignRequest{Requests: test.requests})
			if planErr == nil || planErr.Kind != ErrorBadRequest || !strings.Contains(planErr.Message, test.want) {
				t.Fatalf("PlanGroup error = %+v, want a bad request containing %q", planErr, test.want)
			}
		})
	}

	// The longest window the network allows still plans.
	planner := NewPlanner(stubPlannerDeps{keyTypes: map[string]string{authorizer.String(): "ed25519"}}, PlannerOptions{GenesisHashResolver: resolver})
	if _, planErr := planner.PlanGroup(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{sign(payment(10, 10+life, 0))}}); planErr != nil {
		t.Fatalf("the longest window was refused: %+v", planErr)
	}
}

// boundsCase is one transaction the network never accepts, made from an
// in-bounds one, with the refusal the bounds check gives it.
type boundsCase struct {
	name   string
	mutate func(*types.Transaction)
	want   string
}

func boundsCases(t *testing.T) []boundsCase {
	t.Helper()
	profile, err := lsigresource.CurrentConsensus()
	if err != nil {
		t.Fatal(err)
	}
	return []boundsCase{
		{
			name:   "a reversed window",
			mutate: func(x *types.Transaction) { x.FirstValid = x.LastValid + 1 },
			want:   "can never be valid",
		},
		{
			name:   "a window one round too long",
			mutate: func(x *types.Transaction) { x.LastValid = x.FirstValid + types.Round(profile.MaxTxnLife) + 1 },
			want:   "is longer than the network's maximum",
		},
		{
			name:   "a note one byte too long",
			mutate: func(x *types.Transaction) { x.Note = make([]byte, profile.MaxAbsoluteTxnNoteBytes+1) },
			want:   "above the network's maximum",
		},
	}
}

// wantBoundsRefusal checks for the bounds check's own refusal: a bad request
// that names the position and carries the bounds message.
func wantBoundsRefusal(t *testing.T, err *ServiceError, position int, want string) {
	t.Helper()
	prefix := fmt.Sprintf("transaction %d: ", position)
	if err == nil || err.Kind != ErrorBadRequest || !strings.HasPrefix(err.Message, prefix) || !strings.Contains(err.Message, want) {
		t.Fatalf("error = %+v, want a bad request starting %q and containing %q", err, prefix, want)
	}
}

// regroupedHex encodes the transactions as one group, with the group ID their
// current bytes need. A lone transaction stays ungrouped.
func regroupedHex(t *testing.T, txns []types.Transaction) []string {
	t.Helper()
	txns = append([]types.Transaction(nil), txns...)
	for i := range txns {
		txns[i].Group = types.Digest{}
	}
	if len(txns) > 1 {
		groupID, err := algocrypto.ComputeGroupID(txns)
		if err != nil {
			t.Fatal(err)
		}
		for i := range txns {
			txns[i].Group = groupID
		}
	}
	encoded := make([]string, len(txns))
	for i := range txns {
		encoded[i] = txnutil.EncodeWithPrefixHex(txns[i])
	}
	return encoded
}

// The rotating prepare route refuses a spend the network never accepts before
// it reads the chain or touches the stage table.
//
// Only the note case can reach the bounds check on a rotating route. The
// rotating spend's own rule (validateRotatingSpend: a window of at most
// RotatingMaxValidityWindow rounds, far below the network's maximum) runs
// first and refuses both a reversed window and one that is too long, so those
// two are pinned here with the rotating refusal they actually get.
func TestRotatingPrepareRefusesATransactionTheNetworkNeverAccepts(t *testing.T) {
	profile, err := lsigresource.CurrentConsensus()
	if err != nil {
		t.Fatal(err)
	}
	if rotatingkey.RotatingMaxValidityWindow >= profile.MaxTxnLife {
		t.Fatalf("the rotating window cap %d is no longer below the network's maximum %d: the window cases can now reach the bounds check, so pin them here", rotatingkey.RotatingMaxValidityWindow, profile.MaxTxnLife)
	}
	f, _ := newSigningFixture(t)
	reads := f.chain.reads
	for _, test := range boundsCases(t) {
		t.Run(test.name, func(t *testing.T) {
			txn := f.spend(1000, 1100)
			test.mutate(&txn)
			_, prepErr := f.prepare(t, txn)
			if len(txn.Note) == 0 {
				if prepErr == nil || prepErr.Kind != ErrorBadRequest || !strings.Contains(prepErr.Message, "validity window must be at most") {
					t.Fatalf("error = %+v, want the rotating window refusal, which comes first", prepErr)
				}
				return
			}
			wantBoundsRefusal(t, prepErr, 1, test.want)
		})
	}
	if f.chain.reads != reads {
		t.Fatalf("refused prepares read the chain %d times", f.chain.reads-reads)
	}

	// The largest note the network accepts is not refused. It pays a per-byte
	// surcharge, which twice the minimum fee covers.
	largest := f.spend(1000, 1100)
	largest.Note = make([]byte, profile.MaxAbsoluteTxnNoteBytes)
	largest.Fee = types.MicroAlgos(2 * profile.MinTxnFee)
	mustPrepare(t, f, largest)
}

// The rotating sign route is its own validation boundary: it makes the check
// on the presented bytes and does not rely on prepare having made it. As on
// prepare, only the note case reaches the bounds check; the rotating window
// rule refuses the two window cases first.
func TestRotatingSignRefusesATransactionTheNetworkNeverAccepts(t *testing.T) {
	profile, err := lsigresource.CurrentConsensus()
	if err != nil {
		t.Fatal(err)
	}
	f, audit := newSigningFixture(t)
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	group := make([]types.Transaction, len(prep.Transactions))
	for i, encoded := range prep.Transactions {
		txn, decodeErr := txnutil.DecodePrefixedHex(encoded)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		group[i] = txn
	}
	reads := f.chain.reads
	for _, test := range boundsCases(t) {
		t.Run(test.name, func(t *testing.T) {
			mutated := append([]types.Transaction(nil), group...)
			test.mutate(&mutated[0])
			_, signErr := f.sign(t, regroupedHex(t, mutated))
			if len(mutated[0].Note) == 0 {
				if signErr == nil || signErr.Kind != ErrorBadRequest || !strings.Contains(signErr.Message, "validity window must be at most") {
					t.Fatalf("error = %+v, want the rotating window refusal, which comes first", signErr)
				}
				return
			}
			wantBoundsRefusal(t, signErr, 1, test.want)
		})
	}
	if f.chain.reads != reads {
		t.Fatalf("refused signs read the chain %d times", f.chain.reads-reads)
	}
	if len(audit.releases) != 0 {
		t.Fatal("a refused sign recorded a release")
	}

	// In bounds: the prepared group signs, and so does a spend carrying the
	// largest note the network accepts (with a fee that covers its surcharge).
	mustSign(t, f, prep.Transactions)
	f, _ = newSigningFixture(t)
	largest := f.spend(1000, 1100)
	largest.Note = make([]byte, profile.MaxAbsoluteTxnNoteBytes)
	largest.Fee = types.MicroAlgos(2 * profile.MinTxnFee)
	mustSign(t, f, mustPrepare(t, f, largest).Transactions)
}

// Frozen-component validation never runs the planner, so it makes the check
// itself, on every position of the frozen group.
func TestValidateFrozenComponentContextRefusesATransactionTheNetworkNeverAccepts(t *testing.T) {
	profile, err := lsigresource.CurrentConsensus()
	if err != nil {
		t.Fatal(err)
	}
	service, authorizer, txn := frozenBoundedTestService(t, 4_500)
	frozen := func(t *testing.T, txn types.Transaction) ([]types.Transaction, signerapi.ComponentRequest) {
		t.Helper()
		planned, planErr := service.Planner.PlanGroup(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{
			AuthAddress: authorizer, TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
		}}})
		if planErr != nil {
			t.Fatal(planErr)
		}
		request := signerapi.ComponentRequest{
			Targets: []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: authorizer}},
		}
		for i := 1; i < len(planned.AllTxns); i++ {
			request.DummyPositions = append(request.DummyPositions, signerapi.ComponentDummyPosition{TargetIndex: i})
		}
		return planned.AllTxns, request
	}
	group, request := frozen(t, txn)
	if len(group) < 2 {
		t.Fatalf("the frozen group has %d transaction(s); the test needs a dummy position", len(group))
	}
	for _, test := range boundsCases(t) {
		t.Run(test.name, func(t *testing.T) {
			mutated := append([]types.Transaction(nil), group...)
			test.mutate(&mutated[0])
			// A dummy position is canonical only on the first transaction's
			// window, and that check runs first, so the dummies follow the
			// target's window. That also makes a dummy out of bounds on its own
			// unreachable here: its window is the target's and its note is one
			// byte, so the first position is always the one named.
			for i := 1; i < len(mutated); i++ {
				mutated[i].FirstValid, mutated[i].LastValid = mutated[0].FirstValid, mutated[0].LastValid
			}
			bad := request
			bad.GroupBytesHex = regroupedHex(t, mutated)
			_, _, serviceErr := service.ValidateFrozenComponentContext(bad)
			wantBoundsRefusal(t, serviceErr, 1, test.want)
		})
	}

	// In bounds: the group as planned, and the longest window the network
	// allows.
	request.GroupBytesHex = regroupedHex(t, group)
	if _, _, serviceErr := service.ValidateFrozenComponentContext(request); serviceErr != nil {
		t.Fatalf("the planned group was refused: %+v", serviceErr)
	}
	txn.LastValid = txn.FirstValid + types.Round(profile.MaxTxnLife)
	group, request = frozen(t, txn)
	request.GroupBytesHex = regroupedHex(t, group)
	if _, _, serviceErr := service.ValidateFrozenComponentContext(request); serviceErr != nil {
		t.Fatalf("the longest window was refused: %+v", serviceErr)
	}
}

// A cosigner node reaches neither the planner nor frozen-component validation,
// so its gates make the check, after the witness key is found and before the
// invariants and the policy. The refusal is input validation, like any other
// bad request, and is not written to the audit log.
func TestCosignerGatesRefuseATransactionTheNetworkNeverAccepts(t *testing.T) {
	profile, err := lsigresource.CurrentConsensus()
	if err != nil {
		t.Fatal(err)
	}
	componentKey := testFalconComponentSelector(t, 0xab)
	source, dest := types.Address{31}.String(), types.Address{32}.String()
	good := []types.Transaction{
		testnetPaymentTransaction(t, source, dest, 1),
		testnetPaymentTransaction(t, source, dest, 2),
	}
	// The wildcard policy allows every one of these transfers, so a refusal
	// can only be the bounds check's.
	gates := func(t *testing.T, holds func(string) bool, txns []types.Transaction) (*ServiceError, *limitedCosignerAuditLogger) {
		t.Helper()
		audit := &limitedCosignerAuditLogger{}
		svc := &Service{PolicyFor: fixedPolicy(wildcardCosignerPolicy(t)), HoldsCosignerKey: holds, AuditLog: audit}
		plan, planErr := prepareComponentSigning(componentPlanRequest{
			RequestID:     "cmp-cosigner-bounds",
			Role:          ComponentSignRoleCosigner,
			ComponentKey:  componentKey,
			GroupBytesHex: regroupedHex(t, txns),
			TargetIndices: []int{0},
		})
		if planErr != nil {
			t.Fatalf("prepareComponentSigning() error = %v", planErr)
		}
		return svc.runCosignerGates(plan), audit
	}
	unaudited := func(t *testing.T, audit *limitedCosignerAuditLogger) {
		t.Helper()
		if len(audit.limited)+len(audit.rejected)+len(audit.approved) != 0 {
			t.Fatalf("audit entries = limited %#v, rejected %#v, approved %#v; want none", audit.limited, audit.rejected, audit.approved)
		}
	}
	for _, test := range boundsCases(t) {
		// Position 1 is the target. Position 2 is not signed here and still
		// fails the whole group.
		for position := range good {
			t.Run(fmt.Sprintf("%s at position %d", test.name, position+1), func(t *testing.T) {
				mutated := append([]types.Transaction(nil), good...)
				test.mutate(&mutated[position])
				gateErr, audit := gates(t, holdsAllCosignerKeys, mutated)
				wantBoundsRefusal(t, gateErr, position+1, test.want)
				unaudited(t, audit)

				// The key check comes first: a node that doesn't hold the
				// witness key says so, whatever the group looks like.
				gateErr, audit = gates(t, func(string) bool { return false }, mutated)
				if gateErr == nil || gateErr.Kind != ErrorBadRequest || !strings.Contains(gateErr.Message, "not found") || strings.Contains(gateErr.Message, test.want) {
					t.Fatalf("error without the key = %+v, want witness key not found", gateErr)
				}
				unaudited(t, audit)
			})
		}
	}

	// In bounds: the group as built, the longest window, and the largest note.
	if gateErr, _ := gates(t, holdsAllCosignerKeys, good); gateErr != nil {
		t.Fatalf("an in-bounds group was refused: %+v", gateErr)
	}
	edge := append([]types.Transaction(nil), good...)
	edge[0].LastValid = edge[0].FirstValid + types.Round(profile.MaxTxnLife)
	edge[1].Note = make([]byte, profile.MaxAbsoluteTxnNoteBytes)
	if gateErr, _ := gates(t, holdsAllCosignerKeys, edge); gateErr != nil {
		t.Fatalf("a group at the limits was refused: %+v", gateErr)
	}
}

func TestDecodeTransactionsRefusesBytesThatAreNotCanonical(t *testing.T) {
	var sender, receiver types.Address
	sender[0], sender[31], receiver[0] = 1, 9, 2
	txn := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender, Fee: 1_000, FirstValid: 1, LastValid: 10},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: receiver, Amount: 1},
	}
	canonicalBytes := txnutil.EncodeWithPrefix(txn)
	body := canonicalBytes[2:]

	decode := func(raw []byte) *ServiceError {
		_, _, err := decodeTransactions(
			[]signerapi.SignRequest{{AuthAddress: sender.String(), TxnBytesHex: hex.EncodeToString(raw)}},
			map[int]bool{}, consoleOf(nil))
		return err
	}
	if err := decode(canonicalBytes); err != nil {
		t.Fatalf("canonical bytes refused: %v", err)
	}

	// The payment with its amount written a second time, as 5,000,000, after
	// its other fields. A lenient decoder keeps the last value.
	var probe types.Transaction
	repeated := append([]byte{'T', 'X', body[0] + 1}, body[1:]...)
	repeated = append(repeated, msgpack.Encode(map[string]uint64{"amt": 5_000_000})[1:]...)
	if err := msgpack.Decode(repeated[2:], &probe); err != nil || probe.Amount != 5_000_000 {
		t.Fatalf("fixture: repeated-field payment decoded to amount %d, %v", probe.Amount, err)
	}

	// The sender as 31 bytes. A lenient decoder pads it to a different
	// account. The receiver differs from the sender, so the field rewritten
	// here can only be the sender.
	shortSender := bytes.Replace(body, append([]byte{0xc4, 32}, sender[:]...), append([]byte{0xc4, 31}, sender[:31]...), 1)
	if bytes.Equal(shortSender, body) {
		t.Fatal("fixture: the sender field was not found in the encoding")
	}
	probe = types.Transaction{}
	if err := msgpack.Decode(shortSender, &probe); err != nil || probe.Receiver != receiver || probe.Sender == sender {
		t.Fatalf("fixture: short-sender payment decoded with sender %s, receiver %s, %v; want another sender",
			probe.Sender, probe.Receiver, err)
	}

	for name, tc := range map[string]struct {
		raw  []byte
		want string
	}{
		"no TX prefix":    {body, canonical.ErrMissingTXPrefix.Error()},
		"prefix only":     {[]byte{'T', 'X'}, canonical.ErrInvalidMsgpack.Error()},
		"not msgpack":     {[]byte{'T', 'X', 0xc1}, canonical.ErrInvalidMsgpack.Error()},
		"trailing bytes":  {append(append([]byte{}, canonicalBytes...), 0xc0), canonical.ErrNotCanonical.Error()},
		"second txn":      {append(append([]byte{}, canonicalBytes...), body...), canonical.ErrNotCanonical.Error()},
		"repeated field":  {repeated, canonical.ErrNotCanonical.Error()},
		"31-byte address": {append([]byte{'T', 'X'}, shortSender...), canonical.ErrNotCanonical.Error()},
	} {
		err := decode(tc.raw)
		if err == nil {
			t.Errorf("%s: accepted, want refused", name)
			continue
		}
		if err.Kind != ErrorBadRequest || !strings.HasSuffix(err.Message, ": "+tc.want) {
			t.Errorf("%s: %v %q, want a bad request ending %q", name, err.Kind, err.Message, tc.want)
		}
	}
}

func TestDecodeTransactionsRefusesPassthroughBytesThatAreNotCanonical(t *testing.T) {
	var sender types.Address
	sender[0] = 1
	stxn := types.SignedTxn{
		Sig: types.Signature{1},
		Txn: types.Transaction{
			Type:             types.PaymentTx,
			Header:           types.Header{Sender: sender, Fee: 1_000, FirstValid: 1, LastValid: 10},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: sender, Amount: 1},
		},
	}
	signed := msgpack.Encode(stxn)
	decode := func(raw []byte) *ServiceError {
		_, _, err := decodeTransactions(
			[]signerapi.SignRequest{{SignedTxnHex: hex.EncodeToString(raw)}},
			map[int]bool{0: true}, consoleOf(nil))
		return err
	}
	if err := decode(signed); err != nil {
		t.Fatalf("canonical passthrough refused: %v", err)
	}
	// The signature written a second time, as a different one. A lenient
	// decoder keeps the last, so the bytes forwarded would carry a signature
	// other than the first one a reader sees.
	other := types.Signature{2}
	repeated := append([]byte{signed[0] + 1}, signed[1:]...)
	repeated = append(repeated, msgpack.Encode(map[string]types.Signature{"sig": other})[1:]...)
	var probe types.SignedTxn
	if err := msgpack.Decode(repeated, &probe); err != nil || probe.Sig != other {
		t.Fatalf("fixture: repeated-signature bytes decoded to %x, %v", probe.Sig[:2], err)
	}

	for name, raw := range map[string][]byte{
		"trailing bytes":     append(append([]byte{}, signed...), 0xc0),
		"second transaction": append(append([]byte{}, signed...), signed...),
		"repeated field":     repeated,
	} {
		err := decode(raw)
		if err == nil || err.Kind != ErrorBadRequest || !strings.HasSuffix(err.Message, canonical.ErrNotCanonical.Error()) {
			t.Errorf("%s: %v, want a bad request ending %q", name, err, canonical.ErrNotCanonical.Error())
		}
	}
}

func TestRequestBytesRefusalEscapesTheCodecsDetailOnTheConsole(t *testing.T) {
	// A map key holding an escape sequence and a forged console line. The
	// codec quotes the key in its error.
	key := "\x1b[2J\n[GROUP] 1 key(s) available for signing"
	raw := append([]byte{'T', 'X', 0x81, 0xd9, byte(len(key))}, key...)
	raw = append(raw, 0x01)

	var console printedConsole
	_, _, err := decodeTransactions(
		[]signerapi.SignRequest{{AuthAddress: "A", TxnBytesHex: hex.EncodeToString(raw)}},
		map[int]bool{}, &console)
	if err == nil || !strings.HasSuffix(err.Message, canonical.ErrInvalidMsgpack.Error()) {
		t.Fatalf("unknown-field bytes: %v, want the fixed invalid-msgpack text", err)
	}
	if strings.Contains(err.Message, "struct field") {
		t.Fatalf("the client was sent the codec's own wording: %q", err.Message)
	}
	printed := console.String()
	if !strings.Contains(printed, "refused") {
		t.Fatalf("the console has no line for the refusal: %q", printed)
	}
	if strings.ContainsAny(printed, "\x1b") || strings.Count(printed, "\n") != 1 {
		t.Fatalf("the console line carries raw control bytes from the request: %q", printed)
	}
}
