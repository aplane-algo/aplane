// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// recordingReleaseAudit captures ROTATING_RELEASE entries and can fail.
type recordingReleaseAudit struct {
	releases []ReleaseRecord
	fail     error
}

func (a *recordingReleaseAudit) LogSignApproved(string, string, string) {}
func (a *recordingReleaseAudit) LogRotatingRelease(account, txid string, stage, lastValid uint64) error {
	if a.fail != nil {
		return a.fail
	}
	a.releases = append(a.releases, ReleaseRecord{Account: account, Stage: stage, TxID: txid, LastValid: lastValid})
	return nil
}

// signingFixture extends the table fixture with approval, policy and
// release memory, so prepare and sign can run end to end against the fake
// chain.
func newSigningFixture(t *testing.T) (*rotatingFixture, *recordingReleaseAudit) {
	t.Helper()
	f := newRotatingFixture(t)
	audit := &recordingReleaseAudit{}
	approve := true
	f.svc.Approval = &ApprovalService{UserAutoApprove: &approve}
	f.svc.GenerateTxnDescriptionFromTxn = func(types.Transaction) string { return "txn" }
	f.svc.Policy = policy.DefaultConfig()
	f.svc.AuditLog = audit
	f.svc.Rotating.Releases = &ReleaseMemory{}
	f.chain.round = 1000
	return f, audit
}

func (f *rotatingFixture) spend(firstValid, lastValid uint64) types.Transaction {
	var gh [32]byte
	copy(gh[:], rotatingTestGenesis)
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      f.account,
			Fee:         1000,
			FirstValid:  types.Round(firstValid),
			LastValid:   types.Round(lastValid),
			GenesisHash: gh,
		},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: f.account, Amount: 0},
	}
}

func (f *rotatingFixture) prepare(t *testing.T, txn types.Transaction) (*signerapi.RotatingPrepareResponse, *ServiceError) {
	t.Helper()
	return f.svc.PrepareRotatingWithContext(context.Background(), signerapi.RotatingPrepareRequest{
		Account: f.account.String(), TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
	}, f.session)
}

func (f *rotatingFixture) sign(t *testing.T, txns []string) (*signerapi.RotatingSignResponse, *ServiceError) {
	t.Helper()
	return f.svc.SignRotatingWithContext(context.Background(), signerapi.RotatingSignRequest{
		Account: f.account.String(), Transactions: txns,
	}, f.session)
}

func mustPrepare(t *testing.T, f *rotatingFixture, txn types.Transaction) *signerapi.RotatingPrepareResponse {
	t.Helper()
	prep, err := f.prepare(t, txn)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return prep
}

func mustSign(t *testing.T, f *rotatingFixture, txns []string) *signerapi.RotatingSignResponse {
	t.Helper()
	resp, err := f.sign(t, txns)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return resp
}

// land simulates the released rotation confirming on chain.
func (f *rotatingFixture) land(t *testing.T, resp *signerapi.RotatingSignResponse) {
	t.Helper()
	f.chain.authorizer = f.stageAddress(t, resp.Target)
	f.chain.round += 3
}

func TestRotatingHappyPathThreeRotations(t *testing.T) {
	f, audit := newSigningFixture(t)
	for stage := uint64(0); stage < 3; stage++ {
		prep := mustPrepare(t, f, f.spend(f.chain.round, f.chain.round+100))
		if prep.Stage != stage || prep.Target != stage+1 || prep.RekeyTo != f.stageAddress(t, stage+1).String() {
			t.Fatalf("stage %d prepare = %+v", stage, prep)
		}
		if len(prep.Transactions) != 2 || prep.Mutations == nil || prep.Mutations.DummiesAdded != 1 {
			t.Fatalf("stage %d group = %d txns, mutations %+v", stage, len(prep.Transactions), prep.Mutations)
		}
		resp := mustSign(t, f, prep.Transactions)
		if resp.Stage != stage || resp.Target != stage+1 || len(resp.Signed) != 2 {
			t.Fatalf("stage %d sign = %+v", stage, resp)
		}
		// The LogicSig attached is the live stage's program, so its address
		// is the authorizer the chain showed.
		var stxn types.SignedTxn
		raw, _ := hex.DecodeString(resp.Signed[0])
		if err := msgpack.Decode(raw, &stxn); err != nil {
			t.Fatal(err)
		}
		if stxn.Txn.RekeyTo != f.stageAddress(t, stage+1) {
			t.Fatalf("signed rekey to %s, want stage %d", stxn.Txn.RekeyTo, stage+1)
		}
		if stage > 0 && stxn.AuthAddr != f.stageAddress(t, stage) {
			t.Fatalf("auth addr %s, want stage %d", stxn.AuthAddr, stage)
		}
		rec, ok := f.svc.Rotating.Releases.Get(f.account.String())
		if !ok || rec.Stage != stage || rec.StageAddr != f.stageAddress(t, stage) || rec.NextAddr != f.stageAddress(t, stage+1) || rec.TxID != resp.TxID {
			t.Fatalf("release memory = %+v, %v", rec, ok)
		}
		f.land(t, resp)
	}
	if len(audit.releases) != 3 || audit.releases[2].Stage != 2 {
		t.Fatalf("audit releases = %+v", audit.releases)
	}
	// The table now covers every stage used plus the next target.
	if f.table(t).Len() < 4 {
		t.Fatalf("table len = %d, want at least 4", f.table(t).Len())
	}
}

func TestRotatingPrepareRejectsMalformedSpends(t *testing.T) {
	f, _ := newSigningFixture(t)
	good := f.spend(1000, 1100)
	cases := map[string]func(*types.Transaction){
		"wrong sender":  func(x *types.Transaction) { x.Sender = types.Address{9} },
		"wrong network": func(x *types.Transaction) { x.GenesisHash[0] ^= 1 },
		"close-out":     func(x *types.Transaction) { x.CloseRemainderTo = types.Address{9} },
		"window of 101": func(x *types.Transaction) { x.LastValid = x.FirstValid + 101 },
		"rekey preset":  func(x *types.Transaction) { x.RekeyTo = types.Address{9} },
		"grouped":       func(x *types.Transaction) { x.Group = types.Digest{1} },
	}
	for name, mutate := range cases {
		txn := good
		mutate(&txn)
		if _, err := f.prepare(t, txn); err == nil || err.Kind != ErrorBadRequest {
			t.Errorf("%s: err = %v, want bad request", name, err)
		}
	}
	if f.table(t).Len() > 2 {
		t.Fatalf("rejected prepares extended the table to %d", f.table(t).Len())
	}
}

func TestRotatingSignIsTheValidationBoundary(t *testing.T) {
	f, _ := newSigningFixture(t)
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	decode := func(h string) types.Transaction {
		txn, err := txnutil.DecodePrefixedHex(h)
		if err != nil {
			t.Fatal(err)
		}
		return txn
	}
	spend, dummy := decode(prep.Transactions[0]), decode(prep.Transactions[1])
	with := func(mutateSpend func(*types.Transaction), mutateDummy func(*types.Transaction)) []string {
		s, d := spend, dummy
		if mutateSpend != nil {
			mutateSpend(&s)
		}
		if mutateDummy != nil {
			mutateDummy(&d)
		}
		return []string{txnutil.EncodeWithPrefixHex(s), txnutil.EncodeWithPrefixHex(d)}
	}
	cases := map[string][]string{
		"rekey to a non-stage":      with(func(x *types.Transaction) { x.RekeyTo = types.Address{7} }, nil),
		"rekey to the live stage":   with(func(x *types.Transaction) { x.RekeyTo = f.account }, nil),
		"rekey two stages ahead":    with(func(x *types.Transaction) { x.RekeyTo = f.stageAddress(t, 2) }, nil),
		"fee lowered":               with(func(x *types.Transaction) { x.Fee = 1000 }, nil),
		"dummy note changed":        with(nil, func(x *types.Transaction) { x.Note = []byte("x") }),
		"group id cleared":          with(func(x *types.Transaction) { x.Group = types.Digest{} }, func(x *types.Transaction) { x.Group = types.Digest{} }),
		"dummy dropped":             prep.Transactions[:1],
		"amount changed after prep": with(func(x *types.Transaction) { x.Amount = 5 }, nil),
	}
	for name, txns := range cases {
		_, err := f.sign(t, txns)
		if err == nil || err.Kind != ErrorBadRequest {
			t.Errorf("%s: err = %v, want bad request", name, err)
		}
	}
	// A stage-2 target was derived to serve the lookup above; the table may
	// have grown, but it is a cache and nothing was signed.
	if _, ok := f.svc.Rotating.Releases.Get(f.account.String()); ok {
		t.Fatal("a rejected sign recorded a release")
	}
	// The untouched group still signs.
	mustSign(t, f, prep.Transactions)
}

func TestRotatingSignRefusesWhenTheAccountMovedDuringApproval(t *testing.T) {
	f, _ := newSigningFixture(t)
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	// Another release from stage 0 landed before this one was approved.
	f.chain.authorizer = f.stageAddress(t, 1)
	_, err := f.sign(t, prep.Transactions)
	if err == nil || err.Kind != ErrorRotatingStageChanged {
		t.Fatalf("err = %v, want rotating_stage_changed", err)
	}
	if _, ok := f.svc.Rotating.Releases.Get(f.account.String()); ok {
		t.Fatal("a refused sign recorded a release")
	}
	// Rebuilding from stage 1 works: the next prepare targets stage 2.
	prep = mustPrepare(t, f, f.spend(1000, 1100))
	if prep.Stage != 1 || prep.Target != 2 {
		t.Fatalf("prepare after move = %+v", prep)
	}
	mustSign(t, f, prep.Transactions)
}

func TestRotatingTimingRules(t *testing.T) {
	f, _ := newSigningFixture(t)
	f.chain.round = 1000
	// FirstValid too far ahead of the node's round.
	prep := mustPrepare(t, f, f.spend(1003, 1100))
	if _, err := f.sign(t, prep.Transactions); err == nil || !strings.Contains(err.Message, "ahead of the current round") {
		t.Fatalf("lead: %v", err)
	}
	// Too few rounds remain.
	prep = mustPrepare(t, f, f.spend(950, 1009))
	if _, err := f.sign(t, prep.Transactions); err == nil || !strings.Contains(err.Message, "remain before last valid") {
		t.Fatalf("remaining: %v", err)
	}
	// Boundaries are accepted.
	prep = mustPrepare(t, f, f.spend(1002, 1010))
	mustSign(t, f, prep.Transactions)
}

func TestRotatingSecondReleaseFromTheSameStageIsAccepted(t *testing.T) {
	f, audit := newSigningFixture(t)
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	first := mustSign(t, f, prep.Transactions)
	// The same group again, and a different spend from the same stage: both
	// sign, both rekey to the same next stage, nothing new is revealed.
	again := mustSign(t, f, prep.Transactions)
	other := mustSign(t, f, mustPrepare(t, f, f.spend(1001, 1090)).Transactions)
	for _, r := range []*signerapi.RotatingSignResponse{first, again, other} {
		if r.Stage != 0 || r.Target != 1 {
			t.Fatalf("release = %+v", r)
		}
	}
	if len(audit.releases) != 3 {
		t.Fatalf("audit releases = %d, want 3", len(audit.releases))
	}
	// Memory holds the newest release.
	rec, _ := f.svc.Rotating.Releases.Get(f.account.String())
	if rec.TxID != other.TxID {
		t.Fatalf("memory holds %s, want the newest %s", rec.TxID, other.TxID)
	}
}

func TestRotatingAuditFailureStillSigns(t *testing.T) {
	f, audit := newSigningFixture(t)
	audit.fail = errors.New("disk full")
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	resp := mustSign(t, f, prep.Transactions)
	if resp.Stage != 0 {
		t.Fatalf("resp = %+v", resp)
	}
	if rec, ok := f.svc.Rotating.Releases.Get(f.account.String()); !ok || rec.TxID != resp.TxID {
		t.Fatal("memory not updated when the audit write failed")
	}
}

func TestRotatingPrepareScansForAnUnknownStage(t *testing.T) {
	f, _ := newSigningFixture(t)
	// The account is at stage 6 and the table is empty, as after a restore.
	f.chain.authorizer = f.stageAddress(t, 6)
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	if prep.Stage != 6 || prep.Target != 7 {
		t.Fatalf("prepare = %+v", prep)
	}
	if f.table(t).Len() < 8 {
		t.Fatalf("table len = %d after scanning to stage 6 and deriving 7", f.table(t).Len())
	}
	resp := mustSign(t, f, prep.Transactions)
	if resp.Stage != 6 {
		t.Fatalf("sign = %+v", resp)
	}
}

func TestRotatingPrepareRefusesWhenTheScanIsCutOff(t *testing.T) {
	f, _ := newSigningFixture(t)
	f.chain.authorizer = types.Address{0xab, 31: 1} // never a stage
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Let a few derivations happen, then cut the request off.
		for f.table(t).Len() < 3 {
		}
		cancel()
	}()
	_, err := f.svc.PrepareRotatingWithContext(ctx, signerapi.RotatingPrepareRequest{
		Account: f.account.String(), TxnBytesHex: txnutil.EncodeWithPrefixHex(f.spend(1000, 1100)),
	}, f.session)
	if err == nil || err.Kind != ErrorRotatingStageUnproven {
		t.Fatalf("err = %v, want rotating_stage_unproven", err)
	}
	if !strings.Contains(err.Message, "stages scanned") {
		t.Fatalf("message %q does not report progress", err.Message)
	}
	if f.table(t).Len() == 0 {
		t.Fatal("progress was not kept in the table")
	}
}

func TestRotatingStatusFromReportsAndMemory(t *testing.T) {
	f, _ := newSigningFixture(t)
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	resp := mustSign(t, f, prep.Transactions)
	acct := f.account.String()

	report := func(auth types.Address, round uint64) []StageTableReport {
		return []StageTableReport{{Account: acct, Resolved: true, Authorizer: auth, Round: round}}
	}
	// In flight: a note, no warning.
	warnings, notes := f.svc.RotatingStatus(report(f.account, 1050))
	if len(warnings) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "in flight") || !strings.Contains(notes[0], resp.TxID) {
		t.Fatalf("in flight: warnings %v, notes %v", warnings, notes)
	}
	// Expired, still live: a warning naming the remedy.
	warnings, notes = f.svc.RotatingStatus(report(f.account, 1101))
	if len(warnings) != 1 || !strings.Contains(warnings[0], "rotate-only spend") || len(notes) != 0 {
		t.Fatalf("expired: warnings %v, notes %v", warnings, notes)
	}
	// Same input again: identical text, so the daemon logs it once.
	again, _ := f.svc.RotatingStatus(report(f.account, 1130))
	if len(again) != 1 || again[0] != warnings[0] {
		t.Fatalf("warning text changed between passes: %q vs %q", again[0], warnings[0])
	}
	// Landed: cleared, silent.
	warnings, notes = f.svc.RotatingStatus(report(f.stageAddress(t, 1), 1105))
	if len(warnings) != 0 || len(notes) != 0 {
		t.Fatalf("landed: warnings %v, notes %v", warnings, notes)
	}
	if _, ok := f.svc.Rotating.Releases.Get(acct); ok {
		t.Fatal("memory not cleared after the release landed")
	}
	// Unresolved account: a note with the count, never "foreign".
	_, notes = f.svc.RotatingStatus([]StageTableReport{{Account: acct, Scanned: 42}})
	if len(notes) != 1 || !strings.Contains(notes[0], "not yet found, 42 stages scanned") || strings.Contains(notes[0], "foreign") {
		t.Fatalf("unresolved note = %v", notes)
	}
}

func TestRebuildReleaseMemoryDerivesVerifiedAddresses(t *testing.T) {
	f, _ := newSigningFixture(t)
	n, err := f.svc.RebuildReleaseMemory(context.Background(), f.session, []AuditedRelease{
		{Account: f.account.String(), Stage: 3, TxID: "TX", LastValid: 500},
		{Account: types.Address{5}.String(), Stage: 1, TxID: "GONE", LastValid: 9},
	}, StageFillOptions{})
	if err != nil || n != 1 {
		t.Fatalf("rebuilt %d, err %v", n, err)
	}
	rec, ok := f.svc.Rotating.Releases.Get(f.account.String())
	if !ok || rec.Stage != 3 || rec.StageAddr != f.stageAddress(t, 3) || rec.NextAddr != f.stageAddress(t, 4) || rec.TxID != "TX" {
		t.Fatalf("rebuilt record = %+v", rec)
	}
	if _, ok := f.svc.Rotating.Releases.Get(types.Address{5}.String()); ok {
		t.Fatal("a release for a key the signer does not hold was rebuilt")
	}
}

func TestRotatingApprovalDescriptionNamesTheRotation(t *testing.T) {
	item := &rotatingPlanItem{Stage: 4, Target: 5, TargetAddress: types.Address{1}}
	desc := item.describe()
	if !strings.Contains(desc, "stage 4 signs") || !strings.Contains(desc, "stage 5") || !strings.Contains(desc, "held by this signer") {
		t.Fatalf("description = %q", desc)
	}
}
