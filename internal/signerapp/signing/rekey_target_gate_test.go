// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"maps"
	"strconv"
	"strings"
	"testing"
	"time"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/txnreview"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// rekeyTargetTestSnapshot holds an ed25519 account and a second one, both
// valid rekey targets, an HTLC account and a key with no metadata, neither a
// valid rekey target, and a rotating account.
func rekeyTargetTestSnapshot() (PlannerRuntimeSnapshot, map[string]types.Address) {
	addrs := map[string]types.Address{
		"plain": {1}, "valid": {2}, "htlc": {3}, "bare": {4}, "rotating": {5}, "foreign": {6},
	}
	snapshot := PlannerRuntimeSnapshot{
		KeyFiles: map[string]string{}, KeyTypes: map[string]string{}, KeyMetadata: map[string]PlannerKeyMetadata{},
	}
	add := func(name, keyType string, metadata *PlannerKeyMetadata) {
		address := addrs[name].String()
		snapshot.KeyFiles[address] = name + ".key"
		snapshot.KeyTypes[address] = keyType
		if metadata != nil {
			snapshot.KeyMetadata[address] = *metadata
		}
	}
	add("plain", "ed25519", &PlannerKeyMetadata{Category: keys.CategoryEd25519, ValidRekeyTarget: true})
	add("valid", "ed25519", &PlannerKeyMetadata{Category: keys.CategoryEd25519, ValidRekeyTarget: true})
	add("htlc", "aplane.htlc.v1", &PlannerKeyMetadata{Category: keys.CategoryGenericLsig})
	add("bare", "ed25519", nil)
	add("rotating", rotatingkey.RotatingTripleWotscV1, &PlannerKeyMetadata{Category: keys.CategoryRotatingLsig})
	return snapshot, addrs
}

// A rekey to an address this signer holds an aplane key for is refused when
// that key records it is not a valid rekey target, and a key with no metadata
// is not one. The account's own address is no exception: an HTLC or rotating
// account back to itself is refused, an ed25519 one passes. A foreign target
// is left to the rekeys setting, a position this signer doesn't sign is
// judged as every position is, and a rotating target held for another account
// gets this refusal at every position, the rotating invariant being a second
// line behind it.
func TestRejectRekeyToInvalidTarget(t *testing.T) {
	snapshot, a := rekeyTargetTestSnapshot()
	svc := &Service{Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot { return snapshot }}}
	invalid := invalidRekeyTargetsFromSnapshot(snapshot)
	rekey := func(from, to string) types.Transaction {
		return types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: a[from], RekeyTo: a[to]}}
	}
	for _, tc := range []struct {
		name string
		txn  types.Transaction
		want string // "" when nothing is refused
	}{
		{"held valid rekey target", rekey("plain", "valid"), ""},
		{"held HTLC account", rekey("plain", "htlc"), "transaction 1: " + rekeyTargetNotValid(a["htlc"].String(), "aplane.htlc.v1").Message},
		{"held key with no metadata", rekey("plain", "bare"), "transaction 1: " + rekeyTargetNotValid(a["bare"].String(), "ed25519").Message},
		{"foreign target", rekey("plain", "foreign"), ""},
		{"an HTLC account back to its own address", rekey("htlc", "htlc"), "transaction 1: " + rekeyTargetNotValid(a["htlc"].String(), "aplane.htlc.v1").Message},
		{"a rotating account back to its own address", rekey("rotating", "rotating"), "transaction 1: " + rekeyTargetNotValid(a["rotating"].String(), rotatingkey.RotatingTripleWotscV1).Message},
		{"an ed25519 account back to its own address", rekey("plain", "plain"), ""},
		{"no rekey", types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: a["plain"]}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.rejectSignerInvariants([]types.Transaction{tc.txn}, []int{0}, invalid)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || err.HTTPStatus() != 403 || err.Code() != signerapi.ErrCodeRekeyTargetNotValid || err.Message != tc.want {
				t.Fatalf("err = %v, want 403 %s %q", err, signerapi.ErrCodeRekeyTargetNotValid, tc.want)
			}
			if strings.Contains(err.Message, "foreign") {
				t.Fatalf("message %q calls a held target foreign", err.Message)
			}
		})
	}
	// A rekey of another account to a held rotating account at a signed
	// position gets the same code as at any other: this invariant runs before
	// the rotating one, and every rotating key records false.
	err := svc.rejectSignerInvariants([]types.Transaction{rekey("plain", "rotating")}, []int{0}, invalid)
	if want := "transaction 1: " + rekeyTargetNotValid(a["rotating"].String(), rotatingkey.RotatingTripleWotscV1).Message; err == nil ||
		err.Code() != signerapi.ErrCodeRekeyTargetNotValid || err.Message != want || err.RefusedPosition == nil || *err.RefusedPosition != 0 {
		t.Fatalf("rekey to a rotating account: err = %+v, want %s %q at position 0", err, signerapi.ErrCodeRekeyTargetNotValid, want)
	}
	// For a rotating target the refusal keeps the rotating explanation.
	if want := "transaction 1: rekey_target_not_valid: cannot rekey to " + a["rotating"].String() +
		": this signer holds its aplane key (" + rotatingkey.RotatingTripleWotscV1 + "), which is not a valid rekey target (valid_rekey_target: false)" +
		"; it is a rotating account, and its address is a one-time stage key; " +
		"an account rekeyed to it would be stuck on that stage, and every signature would reuse that key"; err.Message != want {
		t.Fatalf("rotating target message = %q, want %q", err.Message, want)
	}
	// Any other target's message has no rotating explanation.
	if msg := rekeyTargetNotValid(a["htlc"].String(), "aplane.htlc.v1").Message; strings.Contains(msg, "rotating") {
		t.Fatalf("HTLC target message %q mentions a rotating account", msg)
	}
	// The rotating invariant is a second line: it refuses such a rekey at a
	// signed position only if the rotating key's record said it is a valid
	// rekey target.
	validRotating := map[string]txnreview.InvalidRekeyTarget{}
	for address, target := range invalid {
		if address != a["rotating"].String() {
			validRotating[address] = target
		}
	}
	err = svc.rejectSignerInvariants([]types.Transaction{rekey("plain", "rotating")}, []int{0}, validRotating)
	if want := "transaction 1: " + rotatingkey.RekeyTargetRefusal(a["rotating"].String()); err == nil ||
		err.Code() != signerapi.ErrCodeForbidden || err.Message != want || err.RefusedPosition == nil || *err.RefusedPosition != 0 {
		t.Fatalf("second line: err = %+v, want forbidden %q at position 0", err, want)
	}

	// Every position is judged, not only the ones this signer signs, and a
	// request that signs nothing is judged too. The rotating and
	// nonparticipation invariants still judge only the signed positions, so
	// at a position this signer doesn't sign a rotating target meets this
	// invariant.
	payment := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: a["plain"]}}
	nonparticipating := types.Transaction{Type: types.KeyRegistrationTx, Header: types.Header{Sender: a["foreign"]},
		KeyregTxnFields: types.KeyregTxnFields{Nonparticipation: true}}
	for _, tc := range []struct {
		name   string
		txns   []types.Transaction
		signed []int
		want   string // "" when nothing is refused
	}{
		{"an HTLC target at a position not signed", []types.Transaction{payment, rekey("foreign", "htlc")}, []int{0},
			"transaction 2: " + rekeyTargetNotValid(a["htlc"].String(), "aplane.htlc.v1").Message},
		{"a rotating target at a position not signed", []types.Transaction{payment, rekey("foreign", "rotating")}, []int{0},
			"transaction 2: " + rekeyTargetNotValid(a["rotating"].String(), rotatingkey.RotatingTripleWotscV1).Message},
		{"a rotating account back to itself at a position not signed", []types.Transaction{payment, rekey("rotating", "rotating")}, []int{0},
			"transaction 2: " + rekeyTargetNotValid(a["rotating"].String(), rotatingkey.RotatingTripleWotscV1).Message},
		{"a request that signs nothing", []types.Transaction{rekey("plain", "htlc")}, nil,
			"transaction 1: " + rekeyTargetNotValid(a["htlc"].String(), "aplane.htlc.v1").Message},
		{"a held valid target at a position not signed", []types.Transaction{payment, rekey("foreign", "valid")}, []int{0}, ""},
		{"a foreign target at a position not signed", []types.Transaction{payment, rekey("plain", "foreign")}, []int{0}, ""},
		{"a nonparticipating keyreg at a position not signed", []types.Transaction{payment, nonparticipating}, []int{0}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.rejectSignerInvariants(tc.txns, tc.signed, invalid)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || err.HTTPStatus() != 403 || err.Code() != signerapi.ErrCodeRekeyTargetNotValid || err.Message != tc.want {
				t.Fatalf("err = %v, want 403 %s %q", err, signerapi.ErrCodeRekeyTargetNotValid, tc.want)
			}
			if want := len(tc.txns) - 1; err.RefusedPosition == nil || *err.RefusedPosition != want {
				t.Fatalf("refused position = %v, want %d", err.RefusedPosition, want)
			}
		})
	}
	// A cosigner passes no set: there is nothing to refuse at any position.
	if err := svc.rejectSignerInvariants([]types.Transaction{rekey("plain", "htlc")}, []int{0}, nil); err != nil {
		t.Fatalf("refused with no invalid targets: %v", err)
	}
}

// A plan builds its invalid rekey targets only for a group that rekeys, at
// any position, and then builds all of them: what the gate and the warnings
// see for a rekeying group is unchanged.
func TestInvalidRekeyTargetsAreBuiltOnlyForARekeyingGroup(t *testing.T) {
	snapshot, a := rekeyTargetTestSnapshot()
	payment := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: a["plain"]}}
	if got := invalidRekeyTargetsForGroup(snapshot, []types.Transaction{payment, payment}); got != nil {
		t.Fatalf("a group with no rekey built %v", got)
	}
	foreignRekey := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: a["foreign"], RekeyTo: a["valid"]}}
	got := invalidRekeyTargetsForGroup(snapshot, []types.Transaction{payment, foreignRekey})
	if want := invalidRekeyTargetsFromSnapshot(snapshot); len(got) != len(want) || len(want) == 0 {
		t.Fatalf("a rekeying group built %v, want %v", got, want)
	}
	for address, target := range invalidRekeyTargetsFromSnapshot(snapshot) {
		if got[address] != target {
			t.Fatalf("%s = %+v, want %+v", address, got[address], target)
		}
	}
}

// The invariant judges the key set the request was planned with, which the
// plan carries: an HTLC key deleted, or a reload, between planning and the
// gates does not let a rekey to it through.
func TestValidTargetInvariantJudgesThePlansKeySet(t *testing.T) {
	planned, a := rekeyTargetTestSnapshot()
	svc := &Service{
		// By the time the gates run, the runtime holds no keys at all.
		Planner:                       &Planner{Snapshot: func() PlannerRuntimeSnapshot { return PlannerRuntimeSnapshot{} }},
		Approval:                      &ApprovalService{},
		GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
		IsUnlocked:                    func() bool { return true },
	}
	txn := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: a["plain"], Fee: 1_000, RekeyTo: a["htlc"]}}
	plan := &PlanResult{
		AllTxns: []types.Transaction{txn}, PassthroughIndices: map[int]bool{}, ForeignIndices: map[int]bool{},
		AuthKeyTypes:        []string{"ed25519"},
		KnownAddresses:      knownAddressesFromSnapshot(planned),
		InvalidRekeyTargets: invalidRekeyTargetsFromSnapshot(planned),
	}
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: a["plain"].String(), TxnBytesHex: "00"}}}
	_, _, err := svc.approveGroupWithPlanContext(context.Background(), req, plan)
	want := "transaction 1: " + rekeyTargetNotValid(a["htlc"].String(), "aplane.htlc.v1").Message
	if err == nil || err.Code() != signerapi.ErrCodeRekeyTargetNotValid || err.Message != want {
		t.Fatalf("err = %v, want %q from the plan's key set", err, want)
	}
}

// The invariant refuses such a group before any prompt, so the signer's own
// prompts never show this warning. The warning stays as a defence in depth:
// a group prompt reached directly still says what the rekey target at a
// position this signer does not sign is, a held aplane key that is not a
// valid rekey target, and for a generic LogicSig, that its program decides
// what can be signed.
func TestGroupWarningNamesAHeldInvalidRekeyTargetAtAForeignPosition(t *testing.T) {
	snapshot, a := rekeyTargetTestSnapshot()
	foreignRekey := types.Transaction{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: a["foreign"], Fee: 1_000, RekeyTo: a["htlc"]},
	}
	payment := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: a["plain"], Fee: 1_000},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: a["valid"], Amount: 1},
	}
	txns := []types.Transaction{payment, foreignRekey}
	for _, class := range []string{"foreign", "passthrough"} {
		t.Run(class, func(t *testing.T) {
			plan := &PlanResult{AllTxns: txns, ForeignIndices: map[int]bool{}, PassthroughIndices: map[int]bool{}, BoundedItems: make([]*boundedPlanItem, 2)}
			if class == "foreign" {
				plan.ForeignIndices[1], plan.HasForeign = true, true
			} else {
				plan.PassthroughIndices[1], plan.HasPassthrough = true, true
			}
			// The prompt reads the plan's key set; the runtime's has changed
			// since planning and holds nothing.
			plan.KnownAddresses = knownAddressesFromSnapshot(snapshot)
			plan.InvalidRekeyTargets = invalidRekeyTargetsFromSnapshot(snapshot)
			var got []signerapproval.Violation
			svc := &ApprovalService{
				HasClient:                     func() bool { return true },
				GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
				KnownAddresses:                func() map[string]bool { return nil },
				RequestSigningApproval: func(_, _, _, _ string, _, _ uint64, violations []signerapproval.Violation, _ time.Duration) (bool, error) {
					got = violations
					return true, nil
				},
			}
			req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: a["plain"].String()}, {TxnBytesHex: "00"}}}
			if err := svc.RequestGroupApprovalWithContext(context.Background(), req, plan, "group", 0, 0, txns); err != nil {
				t.Fatal(err)
			}
			want := txnreview.RekeyTransfersText + "\n   " + txnreview.RekeyHeldNotValidText(txnreview.InvalidRekeyTarget{KeyType: "aplane.htlc.v1", GenericLogicSig: true}, false) +
				"\n   " + txnreview.RekeyGenericLogicSigText
			for _, v := range got {
				if v.Field == "Tx 2/2: RekeyTo" {
					if v.Message != want {
						t.Fatalf("rekey warning = %q, want %q", v.Message, want)
					}
					return
				}
			}
			t.Fatalf("no rekey warning for the %s position: %+v", class, got)
		})
	}
}

// shippedSignerPolicyWithRekeys is the shipped default signer policy with its
// rekeys setting replaced.
func shippedSignerPolicyWithRekeys(t *testing.T, rekeys policy.SignerRekeys) *policy.Config {
	t.Helper()
	doc := strings.Replace(policytest.EmbeddedDefault(t, noderole.RoleSigner), `"rekeys": "reject_foreign_rekey"`, `"rekeys": "`+string(rekeys)+`"`, 1)
	decoded, err := policy.DecodePolicyV1([]byte(doc), policy.DefaultKey, noderole.RoleSigner)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := decoded.Compile(policy.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rekeys != rekeys {
		t.Fatalf("compiled rekeys = %q, want %q", cfg.Rekeys, rekeys)
	}
	return cfg
}

// rekeyGateHarness records every trace of approval a request leaves: the
// operator prompts, and what the approval adapter prints, which with User
// Auto-Approve on is its only trace. A request the gates pass stops at
// BeforeExecute, so nothing is signed.
type rekeyGateHarness struct {
	prompts  int
	executes int
	approval strings.Builder
}

// stoppedAfterApproval is what a request the gates passed returns.
const stoppedAfterApproval = "test: stopped after approval"

// configure gives svc an approval adapter, the shipped default policy with
// rekeys replaced, and a BeforeExecute that stops the request.
func (h *rekeyGateHarness) configure(t *testing.T, svc *Service, rekeys policy.SignerRekeys, auto bool) {
	t.Helper()
	svc.Approval = &ApprovalService{
		UserAutoApprove:               &auto,
		Console:                       &stringConsole{&h.approval},
		GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
		HasClient:                     func() bool { return true },
		RequestSigningApprovalContext: func(context.Context, string, string, string, string, uint64, uint64, []signerapproval.Violation, time.Duration) (bool, error) {
			h.prompts++
			return true, nil
		},
	}
	svc.Executor = &Executor{}
	svc.GenerateTxnDescriptionFromTxn = func(types.Transaction) string { return "txn" }
	svc.IsUnlocked = func() bool { return true }
	svc.PolicyFor = fixedPolicy(shippedSignerPolicyWithRekeys(t, rekeys))
	svc.BeforeExecute = func() (func(), *ServiceError) {
		h.executes++
		return nil, unavailable(stoppedAfterApproval)
	}
}

// check holds err to the refusal wantRefused names, before any approval, or,
// when it names none, to a request that went on through review and approval.
func (h *rekeyGateHarness) check(t *testing.T, err *ServiceError, wantRefused string, auto bool) {
	t.Helper()
	if wantRefused != "" {
		if err == nil || err.HTTPStatus() != 403 || err.Code() != signerapi.ErrCodeRekeyTargetNotValid || err.Message != wantRefused {
			t.Fatalf("err = %v, want 403 %s %q", err, signerapi.ErrCodeRekeyTargetNotValid, wantRefused)
		}
		if h.prompts != 0 || h.approval.Len() != 0 || h.executes != 0 {
			t.Fatalf("prompts = %d, approval printed %q, executes = %d; want a refusal before any approval", h.prompts, h.approval.String(), h.executes)
		}
		return
	}
	if err == nil || err.Message != stoppedAfterApproval || h.executes != 1 {
		t.Fatalf("err = %v, executes = %d; want the request to pass the gates and approval", err, h.executes)
	}
	if auto && (h.prompts != 0 || !strings.Contains(h.approval.String(), "[USER AUTO-APPROVE]")) {
		t.Fatalf("prompts = %d, approval printed %q; want User Auto-Approve to approve", h.prompts, h.approval.String())
	}
	if !auto && h.prompts != 1 {
		t.Fatalf("prompts = %d, want the operator asked once", h.prompts)
	}
}

// rekeyTargetCase is a rekey at a position this signer does not sign, and the
// refusal it gets ("" for none).
type rekeyTargetCase struct {
	name           string
	sender, target string
	keyType        string // the refused target's key type
}

// unsignedRekeyCases are the rekeys at a position this signer does not sign,
// over the rekey target test snapshot: held targets that are not valid rekey
// targets, which are refused, and a held valid and a foreign target, which
// are not.
var unsignedRekeyCases = []rekeyTargetCase{
	{"another account to a held rotating account", "foreign", "rotating", rotatingkey.RotatingTripleWotscV1},
	{"another account to a held generic LogicSig recording false", "foreign", "htlc", "aplane.htlc.v1"},
	{"a rotating account back to its own address", "rotating", "rotating", rotatingkey.RotatingTripleWotscV1},
	{"a generic LogicSig recording false back to its own address", "htlc", "htlc", "aplane.htlc.v1"},
	{"another account to a held valid rekey target", "foreign", "valid", ""},
	{"another account to a foreign address", "foreign", "elsewhere", ""},
}

// A /sign request in which any position rekeys an account to a held aplane
// key that is not a valid rekey target is refused, whatever the position: a
// passthrough, a foreign one, or the only position of a request that signs
// nothing. It is refused before policy and before any approval, under every
// rekeys setting, with User Auto-Approve on and off, by the real planner's
// group. A held valid target and a foreign one are not this check's, and the
// request goes on to review.
func TestValidTargetInvariantJudgesEveryPositionOfASignRequest(t *testing.T) {
	snapshot, a := rekeyTargetTestSnapshot()
	a["elsewhere"] = types.Address{8}
	for _, mode := range []string{"passthrough", "foreign", "passthrough-only"} {
		for _, tc := range unsignedRekeyCases {
			for _, rekeys := range []policy.SignerRekeys{policy.RekeysRejectAll, policy.RekeysRejectForeign, policy.RekeysAllow} {
				for _, auto := range []bool{false, true} {
					t.Run(mode+"/"+tc.name+"/"+string(rekeys)+"/auto="+map[bool]string{false: "off", true: "on"}[auto], func(t *testing.T) {
						req, position := rekeyAtPositionRequest(t, a, mode, a[tc.sender], a[tc.target])
						h := &rekeyGateHarness{}
						svc := rekeyTargetSignService(snapshot)
						h.configure(t, svc, rekeys, auto)
						_, err := svc.SignGroupWithContext(context.Background(), req, nil)
						want := ""
						if tc.keyType != "" {
							want = withTransactionIndex(position, rekeyTargetNotValid(a[tc.target].String(), tc.keyType)).Message
						}
						h.check(t, err, want, auto)
					})
				}
			}
		}
	}
}

// rekeyTargetSignService is a /sign service planning with the real planner
// over snapshot.
func rekeyTargetSignService(snapshot PlannerRuntimeSnapshot) *Service {
	return &Service{Planner: NewPlanner(stubPlannerDeps{keyTypes: snapshot.KeyTypes, keyFiles: snapshot.KeyFiles, keyMetadata: snapshot.KeyMetadata},
		PlannerOptions{GenesisHashResolver: apconfig.DefaultGenesisHashNetworkResolver()})}
}

// rekeyAtPositionRequest is a /sign request with a rekey of sender to target
// at a position of the given mode, and that position. In "passthrough" and
// "foreign" mode the first position is a payment from a's plain account,
// which this signer signs, and the rekey is the second; a passthrough group
// is pre-grouped, as passthrough requires, and a foreign one is left for the
// signer to group. In "passthrough-only" mode the rekey is the only position
// and the signer signs nothing; in "sign" mode it is the only position and
// the signer signs it, as plain.
func rekeyAtPositionRequest(t *testing.T, a map[string]types.Address, mode string, sender, target types.Address) (signerapi.GroupSignRequest, int) {
	t.Helper()
	payment := testnetPaymentTransaction(t, a["plain"].String(), a["valid"].String(), 1)
	payment.Fee = 1_000
	rekey := testnetPaymentTransaction(t, sender.String(), sender.String(), 0)
	rekey.Fee = 1_000
	rekey.RekeyTo = target
	signed := func(txn types.Transaction) signerapi.SignRequest {
		return signerapi.SignRequest{SignedTxnHex: hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn, Sig: types.Signature{7}}))}
	}
	regroup := func(txns ...types.Transaction) []types.Transaction {
		groupID, err := algocrypto.ComputeGroupID(txns)
		if err != nil {
			t.Fatal(err)
		}
		for i := range txns {
			txns[i].Group = groupID
		}
		return txns
	}
	switch mode {
	case "passthrough":
		txns := regroup(payment, rekey)
		return signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
			{AuthAddress: a["plain"].String(), TxnBytesHex: txnutil.EncodeWithPrefixHex(txns[0])}, signed(txns[1]),
		}}, 1
	case "foreign":
		return signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
			{AuthAddress: a["plain"].String(), TxnBytesHex: txnutil.EncodeWithPrefixHex(payment)},
			{TxnBytesHex: txnutil.EncodeWithPrefixHex(rekey)},
		}}, 1
	case "sign":
		return signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
			{AuthAddress: a["plain"].String(), TxnBytesHex: txnutil.EncodeWithPrefixHex(rekey)},
		}}, 0
	case "passthrough-only":
		return signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{signed(regroup(rekey)[0])}}, 0
	}
	t.Fatalf("unknown mode %q", mode)
	return signerapi.GroupSignRequest{}, 0
}

// wantPlannedRecord checks that got identifies position of group, as planned,
// the way a SIGN_APPROVED identifies a signed transaction: its sender and
// txid, and for a group the group ID and every transaction ID of the group
// in order, with dummyCount trailing dummies.
func wantPlannedRecord(t *testing.T, got SignedRecord, group []types.Transaction, position, dummyCount int) {
	t.Helper()
	txn := group[position]
	if got.TxnSender != txn.Sender.String() || got.TxID != algocrypto.GetTxID(txn) || got.Fee != uint64(txn.Fee) {
		t.Fatalf("record = %+v, want sender %s txid %s fee %d", got, txn.Sender, algocrypto.GetTxID(txn), txn.Fee)
	}
	if txn.Group == (types.Digest{}) {
		if got.GroupID != "" || got.GroupTxIDs != nil || got.DummyCount != 0 {
			t.Fatalf("record of a transaction alone names a group: %+v", got)
		}
		return
	}
	if got.GroupID != base64.StdEncoding.EncodeToString(txn.Group[:]) || len(got.GroupTxIDs) != len(group) || got.DummyCount != dummyCount {
		t.Fatalf("record group = %q %v dummies %d, want %x, %d members, %d dummies", got.GroupID, got.GroupTxIDs, got.DummyCount, txn.Group, len(group), dummyCount)
	}
	for i, member := range group {
		if got.GroupTxIDs[i] != algocrypto.GetTxID(member) {
			t.Fatalf("group_txids[%d] = %s, want %s", i, got.GroupTxIDs[i], algocrypto.GetTxID(member))
		}
	}
}

// A request refused by the valid-target invariant leaves one SIGN_REJECTED
// entry per position this signer would have signed and one for the position
// the refusal names, whatever its kind, and each identifies its transaction
// as planned, in the group the signer was asked to sign, the way a
// SIGN_APPROVED identifies a signed one, so they join by group. Every entry
// carries the reason, which names the position and the target. A
// passthrough-only request signs nothing and leaves the one entry for its
// passthrough. A refused position this signer signs gets one entry, not two.
func TestValidTargetRefusalIsAuditedAtThePositionItNames(t *testing.T) {
	snapshot, a := rekeyTargetTestSnapshot()
	type entry struct {
		position int
		auth     string // a's name for the auth address, or "" for none
	}
	for _, tc := range []struct {
		name, mode, sender, target, keyType string
		entries                             []entry
	}{
		{"a passthrough-only request", "passthrough-only", "foreign", "htlc", "aplane.htlc.v1", []entry{{0, ""}}},
		{"a mixed request refused at its foreign position", "foreign", "foreign", "rotating", rotatingkey.RotatingTripleWotscV1, []entry{{0, "plain"}, {1, ""}}},
		{"a mixed request refused at its passthrough position", "passthrough", "foreign", "htlc", "aplane.htlc.v1", []entry{{0, "plain"}, {1, ""}}},
		{"a request refused at the position it signs", "sign", "plain", "htlc", "aplane.htlc.v1", []entry{{0, "plain"}}},
	} {
		for _, auto := range []bool{false, true} {
			t.Run(tc.name+"/auto="+map[bool]string{false: "off", true: "on"}[auto], func(t *testing.T) {
				req, position := rekeyAtPositionRequest(t, a, tc.mode, a[tc.sender], a[tc.target])
				svc := rekeyTargetSignService(snapshot)
				planned, planErr := svc.Planner.PlanGroup(req)
				if planErr != nil {
					t.Fatal(planErr)
				}
				log := &testAuditLogger{}
				h := &rekeyGateHarness{}
				h.configure(t, svc, policy.RekeysRejectForeign, auto)
				svc.AuditLog = log
				_, err := svc.SignGroupWithContext(context.Background(), req, nil)
				refusal := withTransactionIndex(position, rekeyTargetNotValid(a[tc.target].String(), tc.keyType)).Message
				h.check(t, err, refusal, auto)
				reason := auditSignerInvariant + refusal
				if !strings.Contains(reason, "transaction "+strconv.Itoa(position+1)+": ") || !strings.Contains(reason, a[tc.target].String()) {
					t.Fatalf("reason %q does not name the position and the target", reason)
				}
				if len(log.rejected) != 0 || len(log.rejectedRecords) != len(tc.entries) {
					t.Fatalf("entries = %+v without a record, %+v with one; want %d with one", log.rejected, log.rejectedRecords, len(tc.entries))
				}
				for i, want := range tc.entries {
					got := log.rejectedRecords[i]
					wantAuth := ""
					if want.auth != "" {
						wantAuth = a[want.auth].String()
					}
					if got.authAddress != wantAuth || got.reason != reason {
						t.Fatalf("entry %d = %+v, want auth %q, reason %q", i, got, wantAuth, reason)
					}
					wantPlannedRecord(t, got.record, planned.AllTxns, want.position, len(planned.DummyTxns))
				}
			})
		}
	}
}

// The entry for the position a refusal names is written wherever that
// position is in the group, a trailing one after the request's positions
// included, although no dummy the signer builds can rekey today. A policy
// rejection, which names no position, writes what it always has.
func TestPositionRefusalIsAuditedWhereverThePositionIs(t *testing.T) {
	sender, other := types.Address{1}, types.Address{2}
	txns := []types.Transaction{
		{Type: types.PaymentTx, Header: types.Header{Sender: sender, Fee: 1_000}},
		{Type: types.PaymentTx, Header: types.Header{Sender: other, Fee: 1_000}},
		{Type: types.PaymentTx, Header: types.Header{Sender: sender, Fee: 0, Note: []byte("dummy")}},
	}
	groupID, err := algocrypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatal(err)
	}
	for i := range txns {
		txns[i].Group = groupID
	}
	plan := &PlanResult{AllTxns: txns, DummyTxns: txns[2:], PassthroughIndices: map[int]bool{}, ForeignIndices: map[int]bool{1: true}}
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: sender.String()}, {}}}
	log := &testAuditLogger{}
	svc := &Service{AuditLog: log}
	refusal := withTransactionIndex(2, forbidden("refused"))
	svc.logSignRejections(req, plan, txns[:2], auditSignerInvariant+refusal.Message, refusal)
	if len(log.rejected) != 0 || len(log.rejectedRecords) != 2 {
		t.Fatalf("entries = %+v / %+v, want the signed position's and the trailing position's records", log.rejected, log.rejectedRecords)
	}
	if signed := log.rejectedRecords[0]; signed.authAddress != sender.String() {
		t.Fatalf("signed position's entry = %+v", signed)
	}
	wantPlannedRecord(t, log.rejectedRecords[0].record, txns, 0, 1)
	if trailing := log.rejectedRecords[1]; trailing.authAddress != "" {
		t.Fatalf("trailing position's entry = %+v, want no auth address", trailing)
	}
	wantPlannedRecord(t, log.rejectedRecords[1].record, txns, 2, 1)

	log = &testAuditLogger{}
	svc.AuditLog = log
	svc.logSignRejections(req, plan, txns[:2], auditPolicyRejected+"test", forbidden("policy"))
	if len(log.rejectedRecords) != 0 || len(log.rejected) != 1 || log.rejected[0].authAddress != sender.String() {
		t.Fatalf("policy rejection entries = %+v / %+v, want the signed position's plain entry", log.rejected, log.rejectedRecords)
	}
}

// The cosigned flow's /sign/component judges the whole frozen group too: a
// contextual position, which this request neither signs nor submits to
// policy, that rekeys an account to a held aplane key that is not a valid
// rekey target refuses the request before approval, and nothing is signed. A
// held valid target is not this check's, and the request goes on to review.
func TestValidTargetInvariantJudgesAComponentRequestsContextualPositions(t *testing.T) {
	// The rekey target test snapshot, moved off the frozen bounded service's
	// own addresses.
	base, original := rekeyTargetTestSnapshot()
	snapshot := PlannerRuntimeSnapshot{KeyFiles: map[string]string{}, KeyTypes: map[string]string{}, KeyMetadata: map[string]PlannerKeyMetadata{}}
	a := map[string]types.Address{"elsewhere": {0x28}}
	for name, address := range original {
		moved := address
		moved[0] += 0x20
		a[name] = moved
		if file, ok := base.KeyFiles[address.String()]; ok {
			snapshot.KeyFiles[moved.String()] = file
			snapshot.KeyTypes[moved.String()] = base.KeyTypes[address.String()]
		}
		if metadata, ok := base.KeyMetadata[address.String()]; ok {
			snapshot.KeyMetadata[moved.String()] = metadata
		}
	}
	for _, tc := range unsignedRekeyCases {
		for _, rekeys := range []policy.SignerRekeys{policy.RekeysRejectAll, policy.RekeysRejectForeign, policy.RekeysAllow} {
			for _, auto := range []bool{false, true} {
				t.Run(tc.name+"/"+string(rekeys)+"/auto="+map[bool]string{false: "off", true: "on"}[auto], func(t *testing.T) {
					service, authorizer, txn := frozenBoundedTestServiceWith(t, 4_500, nil)
					bounded := service.Planner.Snapshot
					// The signer also holds the rekey target test snapshot's keys.
					service.Planner.Snapshot = func() PlannerRuntimeSnapshot {
						merged := bounded()
						merged.KeyFiles, merged.KeyTypes = maps.Clone(merged.KeyFiles), maps.Clone(merged.KeyTypes)
						merged.KeyMetadata = maps.Clone(merged.KeyMetadata)
						for address := range snapshot.KeyFiles {
							merged.KeyFiles[address] = snapshot.KeyFiles[address]
							merged.KeyTypes[address] = snapshot.KeyTypes[address]
							if metadata, ok := snapshot.KeyMetadata[address]; ok {
								merged.KeyMetadata[address] = metadata
							}
						}
						return merged
					}
					if _, clash := snapshot.KeyFiles[authorizer]; clash {
						t.Fatal("the bounded authorizer is one of the snapshot's addresses")
					}
					rekey := types.Transaction{
						Type: types.PaymentTx,
						Header: types.Header{Sender: a[tc.sender], Fee: 1_000, FirstValid: 1, LastValid: 10,
							GenesisHash: txn.GenesisHash, RekeyTo: a[tc.target]},
						PaymentTxnFields: types.PaymentTxnFields{Receiver: a[tc.sender]},
					}
					planned, planErr := service.Planner.PlanGroup(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
						{AuthAddress: authorizer, TxnBytesHex: txnutil.EncodeWithPrefixHex(txn)},
						{TxnBytesHex: txnutil.EncodeWithPrefixHex(rekey)},
					}})
					if planErr != nil {
						t.Fatal(planErr)
					}
					request := signerapi.ComponentRequest{
						Targets:             []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: authorizer}},
						ContextualPositions: []signerapi.ComponentContextPosition{{TargetIndex: 1}},
					}
					for i, plannedTxn := range planned.AllTxns {
						request.GroupBytesHex = append(request.GroupBytesHex, txnutil.EncodeWithPrefixHex(plannedTxn))
						if i > 1 {
							request.DummyPositions = append(request.DummyPositions, signerapi.ComponentDummyPosition{TargetIndex: i})
						}
					}
					h := &rekeyGateHarness{}
					h.configure(t, service, rekeys, auto)
					log := &testAuditLogger{}
					service.AuditLog = log
					_, err := service.SignComponentsWithContext(context.Background(), request, &keystore.KeySession{})
					want := ""
					if tc.keyType != "" {
						want = "transaction 2: " + rekeyTargetNotValid(a[tc.target].String(), tc.keyType).Message
					}
					h.check(t, err, want, auto)
					if want == "" {
						if len(log.rejectedRecords) != 0 {
							t.Fatalf("a request not refused recorded %+v", log.rejectedRecords)
						}
						return
					}
					// The target and the contextual position are each recorded
					// as presented in the frozen group, whose dummies the
					// client signs.
					reason := auditSignerInvariant + want
					if len(log.rejected) != 0 || len(log.rejectedRecords) != 2 {
						t.Fatalf("entries = %+v / %+v, want the target's and position 1's records", log.rejected, log.rejectedRecords)
					}
					for i, auth := range []string{authorizer, ""} {
						if got := log.rejectedRecords[i]; got.authAddress != auth || got.reason != reason {
							t.Fatalf("entry %d = %+v, want auth %q, reason %q", i, got, auth, reason)
						}
						wantPlannedRecord(t, log.rejectedRecords[i].record, planned.AllTxns, i, 0)
					}
				})
			}
		}
	}
}
