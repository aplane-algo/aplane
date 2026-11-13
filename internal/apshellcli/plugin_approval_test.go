// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Developers

package apshellcli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/txnreview"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// The review texts are pinned as written, so a change to them is deliberate.
const wantDraftTitle = "DRAFT: plugin-built transaction(s); apsigner sets the final fees and group ID, and its policy and approval apply to the final group"

const wantDiscardedNotice = "The plugin set a group ID; it is discarded, and apsigner computes the group ID over the final group."

// approvalTestPayment is a payment of amount from one test address to another.
func approvalTestPayment(from, to byte, amount uint64) types.Transaction {
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: reviewTestAddress(from), Fee: 1000, FirstValid: 1, LastValid: 10,
		},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: reviewTestAddress(to), Amount: types.MicroAlgos(amount)},
	}
}

// rawIntents encodes txns as a plugin's default-mode raw intents.
func rawIntents(txns ...types.Transaction) []jsonrpc.TransactionIntent {
	intents := make([]jsonrpc.TransactionIntent, len(txns))
	for i, txn := range txns {
		intents[i] = jsonrpc.TransactionIntent{Type: jsonrpc.TransactionIntentRaw, Encoded: base64.StdEncoding.EncodeToString(msgpack.Encode(txn))}
	}
	return intents
}

func TestReviewPluginTransactionsCancelsOnNegativeResponse(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{
		Out:         &out,
		AutoConfirm: false,
		LineReader: func() (string, error) {
			return "n", nil
		},
	}

	_, cancelled, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: true,
		Transactions:     rawIntents(approvalTestPayment(1, 2, 1)),
	}, nil)
	if err != nil {
		t.Fatalf("reviewPluginTransactions() error = %v", err)
	}
	if !cancelled {
		t.Fatal("reviewPluginTransactions() should cancel on negative response")
	}
	if bytes.Contains(out.Bytes(), []byte("Proceed with signing and submission?")) {
		t.Fatalf("output = %q, approval prompt should be handled by readline prompt, not printed output", out.String())
	}
}

func TestReviewPluginTransactionsSkipsPromptWhenAutoConfirm(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{
		Out:         &out,
		AutoConfirm: true,
	}

	_, cancelled, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: true,
		Transactions:     rawIntents(approvalTestPayment(1, 2, 1)),
	}, nil)
	if err != nil {
		t.Fatalf("reviewPluginTransactions() error = %v", err)
	}
	if cancelled {
		t.Fatal("reviewPluginTransactions() should not cancel with AutoConfirm")
	}
}

func TestReviewPluginTransactionsClearsReadlinePromptBeforeApproval(t *testing.T) {
	var out bytes.Buffer
	var prompts []string
	state := &REPLState{
		Out:         &out,
		AutoConfirm: false,
		SetPrompt: func(p string) {
			prompts = append(prompts, p)
		},
		LineReader: func() (string, error) {
			return "y", nil
		},
	}

	_, cancelled, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: true,
		Transactions:     rawIntents(approvalTestPayment(1, 2, 1)),
	}, nil)
	if err != nil {
		t.Fatalf("reviewPluginTransactions() error = %v", err)
	}
	if cancelled {
		t.Fatal("reviewPluginTransactions() should not cancel on affirmative response")
	}
	if len(prompts) < 2 {
		t.Fatalf("prompts = %#v, want temporary prompt and restore", prompts)
	}
	if prompts[0] != "Proceed with signing and submission? [y/N]: " {
		t.Fatalf("first prompt = %q, want approval prompt", prompts[0])
	}
	if prompts[len(prompts)-1] != "" {
		t.Fatalf("last prompt = %q, want test fixture restore to empty prompt", prompts[len(prompts)-1])
	}
}

// The default mode shows the decoded draft, with the findings the signer
// would warn about, instead of only the intents' count and kind.
func TestReviewPluginTransactionsRendersTheDecodedDraft(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{Out: &out, AutoConfirm: true}
	txn := approvalTestPayment(1, 2, 2_500_000)
	txn.CloseRemainderTo = reviewTestAddress(3)

	if _, _, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: true,
		Transactions:     rawIntents(txn),
	}, nil); err != nil {
		t.Fatalf("reviewPluginTransactions() error = %v", err)
	}
	rendered := out.String()
	for _, want := range []string{
		wantDraftTitle,
		"1 transaction(s):",
		"  [1] apsigner      pay",
		"Payment: 2.500000 ALGO",
		"To:   " + reviewTestAddress(2).String(),
		"!! CloseRemainderTo = " + reviewTestAddress(3).String(),
		"Fees paid by APlane-managed accounts: 0.001000 ALGO",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("review is missing %q:\n%s", want, rendered)
		}
	}
	for _, unwanted := range []string{"raw transaction", "Group ID:", wantDiscardedNotice} {
		if strings.Contains(rendered, unwanted) {
			t.Errorf("review shows %q:\n%s", unwanted, rendered)
		}
	}
}

// The decoded draft is information, not a gate: whether the client prompt is
// asked is still the plugin's requiresApproval and AutoConfirm.
func TestReviewPluginTransactionsRendersWithoutPromptingWhenApprovalNotRequested(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{
		Out:         &out,
		AutoConfirm: false,
		LineReader: func() (string, error) {
			t.Fatal("the client prompt was asked although the plugin did not request approval")
			return "", nil
		},
	}
	_, cancelled, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: false,
		Transactions:     rawIntents(approvalTestPayment(1, 2, 1)),
	}, nil)
	if err != nil || cancelled {
		t.Fatalf("reviewPluginTransactions() = %v, %v; want proceed", cancelled, err)
	}
	if !strings.Contains(out.String(), wantDraftTitle) {
		t.Fatalf("the draft was not shown:\n%s", out.String())
	}
}

// An SDK composer (algosdk's AtomicTransactionComposer, which the reti example
// plugin uses) assigns a group ID to a multi-transaction group. The default
// mode accepts the group, says the ID is discarded, and does not show it as
// the group's.
func TestReviewPluginTransactionsNotesADiscardedGroupID(t *testing.T) {
	txns := []types.Transaction{approvalTestPayment(1, 2, 1), approvalTestPayment(1, 3, 2)}
	groupID, err := crypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	for i := range txns {
		txns[i].Group = groupID
	}
	var out bytes.Buffer
	state := &REPLState{Out: &out, AutoConfirm: true}
	_, cancelled, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: true,
		Transactions:     rawIntents(txns...),
	}, nil)
	if err != nil || cancelled {
		t.Fatalf("reviewPluginTransactions() = %v, %v; want the grouped pair accepted", cancelled, err)
	}
	rendered := out.String()
	if !strings.Contains(rendered, wantDiscardedNotice) {
		t.Fatalf("review does not say the plugin's group ID is discarded:\n%s", rendered)
	}
	for _, unwanted := range []string{"Group ID:", "Group: ", base64.StdEncoding.EncodeToString(groupID[:])} {
		if strings.Contains(rendered, unwanted) {
			t.Errorf("review shows the discarded group ID (%q):\n%s", unwanted, rendered)
		}
	}
}

// A malformed intent is refused before anything is shown or asked.
func TestReviewPluginTransactionsRefusesAMalformedIntentBeforePrinting(t *testing.T) {
	canonicalBytes := msgpack.Encode(approvalTestPayment(1, 2, 1))
	trailing := append(append([]byte{}, canonicalBytes...), msgpack.Encode(approvalTestPayment(1, 2, 5_000_000))...)
	for name, intent := range map[string]jsonrpc.TransactionIntent{
		"second transaction appended": {Type: jsonrpc.TransactionIntentRaw, Encoded: base64.StdEncoding.EncodeToString(trailing)},
		"no encoded transaction":      {Type: jsonrpc.TransactionIntentRaw},
		"kind with control bytes":     {Type: "raw\x1b[2J", Encoded: base64.StdEncoding.EncodeToString(canonicalBytes)},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			state := &REPLState{
				Out: &out,
				LineReader: func() (string, error) {
					t.Fatal("prompted for a malformed intent")
					return "", nil
				},
			}
			_, _, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
				RequiresApproval: true,
				Transactions:     []jsonrpc.TransactionIntent{intent},
			}, nil)
			if err == nil {
				t.Fatal("reviewPluginTransactions() accepted a malformed intent")
			}
			if strings.ContainsRune(err.Error(), '\x1b') {
				t.Fatalf("error carries raw control bytes: %q", err.Error())
			}
			if out.Len() != 0 {
				t.Fatalf("output before the refusal: %q", out.String())
			}
		})
	}
}

// The presign-plan review decodes the draft as the /plan request is built: a
// non-canonical slot is refused before anything is shown, and the draft's own
// group ID, which /plan replaces, is not shown as the group's.
func TestReviewPresignPlanShowsTheDraftThatIsPlanned(t *testing.T) {
	plugin := approvalTestPayment(7, 2, 1)
	managed := approvalTestPayment(1, 7, 2)
	groupID, err := crypto.ComputeGroupID([]types.Transaction{plugin, managed})
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	plugin.Group, managed.Group = groupID, groupID
	signers := []jsonrpc.PluginSigner{{Address: reviewTestAddress(7).String(), Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "ref"}}

	var out bytes.Buffer
	state := &REPLState{Out: &out, AutoConfirm: true}
	if _, _, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		GroupMode:     jsonrpc.GroupModePresignPlan,
		Transactions:  rawIntents(plugin, managed),
		PluginSigners: signers,
	}, nil); err != nil {
		t.Fatalf("reviewPluginTransactions() error = %v", err)
	}
	rendered := out.String()
	for _, want := range []string{"  [1] plugin-signed pay", "  [2] apsigner      pay"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("review is missing %q:\n%s", want, rendered)
		}
	}
	for _, unwanted := range []string{"Group ID:", "Group: "} {
		if strings.Contains(rendered, unwanted) {
			t.Errorf("review shows the draft's group ID (%q):\n%s", unwanted, rendered)
		}
	}
	if !strings.Contains(rendered, wantDiscardedNotice) {
		t.Errorf("review does not say the plugin's group ID is discarded:\n%s", rendered)
	}

	// A draft with no group ID gets no notice.
	ungroupedPlugin, ungroupedManaged := plugin, managed
	ungroupedPlugin.Group, ungroupedManaged.Group = types.Digest{}, types.Digest{}
	out.Reset()
	if _, _, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		GroupMode:     jsonrpc.GroupModePresignPlan,
		Transactions:  rawIntents(ungroupedPlugin, ungroupedManaged),
		PluginSigners: signers,
	}, nil); err != nil {
		t.Fatalf("reviewPluginTransactions(ungrouped, nil) error = %v", err)
	}
	if strings.Contains(out.String(), wantDiscardedNotice) {
		t.Errorf("review of an ungrouped draft says a group ID was discarded:\n%s", out.String())
	}

	trailing := append(msgpack.Encode(managed), msgpack.Encode(managed)...)
	out.Reset()
	_, _, err = reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		GroupMode: jsonrpc.GroupModePresignPlan,
		Transactions: append(rawIntents(plugin), jsonrpc.TransactionIntent{
			Type: jsonrpc.TransactionIntentRaw, Encoded: base64.StdEncoding.EncodeToString(trailing),
		}),
		PluginSigners: signers,
	}, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "presign-plan: transaction 2: ") {
		t.Fatalf("reviewPluginTransactions(non-canonical draft, nil) error = %v, want transaction 2 refused", err)
	}
	if out.Len() != 0 {
		t.Fatalf("output before the refusal: %q", out.String())
	}
}

// The review dispatches on the group mode as submission does: a mode it does
// not know is refused with submission's error, before anything is shown,
// instead of being reviewed as the default mode.
func TestReviewPluginTransactionsRefusesAnUnknownGroupMode(t *testing.T) {
	for _, mode := range []string{"presign_plan", "Pregrouped-Signed", "default"} {
		t.Run(mode, func(t *testing.T) {
			var out bytes.Buffer
			state := &REPLState{
				Out: &out,
				LineReader: func() (string, error) {
					t.Fatal("prompted for an unknown group mode")
					return "", nil
				},
			}
			_, _, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
				GroupMode:        mode,
				RequiresApproval: true,
				Transactions:     rawIntents(approvalTestPayment(1, 2, 1)),
			}, nil)
			if want := `unsupported plugin groupMode "` + mode + `"`; err == nil || err.Error() != want {
				t.Fatalf("reviewPluginTransactions() error = %v, want %q", err, want)
			}
			if out.Len() != 0 {
				t.Fatalf("output before the refusal: %q", out.String())
			}
		})
	}
}

// rekeyReviewFixture is an engine connected to a test signer whose /keys lists
// an ed25519 aplane key that is a valid rekey target, a rotating account and
// an HTLC generic LogicSig that are not, and a generic LogicSig that is; plus
// an account the client signs for only through its auth address, and an
// address the signer lists nothing for. The review's check fetches the list;
// keyFetches counts the fetches.
type rekeyReviewFixture struct {
	eng                                             *engine.Engine
	native, rotating, htlc, vault, rekeyed, foreign types.Address
	keyFetches                                      *atomic.Int32
}

func newRekeyReviewFixture(t *testing.T) rekeyReviewFixture {
	t.Helper()
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	f := rekeyReviewFixture{
		eng:    eng,
		native: reviewTestAddress(20), rotating: reviewTestAddress(21), htlc: reviewTestAddress(22),
		vault: reviewTestAddress(23), rekeyed: reviewTestAddress(24), foreign: reviewTestAddress(25),
		keyFetches: new(atomic.Int32),
	}
	keys := []signerapi.KeyInfo{
		{Address: f.native.String(), KeyType: "ed25519", ValidRekeyTarget: true},
		{Address: f.rotating.String(), KeyType: "aplane.rotating-triple-wotsc.v1", SigningFlow: signerapi.SigningFlowRotating1},
		{Address: f.htlc.String(), KeyType: "aplane.htlc.v1", IsGenericLsig: true},
		{Address: f.vault.String(), KeyType: "example.vault.v1", IsGenericLsig: true, ValidRekeyTarget: true},
	}
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/keys" {
			t.Errorf("unexpected signer request %s %s", r.Method, r.URL.Path)
			http.Error(w, "test signer", http.StatusServiceUnavailable)
			return
		}
		f.keyFetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: len(keys), Keys: keys})
	}))
	t.Cleanup(signer.Close)
	eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
	eng.AliasCache.Aliases = map[string]string{"rekeyed": f.rekeyed.String()}
	eng.AuthCache.AuthAddresses = map[string]string{f.rekeyed.String(): f.native.String()}
	return f
}

// rekeyReviewCase is a rekey and what apshell says of it: the lines of its
// RekeyTo finding as the shared renderer gives them, and, when apshell refuses
// the group, the refusal, after the position.
type rekeyReviewCase struct {
	name    string
	sender  types.Address
	target  types.Address
	lines   []string
	refusal string
}

func (f rekeyReviewFixture) cases() []rekeyReviewCase {
	other := reviewTestAddress(1)
	refused := func(target types.Address, keyType string) string {
		return "cannot rekey to " + target.String() + ": this signer holds its aplane key (" + keyType + "), which is not a valid rekey target"
	}
	return []rekeyReviewCase{{
		name: "held aplane key that is a valid rekey target", sender: other, target: f.native,
		lines: []string{txnreview.RekeyTransfersText, txnreview.RekeyHeldText},
	}, {
		name: "held rotating account", sender: other, target: f.rotating,
		lines: []string{txnreview.RekeyTransfersText,
			txnreview.RekeyHeldNotValidText(txnreview.InvalidRekeyTarget{KeyType: "aplane.rotating-triple-wotsc.v1"}, false)},
		refusal: refused(f.rotating, "aplane.rotating-triple-wotsc.v1"),
	}, {
		name: "held generic LogicSig that is not a valid rekey target", sender: other, target: f.htlc,
		lines: []string{txnreview.RekeyTransfersText,
			txnreview.RekeyHeldNotValidText(txnreview.InvalidRekeyTarget{KeyType: "aplane.htlc.v1", GenericLogicSig: true}, false),
			txnreview.RekeyGenericLogicSigText},
		refusal: refused(f.htlc, "aplane.htlc.v1"),
	}, {
		name: "held generic LogicSig that is a valid rekey target", sender: other, target: f.vault,
		lines: []string{txnreview.RekeyTransfersText, txnreview.RekeyHeldText},
	}, {
		name: "account signable only through its auth address", sender: other, target: f.rekeyed,
		lines: []string{txnreview.RekeyTransfersText, txnreview.RekeyLoseControlText},
	}, {
		name: "address the signer lists nothing for", sender: other, target: f.foreign,
		lines: []string{txnreview.RekeyTransfersText, txnreview.RekeyLoseControlText},
	}, {
		name: "own address, held and valid", sender: f.native, target: f.native,
		lines: []string{txnreview.RekeyToOwnAddressText, txnreview.RekeyOwnAddressHeldText},
	}, {
		name: "own address, held and not valid", sender: f.rotating, target: f.rotating,
		lines: []string{txnreview.RekeyToOwnAddressText,
			txnreview.RekeyHeldNotValidText(txnreview.InvalidRekeyTarget{KeyType: "aplane.rotating-triple-wotsc.v1"}, true)},
		refusal: refused(f.rotating, "aplane.rotating-triple-wotsc.v1"),
	}}
}

// rekeyFindingLines returns the lines of the RekeyTo finding for target in a
// rendered review, with their indentation removed.
func rekeyFindingLines(t *testing.T, rendered string, target types.Address) []string {
	t.Helper()
	all := strings.Split(rendered, "\n")
	for i, line := range all {
		if strings.TrimSpace(line) != "!! RekeyTo = "+target.String() {
			continue
		}
		var lines []string
		indent := line[:strings.Index(line, "!!")] + "   "
		for _, next := range all[i+1:] {
			if !strings.HasPrefix(next, indent) {
				break
			}
			lines = append(lines, strings.TrimSpace(next))
		}
		return lines
	}
	t.Fatalf("no RekeyTo finding for %s in:\n%s", target, rendered)
	return nil
}

// pregroupedIntents signs txns as a pregrouped-signed plugin would emit them:
// grouped, each with a signature. Nothing checks the signature before submission.
func pregroupedIntents(t *testing.T, txns ...types.Transaction) []jsonrpc.TransactionIntent {
	t.Helper()
	gid, err := crypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	intents := make([]jsonrpc.TransactionIntent, len(txns))
	for i, txn := range txns {
		txn.Group = gid
		raw := msgpack.Encode(types.SignedTxn{Sig: types.Signature{1}, Txn: txn})
		intents[i] = jsonrpc.TransactionIntent{Type: jsonrpc.TransactionIntentSigned, Encoded: base64.StdEncoding.EncodeToString(raw)}
	}
	return intents
}

// rekeyReviewResults puts txn, a rekey, into a result of each plugin mode: the
// default draft, where apsigner signs it; a presign-plan group and a
// pregrouped-signed group, where the plugin signs it. It returns the rekey's
// position in each group, counted from 1.
func rekeyReviewResults(t *testing.T, txn types.Transaction) map[string]struct {
	result   *jsonrpc.ExecuteResult
	position int
} {
	t.Helper()
	return map[string]struct {
		result   *jsonrpc.ExecuteResult
		position int
	}{
		"default": {result: &jsonrpc.ExecuteResult{RequiresApproval: true, Transactions: rawIntents(txn)}, position: 1},
		"presign-plan": {result: &jsonrpc.ExecuteResult{
			GroupMode:     jsonrpc.GroupModePresignPlan,
			Transactions:  rawIntents(approvalTestPayment(7, 2, 1), txn),
			PluginSigners: []jsonrpc.PluginSigner{{Address: txn.Sender.String(), Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "ref"}},
		}, position: 2},
		"pregrouped-signed": {result: &jsonrpc.ExecuteResult{
			GroupMode:    jsonrpc.GroupModePregroupedSigned,
			Transactions: pregroupedIntents(t, approvalTestPayment(9, 2, 1), txn),
		}, position: 2},
	}
}

// The review of a rekey reads the signer's key list, fetched for the check, in
// every mode: the held aplane keys and which of them are not valid rekey
// targets, the facts it shares with the signer's prompt. A rekey to a held
// aplane key that is a valid rekey target keeps control; one to an account
// the client signs for only through its auth address, or to an address the
// signer lists nothing for, loses it. A rekey to a held aplane key that is not
// a valid rekey target, the account's own address included, is refused in
// every mode before anything is shown or asked, with the error submission
// gives; the shared renderer still describes it as the signer's warning does.
// The review does not know an account's rekey-to list, which the signer's
// prompt does, so that case is not covered here.
func TestReviewOfARekeyTargetReadsTheSignersKeyList(t *testing.T) {
	f := newRekeyReviewFixture(t)
	// The cache is filled only so the auth-address account is signable; the
	// review's facts come from the fetched list.
	if _, err := f.eng.RefreshKeys(context.Background()); err != nil {
		t.Fatalf("RefreshKeys() error = %v", err)
	}
	keys, err := f.eng.CurrentKeys(context.Background())
	if err != nil {
		t.Fatalf("CurrentKeys() error = %v", err)
	}
	rekeyTargets := engine.RekeyTargetsFromKeys(keys)

	// The client can sign for the auth-address account, so the signable set
	// would call it held.
	signable := map[string]bool{}
	for _, address := range f.eng.GetSignableAddresses() {
		signable[address] = true
	}
	if !signable[f.rekeyed.String()] {
		t.Fatalf("fixture: %s is not signable, so the test shows nothing", f.rekeyed)
	}

	app := apshellapp.New(f.eng, config.DefaultConfig(), t.TempDir())
	for _, tc := range f.cases() {
		t.Run(tc.name, func(t *testing.T) {
			txn := approvalTestPayment(1, 2, 1)
			txn.Sender = tc.sender
			txn.RekeyTo = tc.target

			// The renderer every mode shares, with what the signer lists.
			got := rekeyFindingLines(t, "        "+strings.Join(pluginReviewLines(txn, rekeyTargets), "\n        "), tc.target)
			if !reflect.DeepEqual(got, tc.lines) {
				t.Errorf("renderer: RekeyTo lines = %q, want %q", got, tc.lines)
			}

			for mode, c := range rekeyReviewResults(t, txn) {
				f.keyFetches.Store(0)
				var out bytes.Buffer
				prompted := false
				state := &REPLState{Out: &out, App: app, LineReader: func() (string, error) {
					prompted = true
					return "n", nil
				}}
				_, _, err := reviewPluginTransactions(state, c.result, nil)
				if fetches := f.keyFetches.Load(); fetches != 1 {
					t.Errorf("%s: the review fetched the key list %d time(s), want once", mode, fetches)
				}
				if tc.refusal != "" {
					want := fmt.Sprintf("transaction %d: %s", c.position, tc.refusal)
					if err == nil || err.Error() != want {
						t.Errorf("%s: error = %v, want %q", mode, err, want)
					}
					if out.Len() != 0 || prompted {
						t.Errorf("%s: a refused group was shown (prompted = %v):\n%s", mode, prompted, out.String())
					}
					continue
				}
				if err != nil {
					t.Fatalf("%s: reviewPluginTransactions() error = %v", mode, err)
				}
				if got := rekeyFindingLines(t, out.String(), tc.target); !reflect.DeepEqual(got, tc.lines) {
					t.Errorf("%s: RekeyTo lines = %q, want %q", mode, got, tc.lines)
				}
			}
		})
	}
}

// Without a signer connection a rekey in a plugin group cannot be checked, so
// the review refuses it in every mode before anything is shown, whatever the
// cache holds.
func TestReviewRefusesARekeyWithoutTheSignersKeyList(t *testing.T) {
	f := newRekeyReviewFixture(t)
	f.eng.Connection.SignerClient = nil
	if err := f.eng.PopulateSignerCache([]signerapi.KeyInfo{{Address: f.native.String(), KeyType: "ed25519", ValidRekeyTarget: true}}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	app := apshellapp.New(f.eng, config.DefaultConfig(), t.TempDir())
	txn := approvalTestPayment(1, 2, 1)
	txn.RekeyTo = f.native
	for mode, c := range rekeyReviewResults(t, txn) {
		var out bytes.Buffer
		state := &REPLState{Out: &out, App: app, LineReader: func() (string, error) {
			t.Fatalf("%s: prompted for a group that cannot be checked", mode)
			return "", nil
		}}
		_, _, err := reviewPluginTransactions(state, c.result, nil)
		want := fmt.Sprintf("plugin group rekeys an account (transaction %d): connect to the signer so apshell can check the rekey target against its aplane keys", c.position)
		if err == nil || err.Error() != want {
			t.Errorf("%s: error = %v, want %q", mode, err, want)
		}
		if out.Len() != 0 {
			t.Errorf("%s: shown before the refusal:\n%s", mode, out.String())
		}
	}
}

// The review and the submission of a rekeying plugin group each fetch the key
// list: submission takes the group the review checked and judges its rekeys
// again before it broadcasts this pregrouped-signed group.
func TestReviewAndSubmissionOfARekeyEachFetchTheKeyList(t *testing.T) {
	f := newRekeyReviewFixture(t)
	app := apshellapp.New(f.eng, config.DefaultConfig(), t.TempDir())
	txn := approvalTestPayment(1, 2, 1)
	txn.RekeyTo = f.native
	state := &REPLState{Out: &bytes.Buffer{}, App: app, LineReader: func() (string, error) { return "y", nil }}
	group, cancelled, err := reviewPluginTransactions(state, rekeyReviewResults(t, txn)["pregrouped-signed"].result, nil)
	if err != nil || cancelled {
		t.Fatalf("reviewPluginTransactions() = %v, %v", cancelled, err)
	}
	if fetches := f.keyFetches.Load(); fetches != 1 {
		t.Fatalf("the review fetched the key list %d time(s), want once", fetches)
	}
	// No node is configured, so submission stops at the node, after its own
	// fetch; it asks the signer nothing else.
	if _, err := submitPluginTransactions(state, "plugin", group); err == nil {
		t.Fatal("submission without a node succeeded")
	}
	if fetches := f.keyFetches.Load(); fetches != 2 {
		t.Fatalf("review and submission fetched the key list %d time(s), want twice", fetches)
	}
}

// The REPL, MCP and JavaScript run a plugin result through the one loop,
// processPluginResultStructured: execPlugin calls it for the REPL and MCP, and
// PluginExecutorAdapter.ExecutePlugin for JavaScript's plugin(). It reviews
// each step with reviewPluginTransactions and submits it with
// App.SubmitPluginTransactions, so a refused group stops in the review on
// every surface, non-interactive ones included, before it is shown or
// submitted.
func TestPluginResultPathRefusesARekeyToAHeldInvalidTarget(t *testing.T) {
	f := newRekeyReviewFixture(t)
	txn := approvalTestPayment(1, 2, 1)
	txn.RekeyTo = f.htlc
	var out bytes.Buffer
	state := &REPLState{Out: &out, AutoConfirm: true, App: apshellapp.New(f.eng, config.DefaultConfig(), t.TempDir())}
	pr := &PluginResult{}
	err := processPluginResultStructured(state, pr, &jsonrpc.ExecuteResult{
		Success:       true,
		GroupMode:     jsonrpc.GroupModePresignPlan,
		Transactions:  rawIntents(approvalTestPayment(7, 2, 1), txn),
		PluginSigners: []jsonrpc.PluginSigner{{Address: txn.Sender.String(), Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "ref"}},
	}, nil, nil)
	want := "transaction 2: cannot rekey to " + f.htlc.String() + ": this signer holds its aplane key (aplane.htlc.v1), which is not a valid rekey target"
	if err == nil || err.Error() != want {
		t.Fatalf("processPluginResultStructured() error = %v, want %q", err, want)
	}
	if out.Len() != 0 || len(pr.Steps) != 0 || len(pr.humanSteps) != 0 {
		t.Fatalf("a refused group was shown or submitted: steps %v, output:\n%s", pr.Steps, out.String())
	}
}

// Under AutoConfirm a pregrouped-signed group can never be submitted, so it is
// refused for that reason first: not told to connect to a signer it could not
// use anyway, and with no key list fetched.
func TestReviewRefusesANonInteractivePregroupedGroupBeforeTheKeyList(t *testing.T) {
	f := newRekeyReviewFixture(t)
	f.eng.Connection.SignerClient = nil
	txn := approvalTestPayment(1, 2, 1)
	txn.RekeyTo = f.htlc
	var out bytes.Buffer
	state := &REPLState{Out: &out, AutoConfirm: true, App: apshellapp.New(f.eng, config.DefaultConfig(), t.TempDir())}
	_, _, err := reviewPluginTransactions(state, rekeyReviewResults(t, txn)["pregrouped-signed"].result, nil)
	if err == nil || !strings.Contains(err.Error(), "non-interactive") {
		t.Fatalf("reviewPluginTransactions() error = %v, want the non-interactive refusal", err)
	}
	if out.Len() != 0 || f.keyFetches.Load() != 0 {
		t.Fatalf("shown %q and fetched the key list %d time(s) before the refusal", out.String(), f.keyFetches.Load())
	}
}

// A presign-plan group whose LogicSig arguments reach a slot the plugin signs,
// untargeted or naming its account, is refused by the check the review starts
// with: nothing is shown and nothing is asked.
func TestReviewRefusesArgumentsForAPluginSignedSlotBeforeShowingIt(t *testing.T) {
	pluginTxn := approvalTestPayment(1, 2, 1)
	plugin := pluginTxn.Sender.String()
	for name, token := range map[string]string{"untargeted": "arg:preimage=text:x", "for the plugin's account": "arg:" + plugin + ":preimage=text:x"} {
		t.Run(name, func(t *testing.T) {
			eng, err := newIsolatedTestEngine(t, "testnet")
			if err != nil {
				t.Fatalf("NewEngine() error = %v", err)
			}
			var out bytes.Buffer
			asked := false
			state := &REPLState{
				Out: &out, App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir()),
				LineReader: func() (string, error) { asked = true; return "y", nil },
			}
			var args cmdspec.LsigArgs
			if err := cmdspec.AddLsigArg(&args, token); err != nil {
				t.Fatal(err)
			}
			_, _, err = reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
				Success:       true,
				GroupMode:     jsonrpc.GroupModePresignPlan,
				Transactions:  rawIntents(approvalTestPayment(7, 2, 1), pluginTxn),
				PluginSigners: []jsonrpc.PluginSigner{{Address: plugin, Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "ref"}},
			}, args)
			want := "transaction 2: LogicSig arguments reach " + plugin + ", which the plugin signs"
			if err == nil || !strings.HasPrefix(err.Error(), want) {
				t.Fatalf("reviewPluginTransactions() error = %v, want %q", err, want)
			}
			if out.Len() != 0 || asked {
				t.Fatalf("the refused group was shown (asked: %v):\n%s", asked, out.String())
			}
		})
	}
}
