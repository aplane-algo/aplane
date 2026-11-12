// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Developers

package apshellcli

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
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

	cancelled, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: true,
		Transactions:     rawIntents(approvalTestPayment(1, 2, 1)),
	})
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

	cancelled, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: true,
		Transactions:     rawIntents(approvalTestPayment(1, 2, 1)),
	})
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

	cancelled, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: true,
		Transactions:     rawIntents(approvalTestPayment(1, 2, 1)),
	})
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
	txn.RekeyTo = reviewTestAddress(3)

	if _, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: true,
		Transactions:     rawIntents(txn),
	}); err != nil {
		t.Fatalf("reviewPluginTransactions() error = %v", err)
	}
	rendered := out.String()
	for _, want := range []string{
		wantDraftTitle,
		"1 transaction(s):",
		"  [1] apsigner      pay",
		"Payment: 2.500000 ALGO",
		"To:   " + reviewTestAddress(2).String(),
		"!! RekeyTo = " + reviewTestAddress(3).String(),
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
	cancelled, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: false,
		Transactions:     rawIntents(approvalTestPayment(1, 2, 1)),
	})
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
	cancelled, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: true,
		Transactions:     rawIntents(txns...),
	})
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
			_, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
				RequiresApproval: true,
				Transactions:     []jsonrpc.TransactionIntent{intent},
			})
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
	if _, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		GroupMode:     jsonrpc.GroupModePresignPlan,
		Transactions:  rawIntents(plugin, managed),
		PluginSigners: signers,
	}); err != nil {
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
	if _, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		GroupMode:     jsonrpc.GroupModePresignPlan,
		Transactions:  rawIntents(ungroupedPlugin, ungroupedManaged),
		PluginSigners: signers,
	}); err != nil {
		t.Fatalf("reviewPluginTransactions(ungrouped) error = %v", err)
	}
	if strings.Contains(out.String(), wantDiscardedNotice) {
		t.Errorf("review of an ungrouped draft says a group ID was discarded:\n%s", out.String())
	}

	trailing := append(msgpack.Encode(managed), msgpack.Encode(managed)...)
	out.Reset()
	_, err = reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		GroupMode: jsonrpc.GroupModePresignPlan,
		Transactions: append(rawIntents(plugin), jsonrpc.TransactionIntent{
			Type: jsonrpc.TransactionIntentRaw, Encoded: base64.StdEncoding.EncodeToString(trailing),
		}),
		PluginSigners: signers,
	})
	if err == nil || !strings.HasPrefix(err.Error(), "presign-plan: transaction 2: ") {
		t.Fatalf("reviewPluginTransactions(non-canonical draft) error = %v, want transaction 2 refused", err)
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
			_, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
				GroupMode:        mode,
				RequiresApproval: true,
				Transactions:     rawIntents(approvalTestPayment(1, 2, 1)),
			})
			if want := `unsupported plugin groupMode "` + mode + `"`; err == nil || err.Error() != want {
				t.Fatalf("reviewPluginTransactions() error = %v, want %q", err, want)
			}
			if out.Len() != 0 {
				t.Fatalf("output before the refusal: %q", out.String())
			}
		})
	}
}

// A rekey keeps control only when its target is an address whose own key the
// signer holds. An account the client signs for through its auth address, or
// a generic LogicSig with no key, is signable but not held: a rekey to it
// warns of losing control, as the signer's prompt does.
func TestReviewSaysControlIsKeptOnlyForAHeldKey(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	held, rekeyedAlias, genericLsig := reviewTestAddress(20), reviewTestAddress(21), reviewTestAddress(22)
	eng.SignerCache.Keys[held.String()] = "ed25519"
	eng.SignerCache.Keys[genericLsig.String()] = "aplane.htlc.v1"
	eng.SignerCache.SetGenericLsig(genericLsig.String(), true)
	eng.AliasCache.Aliases = map[string]string{"rekeyed": rekeyedAlias.String()}
	eng.AuthCache.AuthAddresses = map[string]string{rekeyedAlias.String(): held.String()}

	// The client can sign for all three, so the signable set would call each
	// of them held.
	signable := map[string]bool{}
	for _, address := range eng.GetSignableAddresses() {
		signable[address] = true
	}
	for _, address := range []types.Address{held, rekeyedAlias, genericLsig} {
		if !signable[address.String()] {
			t.Fatalf("fixture: %s is not signable, so the test shows nothing", address)
		}
	}

	for name, tc := range map[string]struct {
		target types.Address
		kept   bool
	}{
		"held key":                      {target: held, kept: true},
		"account rekeyed to a held key": {target: rekeyedAlias},
		"generic LogicSig with no key":  {target: genericLsig},
	} {
		t.Run(name, func(t *testing.T) {
			txn := approvalTestPayment(1, 2, 1)
			txn.RekeyTo = tc.target
			for mode, result := range map[string]*jsonrpc.ExecuteResult{
				"default": {Transactions: rawIntents(txn)},
				"presign-plan": {
					GroupMode:     jsonrpc.GroupModePresignPlan,
					Transactions:  rawIntents(approvalTestPayment(7, 2, 1), txn),
					PluginSigners: []jsonrpc.PluginSigner{{Address: reviewTestAddress(7).String(), Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "ref"}},
				},
			} {
				var out bytes.Buffer
				state := &REPLState{Out: &out, AutoConfirm: true, App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir())}
				if _, err := reviewPluginTransactions(state, result); err != nil {
					t.Fatalf("%s: reviewPluginTransactions() error = %v", mode, err)
				}
				rendered := out.String()
				keeps := strings.Contains(rendered, "This signer holds the aplane key for the new address")
				loses := strings.Contains(rendered, "YOU WILL LOSE CONTROL")
				if keeps != tc.kept || loses == tc.kept {
					t.Errorf("%s: kept = %v, lost = %v; want kept = %v:\n%s", mode, keeps, loses, tc.kept, rendered)
				}
			}
			// The pregrouped-signed review renders through the same lines.
			lines := strings.Join(pluginReviewLines(txn, (&REPLState{App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir())}).heldAddresses()), "\n")
			if strings.Contains(lines, "This signer holds the aplane key for the new address") != tc.kept {
				t.Errorf("pregrouped-signed lines: kept != %v:\n%s", tc.kept, lines)
			}
		})
	}
}
