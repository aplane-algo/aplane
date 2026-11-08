// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytext

import (
	"bytes"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/protocol"
	sdkconfig "github.com/algorand/go-algorand-sdk/v2/protocol/config"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/santhosh-tekuri/jsonschema/v6"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"
	"github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

const signerPresetKey = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"

var presetHeld = types.Address{0x44} // another account this signer holds

// signerPresetFeeCap is the fee cap every signer preset carries.
const signerPresetFeeCap = 80_000

func signerPresetConfig(t *testing.T, name string) *policy.Config {
	t.Helper()
	text, err := PresetTemplate(noderole.RoleSigner, name, signerPresetKey)
	if err != nil {
		t.Fatal(err)
	}
	stripped, err := StripComments([]byte(fillPresetPlaceholders(text)))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := policy.DecodePolicyV1(stripped, signerPresetKey, noderole.RoleSigner)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	cfg, err := doc.Compile(policy.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Every signer preset, once filled, decodes for a key and for the node
// default, passes the published schema, draws no advisory, and carries the
// shared note in its header.
func TestSignerPresetsDecodeOnceFilled(t *testing.T) {
	schema := compilePresetSchema(t)
	presets := Presets(noderole.RoleSigner)
	if got := presetNames(presets); got != "deny-all self-only listed-destinations transfers-only" {
		t.Fatalf("signer presets = %s", got)
	}
	for _, preset := range presets {
		for _, key := range []string{signerPresetKey, policy.DefaultKey} {
			text, err := PresetTemplate(noderole.RoleSigner, preset.Name, key)
			if err != nil {
				t.Fatalf("%s/%s: %v", preset.Name, key, err)
			}
			if got := strings.Contains(text, PresetPlaceholderPrefix); got != preset.Placeholders {
				t.Errorf("%s: carries placeholders = %v, Placeholders = %v", preset.Name, got, preset.Placeholders)
			}
			if !strings.Contains(strings.Join(strings.Fields(strings.ReplaceAll(text, "//", "")), " "), SignerPresetNote) {
				t.Errorf("%s: the header lacks the signer note", preset.Name)
			}
			stripped, err := StripComments([]byte(fillPresetPlaceholders(text)))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := policy.DecodePolicyV1(stripped, key, noderole.RoleSigner)
			if err != nil {
				t.Fatalf("%s/%s: %v", preset.Name, key, err)
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(stripped))
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(instance); err != nil {
				t.Errorf("%s/%s: schema: %v", preset.Name, key, err)
			}
			if got := doc.Advisories(); len(got) != 0 {
				t.Errorf("%s: advisories %v", preset.Name, got)
			}
		}
	}
	text, err := PresetTemplate(noderole.RoleSigner, "listed-destinations", signerPresetKey)
	if err != nil {
		t.Fatal(err)
	}
	stripped, _ := StripComments([]byte(text))
	_, err = policy.DecodePolicyV1(stripped, signerPresetKey, noderole.RoleSigner)
	var docErr *policy.DocumentError
	if !errors.As(err, &docErr) || docErr.Pointer != "/address_sets/destinations/0" {
		t.Fatalf("unfilled listed-destinations: %v, want an error at its placeholder", err)
	}
}

// The guards every signer preset shares, read from the compiled config, so
// an edit to one template that loosens them fails here.
func TestSignerPresetsShareTheirGuards(t *testing.T) {
	for _, preset := range Presets(noderole.RoleSigner) {
		cfg := signerPresetConfig(t, preset.Name)
		if cfg.Rekeys != policy.RekeysRejectForeign || !cfg.RejectCloseRemainder || !cfg.RejectAssetClose || !cfg.RejectClawback ||
			!cfg.AlwaysReviewWarnings || cfg.AutoApproveSelfNoOpTransfer || cfg.MaxFeeMicroAlgos != signerPresetFeeCap {
			t.Errorf("%s: guards %+v", preset.Name, cfg)
		}
		tp := cfg.TransferPolicy
		if tp == nil || tp.OnNoRoute != policy.TransferOnNoRouteReject || tp.CloseOnNoRoute != policy.TransferOnNoRouteReject || tp.ClawbackOnNoRoute != policy.TransferOnNoRouteReject {
			t.Errorf("%s: a routing miss is not rejected: %+v", preset.Name, tp)
		}
		for _, r := range tp.Routes {
			if r.AllowClose || r.AllowClawback {
				t.Errorf("%s: route %s allows close-outs or clawbacks", preset.Name, r.ID)
			}
		}
	}
}

// Each preset decides what it says through the node's own evaluator: a
// permitted transfer is left to the Operator Default, never approved;
// everything else is rejected, or reviewed where a warning asks for it.
func TestSignerPresetVerdicts(t *testing.T) {
	mainnet := presetGenesis(t, apconfig.AlgorandMainnetGenesisHash)
	pay := func(to types.Address, amount uint64) types.Transaction {
		return types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: presetSender, Fee: 1000, GenesisHash: mainnet},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: to, Amount: types.MicroAlgos(amount)}}
	}
	axfer := func(to types.Address, amount uint64) types.Transaction {
		return types.Transaction{Type: types.AssetTransferTx, Header: types.Header{Sender: presetSender, Fee: 1000, GenesisHash: mainnet},
			AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: 777, AssetAmount: amount, AssetReceiver: to}}
	}
	with := func(txn types.Transaction, edit func(*types.Transaction)) types.Transaction { edit(&txn); return txn }
	// base is each preset's permitted transfer, for the cases that change
	// one thing about a transaction the preset otherwise allows.
	base := map[string]types.Transaction{
		"deny-all":            pay(presetSender, 1),
		"self-only":           pay(presetSender, 1),
		"listed-destinations": pay(presetListed, 1),
		"transfers-only":      pay(presetOther, 1),
	}
	type outcomes map[string]policyeval.Outcome
	D, R, V := policyeval.Default, policyeval.Reject, policyeval.Review
	want := map[string]outcomes{
		"deny-all":            {"self payment": R, "self payment, zero": R, "opt-in": R, "payment to listed": R, "asset to listed": R, "payment to other": R},
		"self-only":           {"self payment": D, "self payment, zero": D, "opt-in": D, "payment to listed": R, "asset to listed": R, "payment to other": R},
		"listed-destinations": {"self payment": R, "self payment, zero": R, "opt-in": R, "payment to listed": D, "asset to listed": D, "payment to other": R},
		"transfers-only":      {"self payment": D, "self payment, zero": D, "opt-in": D, "payment to listed": D, "asset to listed": D, "payment to other": D},
	}
	for _, preset := range Presets(noderole.RoleSigner) {
		cfg := signerPresetConfig(t, preset.Name)
		b := base[preset.Name]
		allowed := preset.Name != "deny-all"
		ok := func(o policyeval.Outcome) policyeval.Outcome {
			if allowed {
				return o
			}
			return R
		}
		txns := map[string]types.Transaction{
			"self payment":        pay(presetSender, 5),
			"self payment, zero":  pay(presetSender, 0),
			"opt-in":              axfer(presetSender, 0),
			"payment to listed":   pay(presetListed, 5),
			"asset to listed":     axfer(presetListed, 5),
			"payment to other":    pay(presetOther, 5),
			"ALGO close-out":      with(b, func(t *types.Transaction) { t.CloseRemainderTo = presetListed }),
			"ASA close-out":       with(axfer(presetSender, 0), func(t *types.Transaction) { t.AssetCloseTo = presetListed }),
			"clawback":            with(axfer(presetListed, 1), func(t *types.Transaction) { t.AssetSender = presetOther }),
			"application call":    {Type: types.ApplicationCallTx, Header: types.Header{Sender: presetSender, Fee: 1000, GenesisHash: mainnet}},
			"key registration":    {Type: types.KeyRegistrationTx, Header: types.Header{Sender: presetSender, Fee: 1000, GenesisHash: mainnet}},
			"asset configuration": {Type: types.AssetConfigTx, Header: types.Header{Sender: presetSender, Fee: 1000, GenesisHash: mainnet}},
			"fee at the cap":      with(b, func(t *types.Transaction) { t.Fee = signerPresetFeeCap }),
			"fee over the cap":    with(b, func(t *types.Transaction) { t.Fee = signerPresetFeeCap + 1 }),
			"foreign rekey":       with(b, func(t *types.Transaction) { t.RekeyTo = presetOther }),
			"held-key rekey":      with(b, func(t *types.Transaction) { t.RekeyTo = presetHeld }),
			"another sender":      with(b, func(t *types.Transaction) { t.Sender = presetHeld }),
		}
		expect := outcomes{
			"ALGO close-out": R, "ASA close-out": R, "clawback": R,
			"application call": R, "key registration": R, "asset configuration": R,
			"fee at the cap": ok(D), "fee over the cap": R,
			"foreign rekey": R, "held-key rekey": ok(V),
		}
		for name, o := range want[preset.Name] {
			expect[name] = o
		}
		// Sources are "*", so a sender rekeyed to this key routes the same,
		// except where the route names the sender itself.
		expect["another sender"] = ok(D)
		if preset.Name == "self-only" {
			expect["another sender"] = R
		}
		names := make([]string, 0, len(txns))
		for name := range txns {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			wantOutcome, listed := expect[name]
			if !listed {
				t.Fatalf("%s: no expectation for %s", preset.Name, name)
			}
			got := evaluateSignerPreset(t, cfg, txns[name])
			if got.Outcome != wantOutcome {
				t.Errorf("%s: %s = %s (%s %v), want %s", preset.Name, name, got.Outcome, got.RuleID, got.Violations, wantOutcome)
			}
		}

		// A self no-op the self-no-op rule would approve stays with the
		// Operator Default: the preset leaves that rule off.
		if allowed && preset.Name != "listed-destinations" {
			noop := pay(presetSender, 0)
			got, err := policyeval.Evaluate(policyeval.Input{
				Group: []types.Transaction{noop}, Slots: []policyeval.Slot{{Index: 0, Policy: cfg}},
				Plan: &policyeval.PlanFacts{RequestCount: 1, AuthAddressPresent: true},
			})
			if err != nil || got.Outcome != policyeval.Default {
				t.Errorf("%s: self no-op = %+v, %v, want the Operator Default", preset.Name, got, err)
			}
		}
		// One denied signer position rejects the group.
		group := []types.Transaction{b, pay(presetOther, 1)}
		if preset.Name == "transfers-only" {
			group[1] = txns["application call"]
		}
		got, err := policyeval.Evaluate(policyeval.Input{
			Group: group, Slots: []policyeval.Slot{{Index: 0, Policy: cfg}, {Index: 1, Policy: cfg}},
			KnownAddresses: map[string]bool{presetHeld.String(): true},
		})
		if err != nil || got.Outcome != policyeval.Reject {
			t.Errorf("%s: a group with a denied position = %+v, %v, want Reject", preset.Name, got, err)
		}
	}
}

func evaluateSignerPreset(t *testing.T, cfg *policy.Config, txn types.Transaction) policyeval.Verdict {
	t.Helper()
	got, err := policyeval.Evaluate(policyeval.Input{
		Group:          []types.Transaction{txn},
		Slots:          []policyeval.Slot{{Index: 0, Policy: cfg}},
		KnownAddresses: map[string]bool{presetHeld.String(): true, presetSender.String(): true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func presetNames(presets []Preset) string {
	names := make([]string, len(presets))
	for i, p := range presets {
		names[i] = p.Name
	}
	return strings.Join(names, " ")
}

// The signer presets' fee cap covers a full group of payments or asset
// transfers at the minimum fee, the whole group's fee landing on one
// transaction. The planner charges such a member exactly these, and adds
// them (native_pq_fee.go): its transaction factor (one base fee, plus the
// note bytes beyond the free allowance; the app-call and heartbeat terms do
// not apply to a payment or asset transfer), the Falcon contribution when
// it is authorized under the native Falcon scheme, and its share of the
// group's LogicSig program-byte surcharge. A Falcon-delegated LogicSig pays
// both of the last two, so the worst member pays all four. The bound is
// computed from each consensus version the signer accepts, so a protocol
// change that raises it fails here instead of silently refusing such
// groups. Fees other members pool onto this key's transaction (app calls,
// their inner transactions) are not covered, and are documented as needing
// a higher cap.
func TestSignerPresetFeeCapCoversAFullGroup(t *testing.T) {
	for _, version := range []protocol.ConsensusVersion{protocol.ConsensusV42, protocol.ConsensusV43} {
		p, ok := sdkconfig.Consensus[version]
		if !ok {
			t.Fatalf("no consensus parameters for %s", version)
		}
		const unit = 1_000_000 // one transaction's fee factor
		surcharge := uint64(p.PerByteTxnSurcharge)
		note := uint64(p.MaxAbsoluteTxnNoteBytes-p.MaxTxnNoteBytes) * surcharge
		program := uint64(0)
		if p.MaxAbsoluteLogicSigProgramSize > p.LogicSigMaxSize {
			program = (p.MaxAbsoluteLogicSigProgramSize - p.LogicSigMaxSize) * surcharge
		}
		member := unit + note + falcon1024.PQFeeContribution + program
		factor := uint64(p.MaxTxGroupSize) * member
		bound := (p.MinTxnFee*factor + unit - 1) / unit
		if bound > signerPresetFeeCap {
			t.Errorf("%s: a full group can need %d microAlgos, above the presets' cap of %d", version, bound, signerPresetFeeCap)
		}
		t.Logf("%s: full-group bound %d microAlgos, cap %d", version, bound, signerPresetFeeCap)
	}
}
