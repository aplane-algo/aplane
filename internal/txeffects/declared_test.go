// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txeffects_test

import (
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/boundedaccount"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
)

// refusalRules and allowRules are every rule ClassifyFor may report. A rule outside
// both would be a branch the O12 test can't account for.
var (
	refusalRules = map[txeffects.Rule]bool{
		txeffects.RuleFeeCeiling: true, txeffects.RuleSpendNotDeclared: true, txeffects.RuleRekeyRefused: true,
		txeffects.RuleHybridRekey: true, txeffects.RuleDeniedEffect: true, txeffects.RuleDeniedType: true,
	}
	allowRules = map[txeffects.Rule]txeffects.Path{
		txeffects.RuleSpendAllowed: txeffects.PathSpend,
		txeffects.RuleOpenSpend:    txeffects.PathSpend,
		txeffects.RuleRekeyAllowed: txeffects.PathSpendingRekey,
		txeffects.RuleRekeyListed:  txeffects.PathListedRekey,
	}
)

// grammarDeclarations is every declaration the general bounded type produces,
// read from each shape's resolved metadata.
func grammarDeclarations(t *testing.T) map[string]boundedmeta.PathDeclaration {
	t.Helper()
	falcon.RegisterClient()
	provider, err := boundedaccount.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	declarations := make(map[string]boundedmeta.PathDeclaration)
	for _, shape := range boundedaccount.Shapes() {
		params := map[string]string{
			boundedaccount.ParameterSpendEffects:   joinSpend(shape.Spend),
			boundedaccount.ParameterRekeyAuthority: shape.Rekey,
		}
		if shape.Encoding != "" {
			params[boundedaccount.ParameterListEncoding] = shape.Encoding
			params[boundedaccount.ParameterRecipients] = types.Address{1}.String() + "," + types.Address{2}.String()
		}
		if shape.Timelock {
			params[boundedaccount.ParameterUnlockRound] = "5"
		}
		if shape.AnyRecipient {
			params[boundedaccount.ParameterRecipientScope] = boundedaccount.RecipientScopeAny
		}
		if shape.HasRekeyList() {
			params[boundedaccount.ParameterRekeyTo] = types.Address{3}.String()
		}
		if shape.Cosigner {
			params[boundedmeta.CosignerPublicKeyParameter] = strings.Repeat("41", boundedmeta.CosignerPublicKeySizeV1)
		}
		instance, err := provider.ResolveInstance(params)
		if err != nil {
			t.Fatalf("%s: %v", shape.Descriptor(), err)
		}
		declaration, err := instance.Bounded.Declaration()
		if err != nil {
			t.Fatalf("%s: %v", shape.Descriptor(), err)
		}
		declarations[shape.Descriptor()] = declaration
	}
	return declarations
}

// plainDeclarations is every plain host arrangement: always cosigned, with each
// rekey setting.
func plainDeclarations() map[string]boundedmeta.PathDeclaration {
	declarations := make(map[string]boundedmeta.PathDeclaration)
	for _, arrangement := range []struct {
		name  string
		rekey boundedmeta.RekeySetting
		list  bool
	}{
		{"refused", boundedmeta.RekeyRefused, false},
		{"cosigned rekey", boundedmeta.RekeySpendingKey, false},
		{"only these", boundedmeta.RekeyRefused, true},
		{"plus cosigned", boundedmeta.RekeySpendingKey, true},
	} {
		declarations["plain "+arrangement.name] = boundedmeta.PathDeclaration{
			Contract:     boundedmeta.PlainContract,
			Layer3Policy: boundedmeta.Layer3PolicyNone,
			Rekey:        arrangement.rekey,
			RekeyList:    arrangement.list,
			Cosigner: &boundedmeta.CosignerOverlay{
				ComponentKeyType: boundedmeta.CosignerComponentKeyTypeV1,
				RequiredOn:       boundedmeta.CosignerRequiredOn(arrangement.rekey),
			},
		}
	}
	return declarations
}

func joinSpend(spend []txeffects.SpendEffect) string {
	names := make([]string, len(spend))
	for i, effect := range spend {
		names[i] = string(effect)
	}
	return strings.Join(names, ",")
}

// surfaceCorpus exercises every transaction type the protocol surface lists, with
// every combination of the authority- and value-moving address fields, a
// self-directed zero-value and an outward form, and a fee on each side of the
// bounded ceiling.
func surfaceCorpus(t *testing.T) map[string]types.Transaction {
	t.Helper()
	surface := readProtocolSurface(t)
	var sender, other types.Address
	sender[0], other[0] = 0x51, 0x52
	corpus := make(map[string]types.Transaction)
	for _, entry := range surface.TransactionTypes {
		for _, self := range []bool{true, false} {
			for mask := 0; mask < 16; mask++ {
				for _, fee := range []uint64{1_000, boundedmeta.MaximumProfileFee + 1} {
					txn := types.Transaction{Type: types.TxType(entry.Wire)}
					txn.Sender, txn.Fee = sender, types.MicroAlgos(fee)
					if self {
						txn.Receiver, txn.AssetReceiver = sender, sender
					} else {
						txn.Receiver, txn.AssetReceiver = other, other
						txn.Amount, txn.AssetAmount = 1_000, 1
					}
					if mask&1 != 0 {
						txn.RekeyTo = other
					}
					if mask&2 != 0 {
						txn.CloseRemainderTo = other
					}
					if mask&4 != 0 {
						txn.AssetCloseTo = other
					}
					if mask&8 != 0 {
						txn.AssetSender = other
					}
					name := entry.Name
					if self {
						name += "/self"
					} else {
						name += "/outward"
					}
					corpus[fmt.Sprintf("%s/effects=%04b/fee=%d", name, mask, fee)] = txn
				}
			}
		}
	}
	return corpus
}

// O12: for every declaration the grammar can produce, every effect in the protocol
// surface reaches a named allow or deny rule, never a default branch, and an allow
// is only ever what the declaration states.
func TestClassifyForReachesAnExplicitRuleForEveryEffect(t *testing.T) {
	declarations := grammarDeclarations(t)
	// The general type never refuses every rekey, but an expert template may: its
	// declaration is the grammar's with neither a spending-key rekey nor a list.
	for descriptor, declaration := range declarations {
		if declaration.Rekey == boundedmeta.RekeyRefused && declaration.RekeyList {
			declaration.RekeyList = false
			declarations["expert refused, from "+descriptor] = declaration
			break
		}
	}
	maps.Copy(declarations, plainDeclarations())
	corpus := surfaceCorpus(t)
	reached := make(map[txeffects.Rule]bool)
	for descriptor, declaration := range declarations {
		plain := declaration.Contract == boundedmeta.PlainContract
		for name, txn := range corpus {
			decision, err := txeffects.ClassifyFor(txn, declaration)
			if err != nil {
				t.Fatalf("%s / %s: %v", descriptor, name, err)
			}
			reached[decision.Rule] = true
			// A plain host has no host rules: every transaction that doesn't
			// rekey is a spend, and nothing else is.
			if plain && txn.RekeyTo.IsZero() != (decision.Rule == txeffects.RuleOpenSpend) {
				t.Fatalf("%s / %s: rule %s on a plain host", descriptor, name, decision.Rule)
			}
			if !plain && decision.Rule == txeffects.RuleOpenSpend {
				t.Fatalf("%s / %s: a bounded host took an open spend", descriptor, name)
			}
			if path, allowed := allowRules[decision.Rule]; allowed {
				if decision.Path != path {
					t.Fatalf("%s / %s: rule %s took path %s", descriptor, name, decision.Rule, decision.Path)
				}
			} else if !refusalRules[decision.Rule] {
				t.Fatalf("%s / %s: unaccounted rule %q", descriptor, name, decision.Rule)
			} else if decision.Path != txeffects.PathRefused || decision.Reason == "" {
				t.Fatalf("%s / %s: refusal rule %s gave path %q and reason %q", descriptor, name, decision.Rule, decision.Path, decision.Reason)
			}
			switch decision.Path {
			case txeffects.PathSpend:
				if plain {
					break
				}
				if !declaration.AllowsSpendEffect(string(decision.SpendEffect)) || len(decision.Facts.Effects()) != 0 {
					t.Fatalf("%s / %s: allowed an undeclared spend %q", descriptor, name, decision.SpendEffect)
				}
			case txeffects.PathSpendingRekey:
				if declaration.Rekey != boundedmeta.RekeySpendingKey || txn.Type != types.PaymentTx || txn.Amount != 0 || txn.Receiver != txn.Sender {
					t.Fatalf("%s / %s: allowed a rekey the declaration refuses", descriptor, name)
				}
			case txeffects.PathListedRekey:
				if !declaration.RekeyList || txn.Type != types.PaymentTx || txn.Amount != 0 || txn.Receiver != txn.Sender || len(decision.Facts.Effects()) != 1 {
					t.Fatalf("%s / %s: sent a rekey that is not pure to the listed path", descriptor, name)
				}
			}
		}
	}
	for rule := range refusalRules {
		if !reached[rule] {
			t.Errorf("no transaction in the corpus reached %s", rule)
		}
	}
	for rule := range allowRules {
		if !reached[rule] {
			t.Errorf("no transaction in the corpus reached %s", rule)
		}
	}
}

func TestClassifyForRefusesAnInvalidDeclaration(t *testing.T) {
	ceiling := uint64(1_000)
	for _, tc := range []struct {
		name        string
		declaration boundedmeta.PathDeclaration
		want        string
	}{
		{"rekey setting", boundedmeta.PathDeclaration{Contract: boundedmeta.Contract, Rekey: "admin_key"}, "unsupported rekey setting"},
		{"contract", boundedmeta.PathDeclaration{Contract: "bounded1", Rekey: boundedmeta.RekeyRefused}, "unsupported bounded authorization contract"},
		{"plain fee ceiling", boundedmeta.PathDeclaration{Contract: boundedmeta.PlainContract, MaxFee: &ceiling, Rekey: boundedmeta.RekeyRefused}, "no fee ceiling"},
		{"plain spend effects", boundedmeta.PathDeclaration{Contract: boundedmeta.PlainContract, SpendEffects: []string{"pay"}, Rekey: boundedmeta.RekeyRefused}, "no fee ceiling or spend effects"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := txeffects.ClassifyFor(types.Transaction{Type: types.PaymentTx}, tc.declaration)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ClassifyFor() error = %v, want %q", err, tc.want)
			}
		})
	}
}

// A plain host's spend may carry a close or clawback, but a rekey still passes
// only as a pure rekey.
func TestClassifyForPlainHost(t *testing.T) {
	declaration := plainDeclarations()["plain plus cosigned"]
	var sender, other types.Address
	sender[0], other[0] = 1, 2
	closing := types.Transaction{Type: types.PaymentTx}
	closing.Sender, closing.Receiver, closing.CloseRemainderTo, closing.Fee = sender, other, other, 1_000_000
	clawback := types.Transaction{Type: types.AssetTransferTx}
	clawback.Sender, clawback.AssetSender, clawback.AssetReceiver = sender, other, sender
	appCall := types.Transaction{Type: types.ApplicationCallTx}
	appCall.Sender = sender
	pureRekey := types.Transaction{Type: types.PaymentTx}
	pureRekey.Sender, pureRekey.Receiver, pureRekey.RekeyTo = sender, sender, other
	closingRekey := closing
	closingRekey.RekeyTo = other
	rekeyingAppCall := appCall
	rekeyingAppCall.RekeyTo = other
	for _, tc := range []struct {
		name string
		txn  types.Transaction
		rule txeffects.Rule
	}{
		{"close with a high fee", closing, txeffects.RuleOpenSpend},
		{"clawback", clawback, txeffects.RuleOpenSpend},
		{"app call", appCall, txeffects.RuleOpenSpend},
		{"pure rekey", pureRekey, txeffects.RuleRekeyAllowed},
		{"rekey with a close", closingRekey, txeffects.RuleHybridRekey},
		{"app call that rekeys", rekeyingAppCall, txeffects.RuleHybridRekey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decision, err := txeffects.ClassifyFor(tc.txn, declaration)
			if err != nil || decision.Rule != tc.rule {
				t.Fatalf("decision = %+v, %v; want rule %s", decision, err, tc.rule)
			}
		})
	}
}

func TestClassifyForChecksTheFeeCeilingFirst(t *testing.T) {
	ceiling := uint64(2_000)
	declaration := boundedmeta.PathDeclaration{Contract: boundedmeta.Contract, SpendEffects: []string{"pay"}, MaxFee: &ceiling, Rekey: boundedmeta.RekeySpendingKey}
	var sender types.Address
	sender[0] = 1
	txn := types.Transaction{Type: types.PaymentTx}
	txn.Sender, txn.Receiver, txn.Fee = sender, sender, 2_001
	decision, err := txeffects.ClassifyFor(txn, declaration)
	if err != nil || decision.Rule != txeffects.RuleFeeCeiling || !strings.Contains(decision.Reason, "exceeds account maximum 2000") {
		t.Fatalf("decision = %+v, %v", decision, err)
	}
	declaration.MaxFee = nil
	if decision, err := txeffects.ClassifyFor(txn, declaration); err != nil || decision.Path != txeffects.PathSpend {
		t.Fatalf("no ceiling: decision = %+v, %v", decision, err)
	}
}
