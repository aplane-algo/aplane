// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txeffects_test

import (
	"fmt"
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
		if shape.Rekey == boundedaccount.RekeyOnlyThese {
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
	corpus := surfaceCorpus(t)
	reached := make(map[txeffects.Rule]bool)
	for descriptor, declaration := range declarations {
		for name, txn := range corpus {
			decision, err := txeffects.ClassifyFor(txn, declaration)
			if err != nil {
				t.Fatalf("%s / %s: %v", descriptor, name, err)
			}
			reached[decision.Rule] = true
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
	_, err := txeffects.ClassifyFor(types.Transaction{Type: types.PaymentTx}, boundedmeta.PathDeclaration{Rekey: "admin_key"})
	if err == nil || !strings.Contains(err.Error(), "unsupported rekey setting") {
		t.Fatalf("ClassifyFor() error = %v", err)
	}
}

func TestClassifyForChecksTheFeeCeilingFirst(t *testing.T) {
	ceiling := uint64(2_000)
	declaration := boundedmeta.PathDeclaration{Contract: "bounded1", SpendEffects: []string{"pay"}, MaxFee: &ceiling, Rekey: boundedmeta.RekeySpendingKey}
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
