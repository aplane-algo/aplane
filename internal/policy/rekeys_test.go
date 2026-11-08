// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/noderole"
)

// The rekeys setting is the signer's one rejection rule for a rekey. It rejects
// or not; it never approves, so what it lets through is left to the rest of
// policy.
func TestRekeysSettingRejectsByTarget(t *testing.T) {
	held, unheld, protocol := types.Address{1}, types.Address{2}, types.Address{3}
	ctx := LintContext{
		KnownAddresses:       map[string]bool{held.String(): true, protocol.String(): true},
		ProtocolRekeyTargets: map[string]bool{protocol.String(): true},
	}
	rekeyTo := func(target types.Address) types.Transaction {
		return types.Transaction{Type: types.PaymentTx, Header: types.Header{RekeyTo: target}}
	}
	for _, test := range []struct {
		setting SignerRekeys
		target  types.Address
		rule    string // "" when nothing is rejected
	}{
		{RekeysRejectAll, held, RejectAllRekeysRuleID},
		{RekeysRejectAll, unheld, RejectAllRekeysRuleID},
		{RekeysRejectAll, protocol, ""},
		{RekeysRejectForeign, held, ""},
		{RekeysRejectForeign, unheld, RejectForeignRekeyRuleID},
		{RekeysRejectForeign, protocol, ""},
		{RekeysAllow, held, ""},
		{RekeysAllow, unheld, ""},
		{RekeysAllow, protocol, ""},
		// A Config never given a setting fails closed.
		{"", held, RejectAllRekeysRuleID},
		{"", protocol, ""},
	} {
		cfg := &Config{Role: noderole.RoleSigner, TransactionTypes: allowAllTypes(), Rekeys: test.setting}
		got := CheckTxnPolicyLintsIn(rekeyTo(test.target), cfg, ctx)
		rule := ""
		if len(got) > 0 {
			rule = got[0].RuleID
		}
		if len(got) > 1 || rule != test.rule {
			t.Errorf("rekeys %q, target %v: violations %+v, want rule %q", test.setting, test.target, got, test.rule)
		}
	}
	// No rekey, nothing to reject.
	cfg := &Config{Role: noderole.RoleSigner, TransactionTypes: allowAllTypes(), Rekeys: RekeysRejectAll}
	if got := CheckTxnPolicyLintsIn(types.Transaction{Type: types.PaymentTx}, cfg, ctx); len(got) != 0 {
		t.Fatalf("a transaction with no rekey was rejected: %+v", got)
	}
}

// The cosigner role judges rekeys with reject_rekey and rekey_policy, so a
// cosigner Config, which has no rekeys setting, rejects nothing here.
func TestRekeysSettingIsSignerOnly(t *testing.T) {
	cfg := &Config{Role: noderole.RoleCosigner, TransactionTypes: allowAllTypes()}
	txn := types.Transaction{Type: types.PaymentTx, Header: types.Header{RekeyTo: types.Address{2}}}
	if got := CheckTxnPolicyLints(txn, cfg, nil); len(got) != 0 {
		t.Fatalf("a cosigner Config applied the signer's rekey rule: %+v", got)
	}
}

func TestRekeysSettingDecodes(t *testing.T) {
	for _, setting := range []SignerRekeys{RekeysRejectAll, RekeysRejectForeign, RekeysAllow} {
		doc := mustSignerDoc(t, DefaultKey, `{"rekeys": "`+string(setting)+`"}`)
		if doc.Rekeys != setting {
			t.Fatalf("decoded %q, want %q", doc.Rekeys, setting)
		}
		cfg, err := doc.Compile(DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Rekeys != setting {
			t.Fatalf("compiled %q, want %q", cfg.Rekeys, setting)
		}
	}
	for value, want := range map[string]string{
		`"reject_foreign"`: "must be one of reject_all_rekeys, reject_foreign_rekey, allow_rekeys",
		`""`:               "must be one of",
		`true`:             "string",
	} {
		if _, err := DecodePolicyV1(signerJSON(t, DefaultKey, `{"rekeys": `+value+`}`), DefaultKey, noderole.RoleSigner); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("rekeys %s: error = %v, want %q", value, err, want)
		}
	}
}

func TestRekeysSettingDiffRanksStrictness(t *testing.T) {
	doc := func(setting SignerRekeys) *PolicyV1 {
		return mustSignerDoc(t, DefaultKey, `{"rekeys": "`+string(setting)+`"}`)
	}
	assertChanges(t, DiffPolicyV1(doc(RekeysAllow), doc(RekeysRejectAll)), "tightened /rekeys: allow_rekeys → reject_all_rekeys")
	assertChanges(t, DiffPolicyV1(doc(RekeysRejectAll), doc(RekeysRejectForeign)), "loosened /rekeys: reject_all_rekeys → reject_foreign_rekey")
	assertChanges(t, DiffPolicyV1(doc(RekeysRejectForeign), doc(RekeysRejectForeign)))
}

// O8: an account's own rekey-to list is the owner's standing statement, so
// reject_foreign_rekey counts its targets as declared. reject_all_rekeys still
// rejects them: it rejects every rekey.
func TestListedRekeyTargetsCountAsDeclared(t *testing.T) {
	listed := types.Address{4}
	ctx := LintContext{ListedRekeyTargets: map[string]bool{listed.String(): true}}
	txn := types.Transaction{Type: types.PaymentTx, Header: types.Header{RekeyTo: listed}}
	foreign := &Config{Role: noderole.RoleSigner, TransactionTypes: allowAllTypes(), Rekeys: RekeysRejectForeign}
	if got := CheckTxnPolicyLintsIn(txn, foreign, ctx); len(got) != 0 {
		t.Fatalf("reject_foreign_rekey refused a listed target: %+v", got)
	}
	if got := CheckTxnPolicyLintsIn(txn, foreign, LintContext{}); len(got) != 1 || got[0].RuleID != RejectForeignRekeyRuleID {
		t.Fatalf("without its list, the target is foreign: %+v", got)
	}
	all := &Config{Role: noderole.RoleSigner, TransactionTypes: allowAllTypes(), Rekeys: RekeysRejectAll}
	if got := CheckTxnPolicyLintsIn(txn, all, ctx); len(got) != 1 || got[0].RuleID != RejectAllRekeysRuleID {
		t.Fatalf("reject_all_rekeys let a listed rekey through: %+v", got)
	}
}
