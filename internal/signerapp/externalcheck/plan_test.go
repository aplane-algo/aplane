// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package externalcheck

import (
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/policy"
)

const planSources = `{
  "ops": {"base_url": "http://127.0.0.1:8650"},
  "screening": {"base_url": "https://screen.example.com/api/"}
}`

const planChecks = `[
  {"id": "ops-switch", "source": "ops", "scope": "request", "networks": ["*"],
   "path": "/signing/{witness_key}", "require": [{"pointer": "/enabled", "op": "eq", "bool": true}]},
  {"id": "by-sender", "source": "ops", "scope": "transaction", "networks": ["mainnet"],
   "path": "/senders/{sender}", "query": {"type": "{type}", "fee": "max {fee}&x"},
   "require": [{"pointer": "", "op": "present"}]},
  {"id": "screen", "source": "screening", "scope": "movement", "networks": ["mainnet"],
   "movement_kinds": ["pay", "axfer"],
   "path": "/v2/{asset}/{destination}", "require": [{"pointer": "/ok", "op": "eq", "bool": true}]}
]`

func TestBuildPlanListsUnitsAndRendersRequests(t *testing.T) {
	cfg := compileChecks(t, planSources, planChecks)
	pay := payment(addr(1), addr(2), 5)
	axfer := assetTransfer(addr(1), addr(3), 31566704, 7)
	plan, refusal := BuildPlan(cfg.ExternalChecks, cfg.ExternalSources, requestOf(pay, axfer))
	if refusal != nil {
		t.Fatalf("BuildPlan() refusal = %+v", refusal)
	}
	var got []string
	for _, j := range plan.Judgments {
		got = append(got, fmt.Sprintf("%s | %s | %s", j.Check.ID, j.Unit, plan.Lookups[j.Lookup].URL))
	}
	// Both transactions have one sender, so by-sender's two units share one
	// lookup. The base path's trailing "/" does not double the separator.
	want := []string{
		"ops-switch | the request | http://127.0.0.1:8650/signing/" + testWitnessKey,
		"by-sender | transaction 0 | http://127.0.0.1:8650/senders/" + addr(1).String() + "?fee=max+1000%26x&type=pay",
		"by-sender | transaction 1 | http://127.0.0.1:8650/senders/" + addr(1).String() + "?fee=max+1000%26x&type=axfer",
		"screen | the pay movement of transaction 0 | https://screen.example.com/api/v2/algo/" + addr(2).String(),
		"screen | the axfer movement of transaction 1 | https://screen.example.com/api/v2/asa:31566704/" + addr(3).String(),
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("judgments:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(plan.Lookups) != 5 {
		t.Fatalf("%d lookups, want 5", len(plan.Lookups))
	}
	facts := plan.Judgments[3].Facts
	for name, want := range map[string]string{
		"network": "mainnet", "witness_key": testWitnessKey, "sender": addr(1).String(),
		"txid": crypto.GetTxID(pay), "type": "pay", "fee": "1000", "kind": "pay",
		"source": addr(1).String(), "destination": addr(2).String(), "asset": "algo", "asset_id": "0", "amount": "5",
	} {
		if facts[name] != want {
			t.Errorf("fact %s = %q, want %q", name, facts[name], want)
		}
	}
	for _, absent := range []string{"rekey_to", "asset_source"} {
		if _, has := facts[absent]; has {
			t.Errorf("a plain payment has fact %s", absent)
		}
	}
	if got := plan.Judgments[4].Facts["asset_id"]; got != "31566704" {
		t.Errorf("asset_id = %q", got)
	}
}

func TestBuildPlanMergesIdenticalLookups(t *testing.T) {
	cfg := compileChecks(t, planSources, planChecks)
	plan, refusal := BuildPlan(cfg.ExternalChecks, cfg.ExternalSources, requestOf(payment(addr(1), addr(2), 5), payment(addr(1), addr(2), 9)))
	if refusal != nil {
		t.Fatal(refusal)
	}
	// One request lookup, one sender lookup and one destination lookup serve
	// five judgments.
	if len(plan.Lookups) != 3 || len(plan.Judgments) != 5 {
		t.Fatalf("%d lookups for %d judgments, want 3 for 5", len(plan.Lookups), len(plan.Judgments))
	}
	if plan.Judgments[3].Lookup != plan.Judgments[4].Lookup {
		t.Fatal("two payments to one destination must share a lookup")
	}
}

func TestBuildPlanSkipsWhatAChecksDoesNotCover(t *testing.T) {
	cfg := compileChecks(t, planSources, planChecks)
	closeOut := payment(addr(1), addr(2), 5)
	closeOut.CloseRemainderTo = addr(4)
	keyreg := types.Transaction{Type: types.KeyRegistrationTx, Header: types.Header{Sender: addr(1)}}
	req := requestOf(closeOut, keyreg)
	req.NetworkOf = func(txn types.Transaction) string {
		if txn.Type == types.KeyRegistrationTx {
			return "testnet"
		}
		return "mainnet"
	}
	plan, refusal := BuildPlan(cfg.ExternalChecks, cfg.ExternalSources, req)
	if refusal != nil {
		t.Fatal(refusal)
	}
	var units []string
	for _, j := range plan.Judgments {
		units = append(units, j.Check.ID+":"+j.Unit)
	}
	// The testnet keyreg is outside by-sender's networks and has no movement;
	// the close-out is outside screen's kinds.
	want := "ops-switch:the request,by-sender:transaction 0,screen:the pay movement of transaction 0"
	if strings.Join(units, ",") != want {
		t.Fatalf("units = %s, want %s", strings.Join(units, ","), want)
	}
}

func TestBuildPlanRefusals(t *testing.T) {
	amountCheck := `[{"id": "allowance", "source": "ops", "scope": "movement", "networks": ["*"],
	  "path": "/a", "require": [{"pointer": "/remaining", "op": "ge", "fact": "amount"}]}]`
	rekeyCheck := `[{"id": "handover", "source": "ops", "scope": "transaction", "networks": ["*"],
	  "path": "/h/{rekey_to}", "require": [{"pointer": "", "op": "present"}]}]`
	perDestination := `[{"id": "each", "source": "ops", "scope": "movement", "networks": ["*"],
	  "path": "/d/{destination}", "require": [{"pointer": "", "op": "present"}]}]`
	closeOut := payment(addr(1), addr(2), 5)
	closeOut.CloseRemainderTo = addr(4)
	rekey := payment(addr(1), addr(1), 0)
	rekey.RekeyTo = addr(9)
	var many []types.Transaction
	for i := 0; i < 16; i++ {
		txn := payment(addr(1), addr(byte(10+i)), 1)
		txn.CloseRemainderTo = addr(byte(40 + i))
		many = append(many, txn)
	}
	for _, tt := range []struct {
		name, checks string
		group        []types.Transaction
		outcome      string
		unit, detail string
	}{
		{"amount on a close-out", amountCheck, []types.Transaction{closeOut},
			policy.ExternalCheckMissingFactOutcome, "the pay_close movement of transaction 0", "no amount"},
		{"rekey_to off a rekey", rekeyCheck, []types.Transaction{payment(addr(1), addr(2), 1)},
			policy.ExternalCheckMissingFactOutcome, "transaction 0", "no rekey_to"},
		{"too many lookups", perDestination, many,
			policy.ExternalCheckTooManyLookupsOutcome, "the pay movement of transaction 16", "more than 32"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := compileChecks(t, planSources[:strings.Index(planSources, ",")]+"}", tt.checks)
			group := tt.group
			if tt.name == "too many lookups" {
				// 16 payments with close-outs are 32 destinations; one more
				// payment is the 33rd.
				group = append(group, payment(addr(1), addr(99), 1))
			}
			_, refusal := BuildPlan(cfg.ExternalChecks, cfg.ExternalSources, requestOf(group...))
			if refusal == nil {
				t.Fatal("BuildPlan() refusal = nil")
			}
			if refusal.Outcome != tt.outcome || refusal.Unit != tt.unit || !strings.Contains(refusal.Detail, tt.detail) {
				t.Fatalf("refusal = %+v, want %s for %s (%s)", refusal, tt.outcome, tt.unit, tt.detail)
			}
		})
	}
	// A rekey has the fact, and a pay movement of amount 0 to itself.
	cfg := compileChecks(t, `{"ops": {"base_url": "http://127.0.0.1:8650"}}`, rekeyCheck)
	plan, refusal := BuildPlan(cfg.ExternalChecks, cfg.ExternalSources, requestOf(rekey))
	if refusal != nil || !strings.HasSuffix(plan.Lookups[0].URL, "/h/"+addr(9).String()) {
		t.Fatalf("rekey plan = %+v, refusal %+v", plan, refusal)
	}
	cfg = compileChecks(t, `{"ops": {"base_url": "http://127.0.0.1:8650"}}`, amountCheck)
	plan, refusal = BuildPlan(cfg.ExternalChecks, cfg.ExternalSources, requestOf(rekey))
	if refusal != nil || len(plan.Judgments) != 1 || plan.Judgments[0].Facts["amount"] != "0" ||
		plan.Judgments[0].Facts["destination"] != addr(1).String() {
		t.Fatalf("a cosigned rekey must be judged as a 0 ALGO pay to itself: %+v, %+v", plan, refusal)
	}
}

func TestRefusalWording(t *testing.T) {
	r := &Refusal{CheckID: "screen", Unit: "the pay movement of transaction 0", Source: "screening",
		Path: "/api/v2/x", Detail: `/risk/score = 72, want le 30`}
	if got, want := r.Message(), "external check screen refused the pay movement of transaction 0 (external_check:screen)"; got != want {
		t.Fatalf("Message() = %q, want %q", got, want)
	}
	if strings.Contains(r.Message(), "72") {
		t.Fatal("the requester's message quotes the answer")
	}
	want := `external_check:screen: external check screen refused the pay movement of transaction 0; source screening, GET /api/v2/x: /risk/score = 72, want le 30`
	if got := r.AuditReason(); got != want {
		t.Fatalf("AuditReason() = %q, want %q", got, want)
	}
	r.Outcome = policy.ExternalCheckUnavailableOutcome
	if got := r.RuleID(); got != "external_check:screen:unavailable" {
		t.Fatalf("RuleID() = %q", got)
	}
}
