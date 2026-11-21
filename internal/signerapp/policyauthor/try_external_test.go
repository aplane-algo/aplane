// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"
)

const (
	extSender   = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"
	extReceiver = "EIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDOHSEZI"
	extKey      = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
)

var (
	opsPath       = "/signing/" + extKey
	screeningPath = "/api/v2/addresses/" + extReceiver + "?chain=algorand"
	treasuryPath  = "/allowance/" + extSender + "/algo"
)

// mainnetPayment is a 5 microAlgo mainnet payment every check of the
// external checks fixture applies to.
var mainnetPayment = TryTxn{Network: "mainnet", Sender: extSender, Receiver: extReceiver, Amount: 5, Fee: 1000}

func one(body string) CheckAnswer { return CheckAnswer{Answer: []byte(body)} }

// passing answers every check of the fixture so that it passes.
func passing() ExternalAnswers {
	return ExternalAnswers{
		"ops-switch":         one(`{"enabled": true}`),
		"screen-destination": one(`{"sanctioned": false, "risk": {"score": 12, "level": "low"}}`),
		"daily-allowance":    one(`{"remaining": 100, "request_id": "r-1"}`),
	}
}

// externalDoc is the external checks fixture with edit applied to its JSON.
func externalDoc(t *testing.T, edit func(doc map[string]any)) *File {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(fixture(t, externalFixture), &doc); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(doc)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return writeTryDoc(t, string(data))
}

func addCheck(t *testing.T, doc map[string]any, check string) {
	t.Helper()
	var c any
	if err := json.Unmarshal([]byte(check), &c); err != nil {
		t.Fatal(err)
	}
	doc["external_checks"] = append(doc["external_checks"].([]any), c)
}

// allowCloseOuts lets the fixture's route permit a close-out.
func allowCloseOuts(doc map[string]any) {
	doc["reject_close_remainder"] = false
	doc["transfer_policy"].(map[string]any)["routes"].([]any)[0].(map[string]any)["allow_close"] = true
}

func tryWith(t *testing.T, f *File, txn TryTxn, answers ExternalAnswers) TryResult {
	t.Helper()
	got, err := TryWithAnswers(f, txn, answers, BuiltinNetworks())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// Every applying check answered and passing: the cosigner would sign. The
// lookups are listed as the cosigner's plan renders them, and the echo of a
// canned answer is taken on trust and said to be.
func TestTryAnswersThatPass(t *testing.T) {
	got := tryWith(t, LoadFile(writeFile(t, t.TempDir(), "c.json", fixture(t, externalFixture))), mainnetPayment, passing())
	x := got.ExternalChecks
	if got.Outcome != policyeval.Approve || got.OutcomeWord() != "approve" || ExpectOf(got) != (CaseExpect{Outcome: "approve"}) {
		t.Fatalf("outcome %s, word %q, expect %+v", got.Outcome, got.OutcomeWord(), ExpectOf(got))
	}
	if x.Refusal != nil || len(x.Pending) != 0 || len(x.Judged) != 3 {
		t.Fatalf("external = %+v", x)
	}
	wantLookups := []TryLookup{
		{Source: "ops", Path: opsPath, Checks: []string{"ops-switch"}},
		{Source: "screening", Path: screeningPath, Checks: []string{"screen-destination"}},
		{Source: "treasury", Path: treasuryPath, Checks: []string{"daily-allowance"}},
	}
	for i, l := range x.Lookups {
		if l.Source != wantLookups[i].Source || l.Path != wantLookups[i].Path || !slices.Equal(l.Checks, wantLookups[i].Checks) {
			t.Fatalf("lookup %d = %+v, want %+v", i, l, wantLookups[i])
		}
	}
	for _, j := range x.Judged {
		if !j.Passed || j.EchoUnverified != (j.Check == "daily-allowance") {
			t.Fatalf("judged %+v", j)
		}
	}
	if want := "this cosigner policy document permits the supplied transaction; external checks ops-switch, screen-destination and daily-allowance pass on the answers given"; got.Summary != want {
		t.Fatalf("summary = %q", got.Summary)
	}
	lines := strings.Join(x.Lines(), "\n")
	for _, want := range []string{
		"lookups the cosigner would make:\n  ops: GET " + opsPath + ", for ops-switch\n",
		"  screening: GET " + screeningPath + ", for screen-destination",
		"judged on the answers given:\n  ops-switch, the request: passes\n",
		"  daily-allowance, the pay movement of transaction 0: passes; its echo cannot be verified offline",
	} {
		if !strings.Contains(lines, want) {
			t.Fatalf("lines lack %q:\n%s", want, lines)
		}
	}
	if !slices.Contains(got.Assumes, "the request is for witness key "+extKey) {
		t.Fatalf("assumes = %v", got.Assumes)
	}
}

// A failing answer rejects, and the try shows what the cosigner's audit
// record would: the detail and the rendered request.
func TestTryAnswerThatFails(t *testing.T) {
	answers := passing()
	answers["screen-destination"] = one(`{"sanctioned": false, "risk": {"score": 72, "level": "low"}}`)
	got := tryWith(t, LoadFile(writeFile(t, t.TempDir(), "c.json", fixture(t, externalFixture))), mainnetPayment, answers)
	r := got.ExternalChecks.Refusal
	if got.Outcome != policyeval.Reject || got.OutcomeWord() != "reject" || r == nil || r.RuleID() != "external_check:screen-destination" {
		t.Fatalf("outcome %s, refusal %+v", got.Outcome, r)
	}
	if r.Detail != "/risk/score = 72, want le 30" || r.Path != screeningPath || r.Source != "screening" || r.Unit != "the pay movement of transaction 0" {
		t.Fatalf("refusal = %+v", r)
	}
	if e := ExpectOf(got); e.Outcome != "reject" || e.RuleID != "external_check:screen-destination" {
		t.Fatalf("expect = %+v", e)
	}
	v := got.Violations[0]
	if v.RuleID != r.RuleID() || !strings.Contains(v.Message, "GET "+screeningPath) || !strings.Contains(v.Message, "/risk/score = 72, want le 30") {
		t.Fatalf("violation = %+v", v)
	}
	if want := "this cosigner policy document permits the supplied transaction, but external check screen-destination refuses it"; got.Summary != want {
		t.Fatalf("summary = %q", got.Summary)
	}
	// Every answered unit is still judged and shown.
	if len(got.ExternalChecks.Judged) != 3 || !got.ExternalChecks.Judged[0].Passed || got.ExternalChecks.Judged[1].Passed {
		t.Fatalf("judged = %+v", got.ExternalChecks.Judged)
	}
}

// With an answer missing, the checks still decide: a conditional approve
// that names what passed and what is left.
func TestTryPartialAnswers(t *testing.T) {
	answers := passing()
	delete(answers, "daily-allowance")
	got := tryWith(t, LoadFile(writeFile(t, t.TempDir(), "c.json", fixture(t, externalFixture))), mainnetPayment, answers)
	x := got.ExternalChecks
	if got.OutcomeWord() != OutcomeConditionalApprove || x.Refusal != nil || len(x.Judged) != 2 || len(x.Pending) != 1 {
		t.Fatalf("word %q, external %+v", got.OutcomeWord(), x)
	}
	if p := x.Pending[0]; p.Check != "daily-allowance" || p.Source != "treasury" || p.Path != treasuryPath {
		t.Fatalf("pending = %+v", p)
	}
	if want := "external checks ops-switch and screen-destination pass on the answers given, then external check daily-allowance decides"; !strings.HasSuffix(got.Summary, want) {
		t.Fatalf("summary = %q", got.Summary)
	}
}

// A unit that lacks a fact its check uses is refused by the plan, before
// any lookup and with no answer given: rekey_to on a payment that does not
// rekey, and amount on a close-out.
func TestTryPlanRefusesWithoutAnswers(t *testing.T) {
	rekey := externalDoc(t, func(doc map[string]any) {
		addCheck(t, doc, `{"id": "rekey-target", "source": "ops", "scope": "transaction", "networks": ["*"],
			"path": "/rekey/{rekey_to}", "require": [{"pointer": "/ok", "op": "eq", "bool": true}]}`)
	})
	closeOut := externalDoc(t, func(doc map[string]any) {
		allowCloseOuts(doc)
		addCheck(t, doc, `{"id": "any-amount", "source": "ops", "scope": "movement", "networks": ["*"],
			"path": "/amount", "require": [{"pointer": "/max", "op": "ge", "fact": "amount"}]}`)
	})
	closing := mainnetPayment
	closing.CloseTo = tryAddr(9)
	for _, tt := range []struct {
		name   string
		f      *File
		txn    TryTxn
		rule   string
		detail string
	}{
		{"rekey_to on a payment", rekey, mainnetPayment, "external_check:rekey-target:missing_fact", "it has no rekey_to"},
		{"amount on a close-out", closeOut, closing, "external_check:any-amount:missing_fact", "it has no amount"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := tryWith(t, tt.f, tt.txn, nil)
			x := got.ExternalChecks
			if got.OutcomeWord() != "reject" || x.Refusal == nil || x.Refusal.RuleID() != tt.rule || x.Refusal.Detail != tt.detail {
				t.Fatalf("word %q, refusal %+v", got.OutcomeWord(), x.Refusal)
			}
			if len(x.Lookups) != 0 || len(x.Judged) != 0 || len(x.Pending) != 0 || ExpectOf(got).RuleID != tt.rule {
				t.Fatalf("external = %+v", x)
			}
			if x.Lines() != nil && strings.Contains(strings.Join(x.Lines(), "\n"), "lookups") {
				t.Fatalf("a refused plan lists lookups: %v", x.Lines())
			}
		})
	}
}

// Two checks that render one request share one lookup, as the cosigner
// merges them, and each is judged on the answer given for it.
func TestTryMergedLookupsAreJudgedPerCheck(t *testing.T) {
	f := externalDoc(t, func(doc map[string]any) {
		addCheck(t, doc, `{"id": "ops-level", "source": "ops", "scope": "request", "networks": ["*"],
			"path": "/signing/{witness_key}", "require": [{"pointer": "/level", "op": "le", "number": "3"}]}`)
	})
	answers := passing()
	answers["ops-switch"] = one(`{"enabled": true, "level": 9}`)
	got := tryWith(t, f, mainnetPayment, answers)
	x := got.ExternalChecks
	if len(x.Lookups) != 3 || !slices.Equal(x.Lookups[0].Checks, []string{"ops-switch", "ops-level"}) {
		t.Fatalf("lookups = %+v", x.Lookups)
	}
	if !strings.Contains(strings.Join(x.Lines(), "\n"), "  ops: GET "+opsPath+", for ops-switch, ops-level\n") {
		t.Fatalf("lines = %v", x.Lines())
	}
	if got.OutcomeWord() != OutcomeConditionalApprove || len(x.Pending) != 1 || x.Pending[0].Check != "ops-level" || x.Pending[0].Path != opsPath {
		t.Fatalf("word %q, pending %+v", got.OutcomeWord(), x.Pending)
	}
	answers["ops-level"] = one(`{"enabled": true, "level": 9}`)
	got = tryWith(t, f, mainnetPayment, answers)
	if r := got.ExternalChecks.Refusal; r == nil || r.RuleID() != "external_check:ops-level" || r.Detail != "/level = 9, want le 3" {
		t.Fatalf("refusal = %+v", r)
	}
}

// An answer the cosigner would refuse to read is a failed lookup, not
// judged: one over the source's size, and one with a duplicate key.
func TestTryUnreadableAnswerIsAFailedLookup(t *testing.T) {
	f := LoadFile(writeFile(t, t.TempDir(), "c.json", fixture(t, externalFixture)))
	for _, tt := range []struct {
		name, body, detail string
	}{
		{"oversize", `{"enabled": true, "pad": "` + strings.Repeat("x", policy.DefaultExternalRespBytes) + `"}`, "body over 65536 bytes"},
		{"a duplicate key", `{"enabled": true, "enabled": false}`, "the answer is not acceptable JSON: /enabled: duplicate key"},
		{"not JSON", `enabled`, "the answer is not acceptable JSON"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			answers := passing()
			answers["ops-switch"] = one(tt.body)
			got := tryWith(t, f, mainnetPayment, answers)
			r := got.ExternalChecks.Refusal
			if got.OutcomeWord() != "reject" || r == nil || r.RuleID() != "external_check:ops-switch:unavailable" || !strings.HasPrefix(r.Detail, tt.detail) {
				t.Fatalf("word %q, refusal %+v", got.OutcomeWord(), r)
			}
		})
	}
}

// A named failure refuses as the cosigner would, and in its order: a missing
// token before any lookup, a failed lookup before any rule.
func TestTryFailuresRefuseInTheCosignersOrder(t *testing.T) {
	f := LoadFile(writeFile(t, t.TempDir(), "c.json", fixture(t, externalFixture)))
	answers := ExternalAnswers{
		"ops-switch":         one(`{"enabled": false}`),
		"screen-destination": {Failure: "timeout"},
		"daily-allowance":    {Failure: "token_not_set"},
	}
	for _, want := range []struct{ rule, detail string }{
		{"external_check:daily-allowance:token_not_set", "no token set"},
		{"external_check:screen-destination:unavailable", "timeout after 2s"},
		{"external_check:ops-switch", "/enabled = false, want eq true"},
	} {
		got := tryWith(t, f, mainnetPayment, answers)
		if r := got.ExternalChecks.Refusal; r == nil || r.RuleID() != want.rule || r.Detail != want.detail {
			t.Fatalf("refusal = %+v, want %s: %s", r, want.rule, want.detail)
		}
		if len(got.ExternalChecks.Judged) != len(answers) {
			t.Fatalf("judged = %+v", got.ExternalChecks.Judged)
		}
		switch {
		case answers["daily-allowance"].Failure != "":
			delete(answers, "daily-allowance")
		default:
			delete(answers, "screen-destination")
		}
	}
	got := tryWith(t, f, mainnetPayment, ExternalAnswers{"daily-allowance": {Failure: "pin_mismatch"}})
	if r := got.ExternalChecks.Refusal; r == nil || r.RuleID() != "external_check:daily-allowance:unavailable" || r.Detail != "TLS pin mismatch" {
		t.Fatalf("pin mismatch refusal = %+v", r)
	}
}

// Answers by request path: each unit of a check gets its own answer, and a
// unit with none still decides.
func TestTryAnswersByPath(t *testing.T) {
	f := externalDoc(t, func(doc map[string]any) {
		allowCloseOuts(doc)
		addCheck(t, doc, `{"id": "close-screen", "source": "screening", "scope": "movement", "networks": ["*"],
			"movement_kinds": ["pay", "pay_close"], "path": "/close/{destination}", "require": [{"pointer": "/ok", "op": "eq", "bool": true}]}`)
	})
	closing := mainnetPayment
	closing.CloseTo = tryAddr(9)
	toReceiver, toClose := "/api/close/"+extReceiver, "/api/close/"+tryAddr(9)
	answers := passing()
	answers["close-screen"] = CheckAnswer{ByPath: map[string][]byte{toReceiver: []byte(`{"ok": true}`)}}
	got := tryWith(t, f, closing, answers)
	x := got.ExternalChecks
	if got.OutcomeWord() != OutcomeConditionalApprove || len(x.Pending) != 1 || x.Pending[0].Path != toClose {
		t.Fatalf("word %q, pending %+v, judged %+v", got.OutcomeWord(), x.Pending, x.Judged)
	}
	answers["close-screen"].ByPath[toClose] = []byte(`{"ok": false}`)
	got = tryWith(t, f, closing, answers)
	if r := got.ExternalChecks.Refusal; r == nil || r.RuleID() != "external_check:close-screen" || r.Path != toClose || r.Unit != "the pay_close movement of transaction 0" {
		t.Fatalf("refusal = %+v", r)
	}
	answers["close-screen"].ByPath["/api/close/nobody"] = []byte(`{}`)
	if _, err := TryWithAnswers(f, closing, answers, BuiltinNetworks()); err == nil || !strings.Contains(err.Error(), "makes no lookup /api/close/nobody") {
		t.Fatalf("an answer for a request the check never makes: %v", err)
	}
}

// An answer that names no check of the document, a check that does not
// apply, or a failure the source cannot have is refused.
func TestTryRefusesAnswersThatCannotApply(t *testing.T) {
	f := LoadFile(writeFile(t, t.TempDir(), "c.json", fixture(t, externalFixture)))
	testnet := mainnetPayment
	testnet.Network = "testnet"
	for _, tt := range []struct {
		name    string
		f       *File
		txn     TryTxn
		answers ExternalAnswers
		want    string
	}{
		{"no such check", f, mainnetPayment, ExternalAnswers{"nope": one(`{}`)}, "this document has no external check nope (its checks: ops-switch, screen-destination, daily-allowance)"},
		{"a check that does not apply", f, testnet, ExternalAnswers{"screen-destination": one(`{}`)}, "external check screen-destination does not apply to this transaction (applying: ops-switch)"},
		{"a document without checks", LoadFile(writeFile(t, t.TempDir(), "s.json", fixture(t, "signer_key_full.json"))), mainnetPayment, ExternalAnswers{"x": one(`{}`)}, "this document has no external checks to answer"},
		{"a pin mismatch without pins", f, mainnetPayment, ExternalAnswers{"ops-switch": {Failure: "pin_mismatch"}}, "pins no server key"},
		{"a missing token for a source without one", f, mainnetPayment, ExternalAnswers{"ops-switch": {Failure: "token_not_set"}}, "takes no token"},
		{"an unknown failure", f, mainnetPayment, ExternalAnswers{"ops-switch": {Failure: "slow"}}, `"slow" is not a lookup failure`},
		{"two forms", f, mainnetPayment, ExternalAnswers{"ops-switch": {Answer: []byte(`{}`), Failure: "timeout"}}, "exactly one of"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := TryWithAnswers(tt.f, tt.txn, tt.answers, BuiltinNetworks()); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("TryWithAnswers() error = %v, want %q", err, tt.want)
			}
		})
	}
	// A policy rejection reaches no check, so its answers are not judged.
	expensive := mainnetPayment
	expensive.Fee = 9000
	if got := tryWith(t, f, expensive, passing()); got.Outcome != policyeval.Reject || got.ExternalChecks != nil {
		t.Fatalf("a policy rejection: %+v", got)
	}
}

func TestParseAnswerArgs(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "a.json", []byte(`{"enabled": true}`))
	empty := writeFile(t, dir, "empty.json", nil)
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(strings.Repeat(" ", policy.MaxExternalResponseBytes+10)), 0o600); err != nil {
		t.Fatal(err)
	}
	answers, err := ParseAnswerArgs([]string{"ops-switch=" + path, "screen-destination=" + empty, "daily-allowance=" + big})
	if err != nil {
		t.Fatal(err)
	}
	if string(answers["ops-switch"].Answer) != `{"enabled": true}` || answers["screen-destination"].Answer == nil ||
		len(answers["daily-allowance"].Answer) != policy.MaxExternalResponseBytes+1 {
		t.Fatalf("answers = %v", answers)
	}
	for _, args := range [][]string{{"ops-switch"}, {"=" + path}, {"ops-switch="}, {"a=" + path, "a=" + path}, {"a=" + filepath.Join(dir, "none.json")}} {
		if _, err := ParseAnswerArgs(args); err == nil {
			t.Errorf("ParseAnswerArgs(%q) accepted", args)
		}
	}
}

// A case may answer its checks, by one answer, by request path, or by a
// named failure, and runs through the same try.
func TestCasesWithAnswersAndFailures(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "cosigner.json", fixture(t, externalFixture))
	txn := CaseTxn{Network: "mainnet", Sender: extSender, Receiver: extReceiver, Amount: 5}
	raw := func(s string) json.RawMessage { return json.RawMessage(s) }
	all := map[string]CaseAnswer{
		"ops-switch":         {Answer: raw(`{"enabled": true}`)},
		"screen-destination": {ByPath: map[string]json.RawMessage{screeningPath: raw(`{"sanctioned": false, "risk": {"score": 3, "level": "low"}}`)}},
		"daily-allowance":    {Answer: raw(`{"remaining": 5, "request_id": "x"}`)},
	}
	cases := []Case{
		{Name: "all pass", Document: "cosigner.json", Txn: txn, Answers: all, Expect: CaseExpect{Outcome: "approve"}},
		{Name: "the treasury times out", Document: "cosigner.json", Txn: txn,
			Answers:  map[string]CaseAnswer{"ops-switch": all["ops-switch"], "screen-destination": all["screen-destination"]},
			Failures: map[string]string{"daily-allowance": "timeout"},
			Expect:   CaseExpect{Outcome: "reject", RuleID: "external_check:daily-allowance:unavailable"}},
		{Name: "no token for the treasury", Document: "cosigner.json", Txn: txn,
			Failures: map[string]string{"daily-allowance": "token_not_set"},
			Expect:   CaseExpect{Outcome: "reject", RuleID: "external_check:daily-allowance:token_not_set"}},
		{Name: "a duplicate key", Document: "cosigner.json", Txn: txn,
			Answers: map[string]CaseAnswer{"ops-switch": {Answer: raw(`{"enabled": true, "enabled": true}`)}},
			Expect:  CaseExpect{Outcome: "reject", RuleID: "external_check:ops-switch:unavailable"}},
		{Name: "a null answer", Document: "cosigner.json", Txn: txn,
			Answers: map[string]CaseAnswer{"ops-switch": {Answer: raw(`null`)}},
			Expect:  CaseExpect{Outcome: "reject", RuleID: "external_check:ops-switch"}},
		{Name: "still deciding", Document: "cosigner.json", Txn: txn, Expect: CaseExpect{Outcome: OutcomeConditionalApprove}},
		{Name: "an answer for no check", Document: "cosigner.json", Txn: txn,
			Answers: map[string]CaseAnswer{"nope": {Answer: raw(`{}`)}}, Expect: CaseExpect{Outcome: "approve"}},
	}
	cf := &CaseFile{}
	for _, c := range cases {
		if err := cf.Add(c); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
	}
	if err := cf.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCases(dir)
	if err != nil {
		t.Fatal(err)
	}
	results := RunCases(loaded.Cases, DiskDocuments(dir), BuiltinNetworks())
	for i, r := range results {
		last := i == len(results)-1
		switch {
		case last && (r.Err == nil || !strings.Contains(r.Err.Error(), "no external check nope")):
			t.Errorf("%s: err %v, want the unknown check refused", r.Case.Name, r.Err)
		case !last && (r.Err != nil || !r.Passed):
			t.Errorf("%s: got %+v, err %v", r.Case.Name, ExpectOf(r.Got), r.Err)
		}
	}
	// The saved file keeps each answer's literal text.
	data, err := os.ReadFile(CasesPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"answers": {`, `"by_path": {`, `"failures": {`, `"daily-allowance": "timeout"`, `"enabled": true,`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("cases file lacks %q:\n%s", want, data)
		}
	}
}

// The cases file is checked strictly when it is read.
func TestCasesFileRefusesMalformedAnswers(t *testing.T) {
	base := `{"format": "aplane.policy-cases.v1", "cases": [{"name": "c", "document": "d.json", "txn": {"sender": "A", "receiver": "B"}, %s "expect": {"outcome": "approve"}}]}`
	for _, tt := range []struct {
		name, fields, want string
	}{
		{"an answer and a failure for one check", `"answers": {"a": {"answer": {}}}, "failures": {"a": "timeout"},`, "both an answer and a failure"},
		{"an answer in two forms", `"answers": {"a": {"answer": {}, "by_path": {"/x": {}}}},`, `exactly one of "answer" and "by_path"`},
		{"an answer in neither form", `"answers": {"a": {}},`, `exactly one of "answer" and "by_path"`},
		{"the answer written bare", `"answers": {"a": {"enabled": true}},`, `unknown field "enabled"`},
		{"by_path naming nothing", `"answers": {"a": {"by_path": {}}},`, "names no request"},
		{"by_path that is not a path", `"answers": {"a": {"by_path": {"x": {}}}},`, "is not a request path"},
		{"an unknown failure", `"failures": {"a": "slow"},`, `failure "slow" for external check a is not one of timeout`},
		{"a failure that is not a name", `"failures": {"a": 5},`, "cannot unmarshal"},
		{"an empty check ID", `"failures": {"": "timeout"},`, "names no check"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, ".appolicy"), 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(dir, ".appolicy"), "cases.json", []byte(strings.Replace(base, "%s", tt.fields, 1)))
			if _, err := LoadCases(dir); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LoadCases() error = %v, want %q", err, tt.want)
			}
		})
	}
}

// A try kept as a case keeps its answers; an answer the cosigner could not
// read is kept as the failure it stands for.
func TestCaseOfKeepsTheAnswers(t *testing.T) {
	f := LoadFile(writeFile(t, t.TempDir(), "c.json", fixture(t, externalFixture)))
	answers := passing()
	answers["screen-destination"] = one(`not json`)
	answers["daily-allowance"] = one(`{"pad": "` + strings.Repeat("x", 1<<17) + `"}`)
	got := tryWith(t, f, mainnetPayment, answers)
	c := CaseOf("kept", "c.json", f, mainnetPayment, answers, got)
	if string(c.Answers["ops-switch"].Answer) != `{"enabled": true}` || len(c.Answers) != 1 ||
		c.Failures["screen-destination"] != "not_json" || c.Failures["daily-allowance"] != "too_large" {
		t.Fatalf("case = %+v", c)
	}
	if c.Expect != (CaseExpect{Outcome: "reject", RuleID: "external_check:screen-destination:unavailable"}) {
		t.Fatalf("expect = %+v", c.Expect)
	}
	// Run again, it gets the answer it was saved with.
	dir := filepath.Dir(f.Path)
	cf := &CaseFile{}
	if err := cf.Add(c); err != nil {
		t.Fatal(err)
	}
	if err := cf.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCases(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r := RunCases(loaded.Cases, DiskDocuments(dir), BuiltinNetworks()); r[0].Err != nil || !r[0].Passed {
		t.Fatalf("rerun = %+v", r[0])
	}
}
