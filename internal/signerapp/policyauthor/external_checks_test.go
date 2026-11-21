// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"
)

const externalFixture = "cosigner_key_external_checks.json"

func TestExplainExternalChecks(t *testing.T) {
	out := explainFixture(t, externalFixture, nil)
	assertLines(t, out,
		"External checks: asked only when this document would sign; a check can only refuse\nSources:\n  ops: http://127.0.0.1:8650, no token\n",
		"  screening: https://screen.example.com/api, with a token\n",
		"  treasury: https://treasury.internal.example:8443, with a token, pinned to 1 server key\n",
		"  ops-switch: once per request, on any network\n    asks ops: GET /signing/{witness_key}\n    refuses unless /enabled is true\n",
		"  screen-destination: for each pay or axfer movement, on mainnet\n    Screening for every payment out on mainnet\n",
		"    asks screening: GET /api/v2/addresses/{destination}?chain=algorand\n    refuses unless all of these hold:\n",
		"      /sanctioned is false\n      /risk/score is at most 30\n      /risk/level is one of \"low\", \"medium\"\n",
		"    asks treasury: GET /allowance/{source}/{asset}\n",
		"      /request_id is the request ID the cosigner sent\n      /remaining is at least the movement's amount\n      /frozen is absent\n",
	)
	if strings.Contains(out, "cannot keep") || strings.Contains(out, "is refused") {
		t.Errorf("the explanation says a token cannot be kept:\n%s", out)
	}
	if strings.Index(out, "External checks:") > strings.Index(out, "Routes match a transaction's sender") {
		t.Errorf("the checks come after the closing line:\n%s", out)
	}
	for _, name := range []string{"cosigner_key_full.json", "signer_key_full.json"} {
		if out := explainFixture(t, name, nil); strings.Contains(out, "External checks") || strings.Contains(out, "external checks") {
			t.Errorf("%s has no checks, yet its explanation mentions them:\n%s", name, out)
		}
	}
}

func TestExternalCheckWords(t *testing.T) {
	str, num, yes := "a", "5", true
	for _, tt := range []struct {
		rule policy.ExternalRuleV1
		want string
	}{
		{policy.ExternalRuleV1{Pointer: "/x", Op: policy.ExternalOpNe, String: &str}, `/x is not "a"`},
		{policy.ExternalRuleV1{Pointer: "/x", Op: policy.ExternalOpLt, Number: &num}, "/x is less than 5"},
		{policy.ExternalRuleV1{Pointer: "/x", Op: policy.ExternalOpGt, Fact: "fee"}, "/x is more than the transaction's fee"},
		{policy.ExternalRuleV1{Pointer: "/x", Op: policy.ExternalOpEq, Bool: &yes}, "/x is true"},
		{policy.ExternalRuleV1{Pointer: "/x", Op: policy.ExternalOpNotIn, Numbers: []string{"1", "2"}}, "/x is not one of 1, 2"},
		{policy.ExternalRuleV1{Pointer: "/to", Op: policy.ExternalOpEq, Fact: "destination"}, "/to is the movement's destination"},
		{policy.ExternalRuleV1{Pointer: "", Op: policy.ExternalOpPresent}, "the whole answer is present"},
	} {
		if got := externalRuleWords(tt.rule); got != tt.want {
			t.Errorf("externalRuleWords(%+v) = %q, want %q", tt.rule, got, tt.want)
		}
	}
	for _, tt := range []struct {
		check policy.ExternalCheckV1
		want  string
	}{
		{policy.ExternalCheckV1{Scope: policy.ExternalScopeTransaction}, "for each transaction this cosigner signs"},
		{policy.ExternalCheckV1{Scope: policy.ExternalScopeMovement}, "for each movement of a payment or asset transfer this cosigner signs"},
		{policy.ExternalCheckV1{Scope: policy.ExternalScopeMovement, MovementKinds: []policy.TransferMovementKind{"pay", "pay_close", "clawback"}}, "for each pay, pay_close or clawback movement"},
	} {
		if got := externalScopeWords(tt.check); got != tt.want {
			t.Errorf("externalScopeWords(%+v) = %q, want %q", tt.check, got, tt.want)
		}
	}
	if got := externalNetworkWords(policy.ExternalCheckV1{Networks: []string{"mainnet", "testnet"}}); got != "on mainnet or testnet" {
		t.Errorf("networks = %q", got)
	}
}

func sectionTitles(sections []Section) string {
	var titles []string
	for _, s := range sections {
		titles = append(titles, strings.Repeat("  ", s.Depth)+s.Title)
	}
	return strings.Join(titles, "\n")
}

func TestOutlineExternalSections(t *testing.T) {
	_, sections := outlineFixture(t, externalFixture)
	want := "External sources (3)\n  Source screening\n  Source ops\n  Source treasury\nExternal checks (3)\n  Check ops-switch\n  Check screen-destination\n  Check daily-allowance"
	if got := sectionTitles(sections); !strings.HasSuffix(got, want) {
		t.Fatalf("outline ends\n%s\nwant it to end\n%s", got, want)
	}
	for _, s := range sections {
		if s.ID == "other" {
			t.Fatalf("a field lands under Other fields: %+v", s.Fields)
		}
	}
	for pointer, want := range map[string]struct {
		value string
		edit  EditKind
	}{
		"/external_sources/screening/base_url":           {"https://screen.example.com/api", EditText},
		"/external_sources/screening/token/header":       {"Authorization", EditText},
		"/external_sources/screening/token/prefix":       {`"Bearer "`, EditVerbatim},
		"/external_sources/screening/timeout_ms":         {"2000", EditInteger},
		"/external_sources/screening/max_response_bytes": {"65536", EditInteger},
		"/external_sources/treasury/tls_spki_sha256":     {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", EditTerms},
		"/external_checks/1/id":                          {"screen-destination", EditText},
		"/external_checks/1/source":                      {"screening", EditChoice},
		"/external_checks/1/scope":                       {"movement", EditChoice},
		"/external_checks/1/networks":                    {"mainnet", EditTerms},
		"/external_checks/1/movement_kinds":              {"pay, axfer", EditTerms},
		"/external_checks/1/path":                        {"/v2/addresses/{destination}", EditText},
		"/external_checks/1/query/chain":                 {"algorand", EditText},
		"/external_checks/2/echo_pointer":                {"/request_id", EditText},
		"/external_checks/1/require/1":                   {`{"pointer": "/risk/score", "op": "le", "number": "30"}`, EditJSON},
	} {
		_, f, ok := findField(sections, pointer)
		if !ok || f.Value != want.value || f.Edit == nil || f.Edit.Kind != want.edit {
			t.Errorf("%s = %+v (found %v), want value %q edited as %s", pointer, f, ok, want.value, want.edit)
		}
	}
	_, source, _ := findField(sections, "/external_checks/1/source")
	if fmt.Sprint(source.Edit.Choices) != "[screening ops treasury]" {
		t.Errorf("source choices = %v, want the document's sources", source.Edit.Choices)
	}
	_, scope, _ := findField(sections, "/external_checks/1/scope")
	if fmt.Sprint(scope.Edit.Choices) != "[request transaction movement]" {
		t.Errorf("scope choices = %v", scope.Edit.Choices)
	}
	_, rule, _ := findField(sections, "/external_checks/2/require/0")
	if rule.Note != "/remaining is at least the movement's amount" || rule.Remove == nil || rule.Copy == nil {
		t.Errorf("rule field = %+v", rule)
	}
	// A request check has no movement kinds to set.
	if _, _, ok := findField(sections, "/external_checks/0/movement_kinds"); ok {
		t.Error("a request check offers movement kinds")
	}
	// A source without a token says so, and offers one.
	s, token, ok := findField(sections, "/external_sources/ops/token")
	if !ok || !token.Absent || token.Note != "no token is sent" || len(s.Adds) != 1 || s.Adds[0].Label != "Add a token" {
		t.Errorf("ops token = %+v in %+v", token, s)
	}
	// The plain-http advisory lands on the URL it is about.
	_, http, _ := findField(sections, "/external_sources/ops/base_url")
	if len(http.Problems) != 1 || http.Problems[0].Severity != SeverityWarning || !strings.Contains(http.Problems[0].Message, "plain http") {
		t.Errorf("ops base_url problems = %+v", http.Problems)
	}
}

// A rule is one JSON value, so a decoder error inside it lands on its field.
func TestExternalRuleErrorsLandOnTheRule(t *testing.T) {
	_, sections := outlineFixture(t, "invalid/cosigner_external_bad_op.json")
	_, rule, ok := findField(sections, "/external_checks/0/require/0")
	if !ok || len(rule.Problems) != 1 || !strings.Contains(rule.Problems[0].Message, "must be one of eq") || rule.Note != "" {
		t.Fatalf("rule = %+v (found %v)", rule, ok)
	}
}

func TestSignerOutlineHasNoExternalSections(t *testing.T) {
	_, sections := outlineFixture(t, "invalid/signer_external_checks.json")
	for _, s := range sections {
		if strings.HasPrefix(s.ID, "external") {
			t.Fatalf("a signer outline has section %q", s.Title)
		}
	}
	for _, pointer := range []string{"/external_sources", "/external_checks"} {
		s, f, ok := findField(sections, pointer)
		if !ok || s.Title != "Other fields" || !f.Unknown || f.Note != "not a field of a signer document" {
			t.Errorf("%s = %+v in %q (found %v)", pointer, f, s.Title, ok)
		}
	}
	_, signer := outlineFixture(t, "signer_key_full.json")
	if strings.Contains(sectionTitles(signer), "External") {
		t.Fatalf("a signer outline offers external sections:\n%s", sectionTitles(signer))
	}
	// A cosigner document without checks offers them, empty.
	_, cosigner := outlineFixture(t, "cosigner_key_minimal.json")
	if titles := sectionTitles(cosigner); !strings.Contains(titles, "External sources (0)") || !strings.Contains(titles, "External checks (0)") {
		t.Fatalf("a cosigner outline lacks the external sections:\n%s", titles)
	}
}

// outlineDraft lays out a cosigner draft as the editor would.
func outlineDraft(d *policy.Draft) []Section {
	return Outline(&File{Draft: d, Role: noderole.RoleCosigner}, nil, nil)
}

func sectionByID(t *testing.T, sections []Section, id string) Section {
	t.Helper()
	for _, s := range sections {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no section %s in\n%s", id, sectionTitles(sections))
	return Section{}
}

func addAction(t *testing.T, s Section, label string) AddAction {
	t.Helper()
	for _, a := range s.Adds {
		if a.Label == label {
			return a
		}
	}
	t.Fatalf("section %s has no %q", s.Title, label)
	return AddAction{}
}

func TestExternalRemovals(t *testing.T) {
	f := LoadFile(writeFile(t, t.TempDir(), "c.json", fixture(t, externalFixture)))
	sections := Outline(f, nil, nil)
	field := func(pointer string) Field {
		t.Helper()
		_, fl, ok := findField(sections, pointer)
		if !ok {
			t.Fatalf("no field %s", pointer)
		}
		return fl
	}
	for _, tt := range []struct {
		removal *Removal
		gone    string
	}{
		{sectionByID(t, sections, "external_source:ops").Remove, "/external_sources/ops"},
		{sectionByID(t, sections, "external_check:0").Remove, "/external_checks/0/id"},
		{field("/external_checks/1/require/2").Remove, "/external_checks/1/require/2"},
		// A token needs its header, and a query its only parameter.
		{field("/external_sources/screening/token/header").Remove, "/external_sources/screening/token"},
		{field("/external_sources/screening/token/prefix").Remove, "/external_sources/screening/token/prefix"},
		{field("/external_checks/1/query/chain").Remove, "/external_checks/1/query"},
		{field("/external_sources/treasury/tls_spki_sha256").Remove, "/external_sources/treasury/tls_spki_sha256"},
	} {
		if tt.removal == nil {
			t.Fatalf("no removal for %s", tt.gone)
		}
		next, err := tt.removal.Apply(f.Draft)
		if err != nil {
			t.Fatalf("%s: %v", tt.removal.Label, err)
		}
		if tt.gone == "/external_checks/0/id" {
			// The next check moved into the removed one's place.
			if next.At(tt.gone).Text() != "screen-destination" {
				t.Errorf("%s: check 0 is %q", tt.removal.Label, next.At(tt.gone).Text())
			}
			continue
		}
		if next.At(tt.gone).Exists() {
			t.Errorf("%s: %s still present", tt.removal.Label, tt.gone)
		}
	}
}

// TestExternalChecksBuiltFromTheOutline adds a source, a token, a check, a
// rule and a query parameter through the outline's own actions and fields,
// and the result is a document the decoder accepts.
func TestExternalChecksBuiltFromTheOutline(t *testing.T) {
	d := LoadFile(writeFile(t, t.TempDir(), "m.json", fixture(t, "cosigner_key_minimal.json"))).Draft
	add := func(section, label, input string) {
		t.Helper()
		next, err := addAction(t, sectionByID(t, outlineDraft(d), section), label).Apply(d, input)
		if err != nil {
			t.Fatalf("%s %q: %v", label, input, err)
		}
		d = next
	}
	set := func(pointer, input string) {
		t.Helper()
		_, f, ok := findField(outlineDraft(d), pointer)
		if !ok || f.Edit == nil {
			t.Fatalf("no editable field %s", pointer)
		}
		value, err := f.Edit.Value(input, 0, false)
		if err != nil {
			t.Fatalf("%s %q: %v", pointer, input, err)
		}
		if d, err = d.Set(f.Edit.Pointer, value); err != nil {
			t.Fatal(err)
		}
	}
	add("external_sources", "Add a source", "ops http://127.0.0.1:8650")
	add("external_source:ops", "Add a token", "Authorization")
	set("/external_sources/ops/token/prefix", "Bearer ")
	set("/external_sources/ops/timeout_ms", "1500")
	add("external_checks", "Add a check", "ops-switch ops")
	set("/external_checks/0/networks", "*")
	set("/external_checks/0/path", "/signing/{witness_key}")
	add("external_check:0", "Add a rule", "/enabled")
	set("/external_checks/0/require/0", `{"pointer": "/enabled", "op": "eq", "bool": true}`)
	add("external_check:0", "Add a query parameter", "for=aplane")
	set("/external_checks/0/scope", "movement")
	set("/external_checks/0/movement_kinds", "pay, axfer")

	data, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	f := LoadFile(writeFile(t, t.TempDir(), "built.json", data))
	if f.Document == nil {
		t.Fatalf("built document does not decode: %+v\n%s", f.Problems, data)
	}
	src, check := f.Document.ExternalSources["ops"], f.Document.ExternalChecks[0]
	if src.Token == nil || src.Token.Header != "Authorization" || src.Token.Prefix != "Bearer " || src.TimeoutMS != 1500 {
		t.Errorf("source = %+v", src)
	}
	if check.ID != "ops-switch" || !check.NetworkWildcard || check.Scope != policy.ExternalScopeMovement ||
		len(check.MovementKinds) != 2 || check.Path.Text != "/signing/{witness_key}" ||
		len(check.Query) != 1 || check.Query[0].Name != "for" || len(check.Require) != 1 || check.Require[0].Bool == nil {
		t.Errorf("check = %+v", check)
	}

	// Bad input is refused, and nothing is added twice.
	minimal := LoadFile(writeFile(t, t.TempDir(), "m.json", fixture(t, "cosigner_key_minimal.json"))).Draft
	built := outlineDraft(d)
	for _, tt := range []struct {
		section, label, input string
		draft                 *policy.Draft
	}{
		{"external_sources", "Add a source", "Bad! http://127.0.0.1", minimal},
		{"external_sources", "Add a source", "ops", minimal},
		{"external_sources", "Add a source", "ops http://127.0.0.1:9", d},
		{"external_checks", "Add a check", "only-an-id", minimal},
		{"external_check:0", "Add a rule", "enabled", d},
		{"external_check:0", "Add a query parameter", "novalue", d},
		{"external_check:0", "Add a query parameter", "for=again", d},
	} {
		if _, err := addAction(t, sectionByID(t, built, tt.section), tt.label).Apply(tt.draft, tt.input); err == nil {
			t.Errorf("%s %q accepted", tt.label, tt.input)
		}
	}
	tokenAdd := externalTokenAdd("/external_sources/ops/token")
	for _, input := range []string{"", "Two Words", "Header:"} {
		if _, err := tokenAdd.Apply(minimal, input); err == nil {
			t.Errorf("Add a token %q accepted", input)
		}
	}
}

func TestExternalEditKindsAndTerms(t *testing.T) {
	for _, tt := range []struct {
		spec  EditSpec
		input string
		want  string
	}{
		{EditSpec{Kind: EditInteger}, " 65,536 ", "65536"},
		{EditSpec{Kind: EditVerbatim}, "Bearer ", `"Bearer "`},
		{EditSpec{Kind: EditJSON}, ` {"op": "absent"} `, `{"op": "absent"}`},
		{EditSpec{Kind: EditTerms, Term: TermMovement}, "pay, axfer_optin", `["pay","axfer_optin"]`},
		{EditSpec{Kind: EditTerms, Term: TermTLSPin}, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", `["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]`},
	} {
		got, err := tt.spec.Value(tt.input, 0, false)
		if err != nil || string(got) != tt.want {
			t.Errorf("%s %q = %s, %v; want %s", tt.spec.Kind, tt.input, got, err, tt.want)
		}
	}
	for _, tt := range []struct {
		spec  EditSpec
		input string
	}{
		{EditSpec{Kind: EditInteger}, "-1"},
		{EditSpec{Kind: EditInteger}, "2.5"},
		{EditSpec{Kind: EditJSON}, `{"op": `},
		{EditSpec{Kind: EditJSON}, `{"op": 1, "op": 2}`},
		{EditSpec{Kind: EditTerms, Term: TermMovement}, "pay, teleport"},
		{EditSpec{Kind: EditTerms, Term: TermTLSPin}, "AAAA"},
		{EditSpec{Kind: EditTerms, Term: TermTLSPin}, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	} {
		if got, err := tt.spec.Value(tt.input, 0, false); err == nil {
			t.Errorf("%s %s %q accepted as %s", tt.spec.Kind, tt.spec.Term, tt.input, got)
		}
	}
	d := LoadFile(writeFile(t, t.TempDir(), "c.json", fixture(t, externalFixture))).Draft
	if got := (EditSpec{Term: TermMovement}).Suggestions(d); fmt.Sprint(got) != fmt.Sprint(movementKindNames()) {
		t.Errorf("movement kind suggestions = %v", got)
	}
	// A rule's editor starts from JSON, whatever its strings hold.
	tricky := `{"pointer": "/a\u0001b", "op": "eq", "string": "<\"x\">"}`
	td, err := policy.ParseDraft([]byte(tricky))
	if err != nil {
		t.Fatal(err)
	}
	spec := EditSpec{Kind: EditJSON, Pointer: ""}
	input := spec.Input(td.Root(), 0, false)
	if _, err := spec.Value(input, 0, false); err != nil {
		t.Fatalf("the editor's own input %q is refused: %v", input, err)
	}
	// and its copy is the same rule.
	doc := strings.Replace(string(fixture(t, externalFixture)), `"pointer": "/enabled"`, `"pointer": "/en\u0001abled"`, 1)
	cf := LoadFile(writeFile(t, t.TempDir(), "c.json", []byte(doc)))
	_, rule, ok := findField(Outline(cf, nil, nil), "/external_checks/0/require/0")
	if !ok || rule.Copy == nil {
		t.Fatal("a rule has no copy action")
	}
	next, err := rule.Copy.Apply(cf.Draft, "")
	if err != nil {
		t.Fatalf("copy a rule: %v", err)
	}
	if got := next.At("/external_checks/0/require/1/pointer").Text(); got != "/en\x01abled" {
		t.Fatalf("copied rule pointer = %q", got)
	}
}

func TestTryExternalChecksDecideAfterThePolicy(t *testing.T) {
	f := LoadFile(writeFile(t, t.TempDir(), "c.json", fixture(t, externalFixture)))
	permits := "this cosigner policy document permits the supplied transaction"
	for _, tt := range []struct {
		name  string
		txn   TryTxn
		apply []string
		next  string
	}{
		{"a mainnet payment", TryTxn{Network: "mainnet", Sender: tryAddr(1), Receiver: tryAddr(2), Amount: 5, Fee: 1000},
			[]string{"ops-switch", "screen-destination", "daily-allowance"}, "then external checks ops-switch, screen-destination and daily-allowance decide"},
		{"a testnet payment", TryTxn{Network: "testnet", Sender: tryAddr(1), Receiver: tryAddr(2), Amount: 5, Fee: 1000},
			[]string{"ops-switch"}, "then external check ops-switch decides"},
		// An opt-in is a movement of a kind the movement checks leave out.
		{"a mainnet opt-in", TryTxn{Network: "mainnet", Sender: tryAddr(1), Receiver: tryAddr(1), Asset: 7, Fee: 1000},
			[]string{"ops-switch"}, "then external check ops-switch decides"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Try(f, tt.txn, BuiltinNetworks())
			if err != nil {
				t.Fatal(err)
			}
			x := got.ExternalChecks
			if got.Outcome != policyeval.Approve || x == nil || !slices.Equal(x.Apply, tt.apply) {
				t.Fatalf("Try() = %+v, external %+v; want approve, then %v", got, x, tt.apply)
			}
			if want := permits + "; " + tt.next; got.Summary != want {
				t.Fatalf("summary = %q, want %q", got.Summary, want)
			}
		})
	}

	// No check applies: the policy's verdict stands.
	none := strings.Replace(string(fixture(t, externalFixture)), `"networks": [
        "*"
      ],
      "path": "/signing/{witness_key}"`, `"networks": [
        "mainnet"
      ],
      "path": "/signing/{witness_key}"`, 1)
	got, err := Try(writeTryDoc(t, none), TryTxn{Network: "testnet", Sender: tryAddr(1), Receiver: tryAddr(2), Amount: 5, Fee: 1000}, BuiltinNetworks())
	if err != nil {
		t.Fatal(err)
	}
	if got.ExternalChecks == nil || len(got.ExternalChecks.Apply) != 0 || got.Summary != permits+"; no external check applies to it" {
		t.Fatalf("Try() with no check applying = %+v, summary %q", got.ExternalChecks, got.Summary)
	}

	// A rejection never reaches the checks.
	got, err = Try(f, TryTxn{Network: "mainnet", Sender: tryAddr(1), Receiver: tryAddr(2), Amount: 5, Fee: 9000}, BuiltinNetworks())
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != policyeval.Reject || got.ExternalChecks != nil || strings.Contains(got.Summary, "external") {
		t.Fatalf("Try(rejected) = %+v", got)
	}
	// A document without checks permits as before.
	plain := LoadFile(writeFile(t, t.TempDir(), "p.json", fixture(t, "cosigner_key_full.json")))
	if got, err := Try(plain, TryTxn{Network: "mainnet", Sender: tryAddr(1), Receiver: tryAddr(1), Fee: 1000}, BuiltinNetworks()); err != nil || got.ExternalChecks != nil || strings.Contains(got.Summary, "external") {
		t.Fatalf("Try(no checks) = %+v, %v", got, err)
	}
}

// A try the policy approves is a conditional approve when a check applies,
// and a plain approve when none does. A saved case records the same word and
// is accepted back.
func TestTryOutcomeWordWithExternalChecks(t *testing.T) {
	f := LoadFile(writeFile(t, t.TempDir(), "c.json", fixture(t, externalFixture)))
	got, err := Try(f, TryTxn{Network: "mainnet", Sender: tryAddr(1), Receiver: tryAddr(2), Amount: 5, Fee: 1000}, BuiltinNetworks())
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != policyeval.Approve || got.OutcomeWord() != OutcomeConditionalApprove || ExpectOf(got).Outcome != "conditional_approve" {
		t.Fatalf("outcome = %s, word %q, case %q; want approve, conditional_approve", got.Outcome, got.OutcomeWord(), ExpectOf(got).Outcome)
	}
	for _, r := range []TryResult{
		{Outcome: policyeval.Approve},
		{Outcome: policyeval.Approve, ExternalChecks: &TryExternalChecks{}},
		{Outcome: policyeval.Reject, ExternalChecks: &TryExternalChecks{Apply: []string{"c"}}},
	} {
		if word := r.OutcomeWord(); word != r.Outcome.String() {
			t.Errorf("OutcomeWord() = %q for %+v, want %q", word, r, r.Outcome)
		}
	}
}
