// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package chainread

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

// staticIndexer answers every request with body, from memory, so what a
// lookup allocates is the lookup's own work. It counts the requests.
type staticIndexer struct {
	body     []byte
	requests *atomic.Int32
}

func (s staticIndexer) RoundTrip(req *http.Request) (*http.Response, error) {
	s.requests.Add(1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(s.body)),
		Request:    req,
	}, nil
}

func staticReader(body []byte, requests *atomic.Int32) Reader {
	return Reader{
		Resolver: apconfig.DefaultGenesisHashNetworkResolver,
		IndexerConfig: func(string) *apconfig.IndexerNetworkConfig {
			return &apconfig.IndexerNetworkConfig{Server: "http://indexer.test", Token: indexerToken}
		},
		IndexerTransport: staticIndexer{body: body, requests: requests},
	}
}

// lookupAllocation runs one lookup against body and reports its outcome and
// the bytes allocated meanwhile (the most of three runs).
func lookupAllocation(t *testing.T, body []byte) (StageLookup, uint64) {
	t.Helper()
	var requests atomic.Int32
	r := staticReader(body, &requests)
	var got StageLookup
	var most uint64
	for i := 0; i < 3; i++ {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		result, err := r.LookupLastRotation(context.Background(), testnetGenesis, lookupAccount, lookupAuthorizer)
		runtime.ReadMemStats(&after)
		if err != nil {
			t.Fatal(err)
		}
		assertNoToken(t, result)
		got = result
		most = max(most, after.TotalAlloc-before.TotalAlloc)
		if n := requests.Load(); n != int32(i+1) {
			t.Fatalf("lookup %d made %d requests in all, want one each", i+1, n)
		}
	}
	return got, most
}

// allocationBound is what one lookup may allocate on any response: the body
// buffer (the cap and a byte), at most lookupLimit results with the largest
// program each, and the syntax check's nesting stack and the HTTP exchange,
// which stay well under the slack. The SDK's models once took about 2.3 GB
// for a 1 MiB body of empty results.
const allocationBound = MaxIndexerResponseBytes + lookupLimit*maxLogicBytes + 192<<10

func jsonBody(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLookupAllocationIsBoundedByTheCapNotTheResults(t *testing.T) {
	good := string(jsonBody(t, spend(lookupAccount, lookupAuthorizer, stageProgram(7, "x"), false)))
	other := string(jsonBody(t, clawback(lookupAccount)))
	repeat := func(unit string, n int) string { return strings.TrimSuffix(strings.Repeat(unit+",", n), ",") }
	wrap := func(elems string) string { return `{"transactions":[` + elems + `]}` }
	// fill is how many copies of unit fit in the cap beside extra bytes.
	fill := func(unit string, extra int) int { return (MaxIndexerResponseBytes - extra) / len(unit) }

	empties := `{"transactions":[` + repeat("{}", 333_000) + "]}"
	arrays := `"transactions":[` + repeat("{}", lookupLimit) + `],`
	huge := strings.Repeat("A", MaxIndexerResponseBytes-4096)
	withArgs := spend(lookupAccount, lookupAuthorizer, stageProgram(2, "args"), false)
	withArgs["signature"].(map[string]any)["logicsig"].(map[string]any)["args"] = []string{huge}
	withUnknown := clawback(lookupAccount)
	withUnknown["a-newer-indexer-field"] = map[string]any{"nested": []string{huge}}
	var largest []map[string]any
	for i := 0; i < lookupLimit; i++ {
		txn := clawback(lookupAccount)
		txn["signature"].(map[string]any)["logicsig"].(map[string]any)["logic"] = base64.StdEncoding.EncodeToString(make([]byte, maxLogicBytes))
		largest = append(largest, txn)
	}
	deep := 9_990 // under the syntax check's nesting limit, so it is read

	for _, tc := range []struct {
		name string
		body string
		want LookupOutcome
	}{
		// Over the cap: refused before decoding.
		{"333,000 empty results", empties, LookupUnavailable},
		{"25,559 transactions keys", "{" + strings.Repeat(arrays, 25_559) + `"transactions":[` + good + "]}", LookupUnavailable},
		{"a match padded past the cap", wrap(good) + strings.Repeat(" ", MaxIndexerResponseBytes+1-len(wrap(good))), LookupUnavailable},
		// Within the cap.
		{"empty results to the cap", `{"transactions":[` + repeat("{}", fill("{},", 40)) + "]}", LookupUnavailable},
		{"transactions keys to the cap", "{" + strings.Repeat(arrays, fill(arrays, len(good)+40)) + `"transactions":[` + good + "]}", LookupUnavailable},
		{"a match, then 50 more", wrap(good + "," + repeat(other, 50)), LookupUnavailable},
		{"a match, then garbage", `{"transactions":[` + good + ",@@@@ garbage", LookupUnavailable},
		{"a match, truncated", `{"transactions":[` + good, LookupUnavailable},
		{"a match, then a second document", wrap(good) + wrap(good), LookupUnavailable},
		{"nesting past the syntax check's limit", `{"x":` + strings.Repeat("[", fill("[", 10)), LookupUnavailable},
		{"nesting to the limit, then the match", `{"x":` + strings.Repeat("[", deep) + strings.Repeat("]", deep) + `,"transactions":[` + good + "]}", LookupCandidate},
		{"enormous arguments on the spend", string(jsonBody(t, map[string]any{"transactions": []any{withArgs}})), LookupCandidate},
		{"enormous unknown field", string(jsonBody(t, map[string]any{"transactions": []any{withUnknown}})), LookupNoOutgoingRekey},
		{"enormous next-token", string(jsonBody(t, map[string]any{"transactions": []any{clawback(lookupAccount)}, "next-token": huge})), LookupNoOutgoingRekey},
		{"the limit's results, each with the largest program", string(jsonBody(t, map[string]any{"transactions": largest})), LookupNoOutgoingRekey},
		{"whitespace to the cap", strings.Repeat(" ", MaxIndexerResponseBytes-len(`{"transactions":[]}`)) + `{"transactions":[]}`, LookupNoOutgoingRekey},
		{"many top-level keys to the cap", "{" + strings.Repeat(`"a":1,`, fill(`"a":1,`, len(good)+40)) + `"transactions":[` + good + "]}", LookupCandidate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, allocated := lookupAllocation(t, []byte(tc.body))
			t.Logf("%d-byte body: %s (%s), %d bytes allocated", len(tc.body), got.Outcome, got.Reason, allocated)
			if got.Outcome != tc.want {
				t.Fatalf("lookup = %+v, want %s", got, tc.want)
			}
			if allocated > allocationBound {
				t.Fatalf("lookup allocated %d bytes, over the %d bound", allocated, allocationBound)
			}
		})
	}
}

// A field longer than its bound refuses the page without being kept.
func TestLookupRefusesAFieldOverItsBound(t *testing.T) {
	overLogic := make([]byte, maxLogicBytes+1)
	cases := map[string]func(txn map[string]any){
		"program over the largest a group allows": func(txn map[string]any) {
			txn["signature"].(map[string]any)["logicsig"].(map[string]any)["logic"] = base64.StdEncoding.EncodeToString(overLogic)
		},
		"transaction ID over its length":  func(txn map[string]any) { txn["id"] = strings.Repeat("A", txIDLength+1) },
		"sender over an address's length": func(txn map[string]any) { txn["sender"] = strings.Repeat("A", addressLength+1) },
		"rekey-to over an address's length": func(txn map[string]any) {
			txn["rekey-to"] = strings.Repeat("A", 100_000)
		},
		"auth-addr over an address's length": func(txn map[string]any) { txn["auth-addr"] = strings.Repeat("A", addressLength+1) },
		"genesis hash over 32 bytes": func(txn map[string]any) {
			txn["genesis-hash"] = base64.StdEncoding.EncodeToString(make([]byte, 33))
		},
		"an address that is not a string": func(txn map[string]any) { txn["sender"] = 12 },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			txn := spend(lookupAccount, lookupAuthorizer, stageProgram(2, "x"), false)
			edit(txn)
			got, allocated := lookupAllocation(t, jsonBody(t, map[string]any{"transactions": []any{txn}}))
			if got.Outcome != LookupUnavailable {
				t.Fatalf("lookup = %+v, want unavailable", got)
			}
			if allocated > allocationBound {
				t.Fatalf("lookup allocated %d bytes", allocated)
			}
		})
	}
	// At the bounds, the spend is read.
	txn := spend(lookupAccount, lookupAuthorizer, stageProgram(2, string(make([]byte, maxLogicBytes-12))), false)
	if got, _ := lookupAllocation(t, jsonBody(t, map[string]any{"transactions": []any{txn}})); got.Outcome != LookupCandidate {
		t.Fatalf("largest program: %+v, want a candidate", got)
	}
}

// The signature fields are read for presence only; each one besides the
// program refuses the spend, in whatever form the Indexer sends it.
func TestLookupReadsSignaturePresence(t *testing.T) {
	pq := map[string]any{"public-key": "AA==", "scheme": "falcon", "signature": "AA=="}
	for name, edit := range map[string]func(sig, lsig map[string]any){
		"top-level pqsig": func(sig, _ map[string]any) { sig["pqsig"] = pq },
		"logicsig pqsig":  func(_, lsig map[string]any) { lsig["pqsig"] = pq },
		"top-level sig":   func(sig, _ map[string]any) { sig["sig"] = "AA==" },
	} {
		t.Run(name, func(t *testing.T) {
			txn := spend(lookupAccount, lookupAuthorizer, stageProgram(2, "x"), false)
			sig := txn["signature"].(map[string]any)
			edit(sig, sig["logicsig"].(map[string]any))
			got, _ := lookupAllocation(t, jsonBody(t, map[string]any{"transactions": []any{txn}}))
			if got.Outcome != LookupNotAStageProgram {
				t.Fatalf("lookup = %+v, want not_a_stage_program", got)
			}
		})
	}
	// Empty values are absent.
	txn := spend(lookupAccount, lookupAuthorizer, stageProgram(2, "x"), false)
	sig := txn["signature"].(map[string]any)
	sig["sig"], sig["multisig"], sig["pqsig"] = "", map[string]any{}, nil
	if got, _ := lookupAllocation(t, jsonBody(t, map[string]any{"transactions": []any{txn}})); got.Outcome != LookupCandidate {
		t.Fatalf("empty signature fields: %+v, want a candidate", got)
	}
}

// Every field the lookup reads is named as the SDK's Indexer models name it.
func TestLookupFieldNamesAreTheIndexers(t *testing.T) {
	txn := spend(lookupAccount, lookupAuthorizer, stageProgram(4, "four"), false)
	txn["intra-round-offset"] = 3
	body := jsonBody(t, map[string]any{"current-round": 9, "next-token": "abc", "transactions": []any{txn}})
	m, err := decodeNewest(body, lookupAccount.String())
	if err != nil || m == nil {
		t.Fatalf("decodeNewest = %+v, %v", m, err)
	}
	if string(m.ID) != spendTxID || string(m.Sender) != lookupAccount.String() || string(m.RekeyTo) != lookupAuthorizer.String() ||
		string(m.AuthAddr) != programAddress(stageProgram(4, "four")).String() || m.ConfirmedRound != 4321 ||
		!bytes.Equal(m.GenesisHash, testnetGenesis) || !bytes.Equal(m.Signature.Logicsig.Logic, stageProgram(4, "four")) {
		t.Fatalf("decoded %s", fmt.Sprintf("%+v", *m))
	}
	if m, err := decodeNewest(jsonBody(t, map[string]any{"next-token": "abc", "transactions": []any{}}), lookupAccount.String()); err != nil || m != nil {
		t.Fatalf("decodeNewest of an empty answer = %+v, %v", m, err)
	}
}

// decoderOutcome runs one lookup against body and checks it made one
// request.
func decoderOutcome(t *testing.T, body string) StageLookup {
	t.Helper()
	got, _ := lookupAllocation(t, []byte(body))
	return got
}

// The decoder's rules, one subtest each. Every answer below holds the
// account's matching spend, which the lookup must not use.
func TestLookupDecoderRules(t *testing.T) {
	good := string(jsonBody(t, spend(lookupAccount, lookupAuthorizer, stageProgram(7, "x"), false)))
	other := string(jsonBody(t, clawback(lookupAccount)))
	wrap := func(elems string) string { return `{"transactions":[` + elems + `]}` }
	if got := decoderOutcome(t, wrap(good)); got.Outcome != LookupCandidate {
		t.Fatalf("the plain answer: %+v, want a candidate", got)
	}
	prog := stageProgram(7, "x")
	fields := func(extra string) string {
		return fmt.Sprintf(`{"id":%q,"confirmed-round":4321,"genesis-hash":%q,"sender":%q,"rekey-to":%q,"auth-addr":%q,"signature":{"logicsig":{"logic":%q}}%s}`,
			spendTxID, base64.StdEncoding.EncodeToString(testnetGenesis), lookupAccount, lookupAuthorizer, programAddress(prog), base64.StdEncoding.EncodeToString(prog), extra)
	}
	if got := decoderOutcome(t, wrap(fields(""))); got.Outcome != LookupCandidate {
		t.Fatalf("the hand-built answer: %+v, want a candidate", got)
	}
	for _, tc := range []struct {
		rule, name, body string
		want             LookupOutcome
	}{
		{"a", "a match padded past the cap", wrap(good) + strings.Repeat(" ", MaxIndexerResponseBytes+1-len(wrap(good))), LookupUnavailable},
		{"b", "a match, then a second document", wrap(good) + wrap(good), LookupUnavailable},
		{"b", "a match, then trailing data", wrap(good) + " x", LookupUnavailable},
		{"b", "a match, then garbage", `{"transactions":[` + good + ",@@@@", LookupUnavailable},
		{"b", "a match, truncated", `{"transactions":[` + good, LookupUnavailable},
		{"c", "a second transactions key", `{"transactions":[` + good + `],"transactions":[]}`, LookupUnavailable},
		{"c", "a match, then results past the limit", wrap(good + strings.Repeat(","+other, lookupLimit)), LookupUnavailable},
		{"d", "upper-case keys", wrap(strings.NewReplacer(`"sender"`, `"SENDER"`, `"rekey-to"`, `"REKEY-TO"`).Replace(good)), LookupNoOutgoingRekey},
		{"d", "a key that folds to sender", wrap(strings.Replace(good, `"sender"`, `"ſender"`, 1)), LookupNoOutgoingRekey},
		{"d", "upper-case TRANSACTIONS", `{"TRANSACTIONS":[` + good + `]}`, LookupNoOutgoingRekey},
		{"d", "an escaped key", wrap(strings.Replace(good, `"sender"`, `"\u0073ender"`, 1)), LookupUnavailable},
		{"e", "sender twice", wrap(fields(fmt.Sprintf(`,"sender":%q`, otherAddress))), LookupUnavailable},
		{"e", "rekey-to twice", wrap(fields(fmt.Sprintf(`,"rekey-to":%q`, otherAddress))), LookupUnavailable},
		{"e", "signature twice", wrap(fields(`,"signature":{"sig":"AAAA"}`)), LookupUnavailable},
		{"e", "logicsig twice", wrap(strings.Replace(fields(""), `"signature":{"logicsig":{`, `"signature":{"logicsig":{"signature":"AAAA"},"logicsig":{`, 1)), LookupUnavailable},
		{"e", "a logicsig field twice", wrap(strings.Replace(fields(""), `"signature":{"logicsig":{`, `"signature":{"logicsig":{"signature":"AAAA","signature":null,`, 1)), LookupUnavailable},
	} {
		t.Run(tc.rule+"/"+tc.name, func(t *testing.T) {
			if got := decoderOutcome(t, tc.body); got.Outcome != tc.want {
				t.Fatalf("lookup = %+v, want %s", got, tc.want)
			}
		})
	}
}
