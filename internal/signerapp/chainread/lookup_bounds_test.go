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
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

// staticIndexer answers every request with body, from memory, so what a
// lookup allocates is the lookup's own work.
type staticIndexer struct{ body []byte }

func (s staticIndexer) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(s.body)),
		Request:    req,
	}, nil
}

func staticReader(body []byte) Reader {
	return Reader{
		Resolver: apconfig.DefaultGenesisHashNetworkResolver,
		IndexerConfig: func(string) *apconfig.IndexerNetworkConfig {
			return &apconfig.IndexerNetworkConfig{Server: "http://indexer.test", Token: indexerToken}
		},
		IndexerTransport: staticIndexer{body: body},
	}
}

// lookupAllocation runs one lookup against body and reports its outcome and
// the bytes allocated meanwhile (the most of three runs).
func lookupAllocation(t *testing.T, body []byte) (StageLookup, uint64) {
	t.Helper()
	if len(body) > MaxIndexerResponseBytes {
		t.Fatalf("test body is %d bytes, over the cap", len(body))
	}
	r := staticReader(body)
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
	}
	return got, most
}

// requestAllocationBound is what one request may allocate on any response
// within the 1 MiB cap: the decoder's buffer for the largest value it holds,
// grown by doubling (about 2 MiB in all for a 1 MiB value), plus at most
// eight results of bounded fields. A lookup makes at most two requests. The
// SDK's models once took about 2.3 GB for the first body below.
const requestAllocationBound = 3 << 20

func jsonBody(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLookupAllocationIsBoundedByTheCapNotTheResults(t *testing.T) {
	var empties strings.Builder
	empties.WriteString(`{"transactions":[`)
	for i := 0; i < 333_000; i++ {
		if i > 0 {
			empties.WriteByte(',')
		}
		empties.WriteString("{}")
	}
	empties.WriteString("]}")

	huge := strings.Repeat("A", MaxIndexerResponseBytes-4096)
	withArgs := spend(lookupAccount, lookupAuthorizer, stageProgram(2, "args"), false)
	withArgs["signature"].(map[string]any)["logicsig"].(map[string]any)["args"] = []string{huge}
	withUnknown := clawback(lookupAccount)
	withUnknown["a-newer-indexer-field"] = map[string]any{"nested": []string{huge}}

	maxLogic := make([]byte, maxLogicBytes)
	var eightLarge []map[string]any
	for i := 0; i < 8; i++ {
		txn := clawback(lookupAccount)
		txn["signature"].(map[string]any)["logicsig"].(map[string]any)["logic"] = base64.StdEncoding.EncodeToString(maxLogic)
		eightLarge = append(eightLarge, txn)
	}

	for _, tc := range []struct {
		name string
		body []byte
		want LookupOutcome
		// requests is how many the body leads to: a page without a match
		// that names a next page is followed once.
		requests uint64
	}{
		// Refused at the ninth result, before it is decoded.
		{"333,000 empty results", []byte(empties.String()), LookupUnavailable, 1},
		// The match's arguments are scanned past, never kept.
		{"enormous arguments on the spend", jsonBody(t, map[string]any{"transactions": []any{withArgs}}), LookupCandidate, 1},
		// An unknown field, at any depth, is scanned past.
		{"enormous unknown field", jsonBody(t, map[string]any{"transactions": []any{withUnknown}}), LookupNoOutgoingRekey, 1},
		// The same twice: the page names a next page, which is the same.
		{"enormous unknown field on both pages", jsonBody(t, map[string]any{"transactions": []any{withUnknown}, "next-token": "p1"}), LookupNoOutgoingRekey, 2},
		// Eight results, each with the largest program a group allows.
		{"eight largest programs", jsonBody(t, map[string]any{"transactions": eightLarge}), LookupNoOutgoingRekey, 1},
		// Padding up to the cap before the value.
		{"whitespace to the cap", []byte(strings.Repeat(" ", MaxIndexerResponseBytes-len(`{"transactions":[]}`)) + `{"transactions":[]}`), LookupNoOutgoingRekey, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, allocated := lookupAllocation(t, tc.body)
			t.Logf("%d-byte body, %d request(s): %s, %d bytes allocated", len(tc.body), tc.requests, got.Outcome, allocated)
			if got.Outcome != tc.want {
				t.Fatalf("lookup = %+v, want %s", got, tc.want)
			}
			if bound := tc.requests * requestAllocationBound; allocated > bound {
				t.Fatalf("lookup allocated %d bytes, over the %d bound", allocated, bound)
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
		"next token over its bound":       nil,
		"an address that is not a string": func(txn map[string]any) { txn["sender"] = 12 },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			txn := spend(lookupAccount, lookupAuthorizer, stageProgram(2, "x"), false)
			page := map[string]any{"transactions": []any{txn}}
			if edit != nil {
				edit(txn)
			} else {
				page = map[string]any{"transactions": []any{clawback(lookupAccount)}, "next-token": strings.Repeat("n", maxNextTokenLength+1)}
			}
			got, allocated := lookupAllocation(t, jsonBody(t, page))
			if got.Outcome != LookupUnavailable {
				t.Fatalf("lookup = %+v, want unavailable", got)
			}
			if allocated > requestAllocationBound {
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
	page, err := decodePage(bytes.NewReader(body), lookupAccount.String())
	if err != nil || page.match == nil {
		t.Fatalf("decodePage = %+v, %v", page, err)
	}
	m := page.match
	if string(m.ID) != spendTxID || string(m.Sender) != lookupAccount.String() || string(m.RekeyTo) != lookupAuthorizer.String() ||
		string(m.AuthAddr) != programAddress(stageProgram(4, "four")).String() || m.ConfirmedRound != 4321 ||
		!bytes.Equal(m.GenesisHash, testnetGenesis) || !bytes.Equal(m.Signature.Logicsig.Logic, stageProgram(4, "four")) {
		t.Fatalf("decoded %s", fmt.Sprintf("%+v", *m))
	}
	page, err = decodePage(bytes.NewReader(jsonBody(t, map[string]any{"next-token": "abc", "transactions": []any{}})), lookupAccount.String())
	if err != nil || page.match != nil || page.next != "abc" {
		t.Fatalf("decodePage = %+v, %v", page, err)
	}
}
