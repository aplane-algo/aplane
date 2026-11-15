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

// allocationBound is what the lookup's one request may allocate on any
// response: the decoder's buffer for the largest value it holds, at most the
// body cap, grown by doubling (about twice the cap in all), plus at most
// eight results of bounded fields, one at a time. The SDK's models once took
// about 2.3 GB for the first body below.
const allocationBound = 3 * MaxIndexerResponseBytes

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

	var eightLargest []map[string]any
	for i := 0; i < 8; i++ {
		txn := clawback(lookupAccount)
		txn["signature"].(map[string]any)["logicsig"].(map[string]any)["logic"] = base64.StdEncoding.EncodeToString(make([]byte, maxLogicBytes))
		eightLargest = append(eightLargest, txn)
	}

	for _, tc := range []struct {
		name string
		body []byte
		want LookupOutcome
	}{
		// Refused when the ninth result begins, before it is decoded.
		{"333,000 empty results", []byte(empties.String()), LookupUnavailable},
		// The spend's arguments are scanned past, never kept.
		{"enormous arguments on the spend", jsonBody(t, map[string]any{"transactions": []any{withArgs}}), LookupCandidate},
		// An unknown field, at any depth, is scanned past.
		{"enormous unknown field", jsonBody(t, map[string]any{"transactions": []any{withUnknown}}), LookupNoOutgoingRekey},
		// A next-token, whatever its size, is never decoded or followed.
		{"enormous next-token", jsonBody(t, map[string]any{"transactions": []any{clawback(lookupAccount)}, "next-token": huge}), LookupNoOutgoingRekey},
		// Eight results from other senders, each with the largest program
		// a group allows.
		{"eight largest programs", jsonBody(t, map[string]any{"transactions": eightLargest}), LookupNoOutgoingRekey},
		// Padding up to the cap before the value.
		{"whitespace to the cap", []byte(strings.Repeat(" ", MaxIndexerResponseBytes-len(`{"transactions":[]}`)) + `{"transactions":[]}`), LookupNoOutgoingRekey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, allocated := lookupAllocation(t, tc.body)
			t.Logf("%d-byte body: %s, %d bytes allocated", len(tc.body), got.Outcome, allocated)
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
	m, err := decodeNewest(bytes.NewReader(body), lookupAccount.String())
	if err != nil || m == nil {
		t.Fatalf("decodeNewest = %+v, %v", m, err)
	}
	if string(m.ID) != spendTxID || string(m.Sender) != lookupAccount.String() || string(m.RekeyTo) != lookupAuthorizer.String() ||
		string(m.AuthAddr) != programAddress(stageProgram(4, "four")).String() || m.ConfirmedRound != 4321 ||
		!bytes.Equal(m.GenesisHash, testnetGenesis) || !bytes.Equal(m.Signature.Logicsig.Logic, stageProgram(4, "four")) {
		t.Fatalf("decoded %s", fmt.Sprintf("%+v", *m))
	}
	if m, err := decodeNewest(bytes.NewReader(jsonBody(t, map[string]any{"next-token": "abc", "transactions": []any{}})), lookupAccount.String()); err != nil || m != nil {
		t.Fatalf("decodeNewest of an empty answer = %+v, %v", m, err)
	}
}
