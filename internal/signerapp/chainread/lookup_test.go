// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package chainread

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	apconfig "github.com/aplane-algo/aplane/internal/config"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// indexerToken is the configured Indexer token. No message, reason or field
// of a lookup may hold it, whatever the Indexer sends back.
const indexerToken = "INDEXER-SECRET-TOKEN-0123456789"

// fakeIndexer serves /v2/transactions from pages of results: a request
// without a next token gets pages[0], one with next token "p<i>" gets
// pages[i]. Every page but the last carries the next page's token, which
// the lookup must ignore. At the end of the test it checks that it saw
// exactly one request, the lookup's one, or none when noRequests is set.
type fakeIndexer struct {
	mu         sync.Mutex
	pages      [][]map[string]any
	handler    http.HandlerFunc // replaces the page server when set
	requests   []*http.Request
	noRequests bool
}

func (f *fakeIndexer) serve(t *testing.T) *httptest.Server {
	t.Helper()
	t.Cleanup(func() {
		want := 1
		if f.noRequests {
			want = 0
		}
		if got := f.requestCount(); got != want {
			t.Errorf("the fake Indexer saw %d requests, want %d", got, want)
		}
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Clone(context.Background()))
		handler := f.handler
		f.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		if r.URL.Path != "/v2/transactions" {
			http.NotFound(w, r)
			return
		}
		page := 0
		if next := r.URL.Query().Get("next"); next != "" {
			if _, err := fmt.Sscanf(next, "p%d", &page); err != nil {
				http.Error(w, "bad token", http.StatusBadRequest)
				return
			}
		}
		body := map[string]any{"current-round": 5000, "transactions": []map[string]any{}}
		if page < len(f.pages) {
			body["transactions"] = f.pages[page]
			if page+1 < len(f.pages) {
				body["next-token"] = fmt.Sprintf("p%d", page+1)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeIndexer) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeIndexer) request(i int) *http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[i]
}

// lookupReaderFor reads the Indexer at srv for testnet only.
func lookupReaderFor(srv *httptest.Server) Reader {
	return Reader{
		Resolver: apconfig.DefaultGenesisHashNetworkResolver,
		IndexerConfig: func(network string) *apconfig.IndexerNetworkConfig {
			if network != "testnet" {
				return nil
			}
			return &apconfig.IndexerNetworkConfig{Server: srv.URL, Token: indexerToken}
		},
	}
}

// stageProgram is a program with the stage prefix of stage n, then tail.
func stageProgram(n uint64, tail string) []byte {
	p := []byte{0x0d, 0x80, 0x08}
	p = binary.BigEndian.AppendUint64(p, n)
	p = append(p, 0x48)
	return append(p, tail...)
}

func programAddress(p []byte) types.Address { return crypto.AddressFromProgram(p) }

var (
	lookupAccount    = types.Address{0xA1, 31: 1}
	lookupAuthorizer = types.Address{0xA2, 31: 2}
	otherAddress     = types.Address{0xA3, 31: 3}
	spendTxID        = strings.Repeat("A", 51) + "Q"
)

// spend builds an Indexer transaction: the account's rekey to rekeyTo,
// signed by logic, with auth-addr set to the program's address unless
// selfSigned.
func spend(sender types.Address, rekeyTo types.Address, logic []byte, selfSigned bool) map[string]any {
	txn := map[string]any{
		"id":              spendTxID,
		"confirmed-round": 4321,
		"genesis-hash":    base64.StdEncoding.EncodeToString(testnetGenesis),
		"sender":          sender.String(),
		"rekey-to":        rekeyTo.String(),
		"tx-type":         "pay",
		"round-time":      1,
		"fee":             1000,
		"first-valid":     1,
		"last-valid":      2,
		"payment-transaction": map[string]any{
			"amount": 0, "receiver": sender.String(),
		},
	}
	if logic != nil {
		txn["signature"] = map[string]any{"logicsig": map[string]any{"logic": base64.StdEncoding.EncodeToString(logic)}}
		if !selfSigned {
			txn["auth-addr"] = programAddress(logic).String()
		}
	}
	return txn
}

// clawback is a newer result the sender role also matches: an asset
// clawback whose asset sender is the account. Its top-level sender is the
// clawback address, and it rekeys that address.
func clawback(account types.Address) map[string]any {
	txn := spend(otherAddress, otherAddress, stageProgram(99, "clawback"), false)
	txn["tx-type"] = "axfer"
	txn["asset-transfer-transaction"] = map[string]any{"asset-id": 7, "amount": 1, "receiver": otherAddress.String(), "sender": account.String()}
	return txn
}

func lookup(t *testing.T, r Reader, account, authorizer types.Address) StageLookup {
	t.Helper()
	got, err := r.LookupLastRotation(context.Background(), testnetGenesis, account, authorizer)
	if err != nil {
		t.Fatalf("LookupLastRotation error = %v", err)
	}
	assertNoToken(t, got)
	return got
}

func assertNoToken(t *testing.T, got StageLookup) {
	t.Helper()
	if s := fmt.Sprintf("%+v", got); strings.Contains(s, indexerToken) {
		t.Fatalf("lookup result holds the token: %s", s)
	}
}

func TestLookupStageNSpendIsCandidateNPlusOne(t *testing.T) {
	p7 := stageProgram(7, "seven")
	idx := &fakeIndexer{pages: [][]map[string]any{{spend(lookupAccount, lookupAuthorizer, p7, false)}}}
	srv := idx.serve(t)
	got := lookup(t, lookupReaderFor(srv), lookupAccount, lookupAuthorizer)
	if got.Outcome != LookupCandidate || got.Stage != 8 || got.TxID != spendTxID || got.Round != 4321 {
		t.Fatalf("lookup = %+v, want candidate 8 from %s at round 4321", got, spendTxID)
	}
	if got.Network != "testnet" || got.Host != strings.TrimPrefix(srv.URL, "http://") {
		t.Fatalf("lookup names network %q host %q", got.Network, got.Host)
	}
	// One request, for the account's newest outgoing rekey, with the token
	// as the SDK sends it.
	if idx.requestCount() != 1 {
		t.Fatalf("requests = %d, want 1", idx.requestCount())
	}
	req := idx.request(0)
	if req.URL.Path != "/v2/transactions" || req.URL.RawQuery != "address="+lookupAccount.String()+"&address-role=sender&limit=8&rekey-to=true" {
		t.Fatalf("request = %s?%s", req.URL.Path, req.URL.RawQuery)
	}
	if req.Header.Get("X-Indexer-API-Token") != indexerToken {
		t.Fatalf("token header = %q", req.Header.Get("X-Indexer-API-Token"))
	}
}

func TestLookupStageZeroSpendIsCandidateOne(t *testing.T) {
	p0 := stageProgram(0, "zero")
	account := programAddress(p0)
	idx := &fakeIndexer{pages: [][]map[string]any{{spend(account, lookupAuthorizer, p0, true)}}}
	got := lookup(t, lookupReaderFor(idx.serve(t)), account, lookupAuthorizer)
	if got.Outcome != LookupCandidate || got.Stage != 1 {
		t.Fatalf("lookup = %+v, want candidate 1", got)
	}
}

func TestLookupWithoutAnIndexerAsksNothing(t *testing.T) {
	idx := &fakeIndexer{noRequests: true}
	srv := idx.serve(t)
	for name, r := range map[string]Reader{
		"no Indexer for the network": func() Reader {
			r := lookupReaderFor(srv)
			r.IndexerConfig = func(string) *apconfig.IndexerNetworkConfig { return nil }
			return r
		}(),
		"empty server": func() Reader {
			r := lookupReaderFor(srv)
			r.IndexerConfig = func(string) *apconfig.IndexerNetworkConfig { return &apconfig.IndexerNetworkConfig{} }
			return r
		}(),
		"reader without Indexer access": {Resolver: apconfig.DefaultGenesisHashNetworkResolver},
	} {
		t.Run(name, func(t *testing.T) {
			if got := lookup(t, r, lookupAccount, lookupAuthorizer); got.Outcome != LookupNoIndexer {
				t.Fatalf("lookup = %+v, want no_indexer", got)
			}
		})
	}
	// An unmapped genesis hash has no network, so no Indexer either.
	r := lookupReaderFor(srv)
	if got, err := r.LookupLastRotation(context.Background(), make([]byte, 32), lookupAccount, lookupAuthorizer); err != nil || got.Outcome != LookupNoIndexer {
		t.Fatalf("unmapped genesis: %+v, %v", got, err)
	}
	if idx.requestCount() != 0 {
		t.Fatalf("requests = %d, want none", idx.requestCount())
	}
}

func TestLookupRefusesACallerMistake(t *testing.T) {
	r := lookupReaderFor((&fakeIndexer{noRequests: true}).serve(t))
	for name, call := range map[string]func() error{
		"short genesis": func() error {
			_, err := r.LookupLastRotation(context.Background(), []byte{1}, lookupAccount, lookupAuthorizer)
			return err
		},
		"zero account": func() error {
			_, err := r.LookupLastRotation(context.Background(), testnetGenesis, types.Address{}, lookupAuthorizer)
			return err
		},
		"zero authorizer": func() error {
			_, err := r.LookupLastRotation(context.Background(), testnetGenesis, lookupAccount, types.Address{})
			return err
		},
	} {
		if call() == nil {
			t.Fatalf("%s: no error", name)
		}
	}
}

// The sender role also matches a clawback's asset sender, and a clawback
// that rekeys its own sender is a result the account did not send. The
// lookup skips results sent by another address and uses the newest the
// account sent.
func TestLookupSkipsANewerClawbackSentByAnotherAddress(t *testing.T) {
	idx := &fakeIndexer{pages: [][]map[string]any{{clawback(lookupAccount), spend(lookupAccount, lookupAuthorizer, stageProgram(5, "five"), false)}}}
	got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer)
	if got.Outcome != LookupCandidate || got.Stage != 6 {
		t.Fatalf("lookup = %+v, want candidate 6 from the account's own rekey", got)
	}
}

// Eight results, none sent by the account: no outgoing rekey. The next
// page, which holds the account's spend, is never asked for: the response's
// next-token is ignored.
func TestLookupEightResultsFromOtherSendersAreNoOutgoingRekey(t *testing.T) {
	var eight []map[string]any
	for i := 0; i < 8; i++ {
		eight = append(eight, clawback(lookupAccount))
	}
	idx := &fakeIndexer{pages: [][]map[string]any{eight, {spend(lookupAccount, lookupAuthorizer, stageProgram(5, "five"), false)}}}
	got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer)
	if got.Outcome != LookupNoOutgoingRekey {
		t.Fatalf("lookup = %+v, want no_outgoing_rekey", got)
	}
	if idx.requestCount() != 1 || idx.request(0).URL.Query().Get("next") != "" {
		t.Fatalf("requests = %d, want the one request and no further page", idx.requestCount())
	}
}

func TestLookupEmptyAnswerIsNoOutgoingRekey(t *testing.T) {
	for name, body := range map[string]string{
		"empty array":         `{"current-round":5,"transactions":[]}`,
		"null":                `{"current-round":5,"transactions":null}`,
		"no transactions key": `{"current-round":5}`,
		"a next-token alone":  `{"current-round":5,"next-token":"p1","transactions":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			idx := &fakeIndexer{handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }}
			if got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer); got.Outcome != LookupNoOutgoingRekey {
				t.Fatalf("lookup = %+v, want no_outgoing_rekey", got)
			}
		})
	}
}

// An Indexer that sends more than the eight results asked has its answer
// refused when the ninth begins.
func TestLookupRefusesAnAnswerOfMoreResultsThanAsked(t *testing.T) {
	var nine []map[string]any
	for i := 0; i < 8; i++ {
		nine = append(nine, clawback(lookupAccount))
	}
	nine = append(nine, spend(lookupAccount, lookupAuthorizer, stageProgram(2, "x"), false))
	empties := make([]map[string]any, 9)
	for i := range empties {
		empties[i] = map[string]any{}
	}
	for name, results := range map[string][]map[string]any{
		"eight others, then the spend": nine,
		"nine empty objects":           empties,
	} {
		t.Run(name, func(t *testing.T) {
			idx := &fakeIndexer{pages: [][]map[string]any{results}}
			if got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer); got.Outcome != LookupUnavailable {
				t.Fatalf("lookup = %+v, want unavailable", got)
			}
		})
	}
	// The account's spend among the first eight is read without reading on.
	early := []map[string]any{clawback(lookupAccount), spend(lookupAccount, lookupAuthorizer, stageProgram(2, "x"), false)}
	for i := 0; i < 20; i++ {
		early = append(early, clawback(lookupAccount))
	}
	idx := &fakeIndexer{pages: [][]map[string]any{early}}
	if got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer); got.Outcome != LookupCandidate || got.Stage != 3 {
		t.Fatalf("lookup = %+v, want the second result's candidate", got)
	}
}

// An Indexer behind algod has not seen the spend that set the authorizer:
// the newest spend it knows from the account hands it to an earlier
// address. An older spend that would match is never used.
func TestLookupNewestRekeyToAnotherAddressIsNotCurrent(t *testing.T) {
	idx := &fakeIndexer{pages: [][]map[string]any{{
		spend(lookupAccount, otherAddress, stageProgram(4, "four"), false),
		spend(lookupAccount, lookupAuthorizer, stageProgram(5, "five"), false),
	}}}
	got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer)
	if got.Outcome != LookupNotCurrent || got.TxID != spendTxID || got.Round != 4321 {
		t.Fatalf("lookup = %+v, want not_current naming the spend read", got)
	}
	// The newest the account sent rekeys nothing: not the current rekey.
	notRekey := spend(lookupAccount, lookupAuthorizer, stageProgram(5, "five"), false)
	delete(notRekey, "rekey-to")
	idx = &fakeIndexer{pages: [][]map[string]any{{notRekey}}}
	if got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer); got.Outcome != LookupNotCurrent {
		t.Fatalf("result without rekey-to: %+v, want not_current", got)
	}
}

func TestLookupWrongGenesisHashIsWrongNetwork(t *testing.T) {
	txn := spend(lookupAccount, lookupAuthorizer, stageProgram(4, "four"), false)
	txn["genesis-hash"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
	missing := spend(lookupAccount, lookupAuthorizer, stageProgram(4, "four"), false)
	delete(missing, "genesis-hash")
	for name, txn := range map[string]map[string]any{"another chain": txn, "no genesis hash": missing} {
		t.Run(name, func(t *testing.T) {
			idx := &fakeIndexer{pages: [][]map[string]any{{txn}}}
			got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer)
			if got.Outcome != LookupWrongNetwork {
				t.Fatalf("lookup = %+v, want wrong_network", got)
			}
		})
	}
}

func TestLookupSpendNotSignedByAStageProgramAlone(t *testing.T) {
	p6 := stageProgram(6, "six")
	withSig := func(edit func(sig map[string]any)) map[string]any {
		txn := spend(lookupAccount, lookupAuthorizer, p6, false)
		edit(txn["signature"].(map[string]any))
		return txn
	}
	logicsig := func(sig map[string]any) map[string]any { return sig["logicsig"].(map[string]any) }
	msig := map[string]any{"version": 1, "threshold": 1, "subsignature": []map[string]any{{"public-key": base64.StdEncoding.EncodeToString(make([]byte, 32))}}}
	plain := spend(lookupAccount, lookupAuthorizer, nil, false)
	plain["signature"] = map[string]any{"sig": base64.StdEncoding.EncodeToString(make([]byte, 64))}
	plain["auth-addr"] = otherAddress.String()
	cases := map[string]map[string]any{
		"delegated by a signature": withSig(func(sig map[string]any) {
			logicsig(sig)["signature"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
		}),
		"delegated by a multisig":       withSig(func(sig map[string]any) { logicsig(sig)["multisig-signature"] = msig }),
		"delegated by a logic multisig": withSig(func(sig map[string]any) { logicsig(sig)["logic-multisig-signature"] = msig }),
		"plain signature":               plain,
		"multisig spend":                withSig(func(sig map[string]any) { sig["multisig"] = msig }),
		"program without the prefix": func() map[string]any {
			p := append([]byte{0x0d, 0x81, 0x01}, "no prefix"...)
			return spend(lookupAccount, lookupAuthorizer, p, false)
		}(),
		"program address is not the signer": func() map[string]any {
			txn := spend(lookupAccount, lookupAuthorizer, p6, false)
			txn["auth-addr"] = otherAddress.String()
			return txn
		}(),
		"stage 0 program with auth-addr set": spend(lookupAccount, lookupAuthorizer, stageProgram(0, "zero"), false),
		"stage 3 program without auth-addr": func() map[string]any {
			p3 := stageProgram(3, "three")
			return spend(programAddress(p3), lookupAuthorizer, p3, true)
		}(),
	}
	for name, txn := range cases {
		t.Run(name, func(t *testing.T) {
			account := lookupAccount
			if sender, _ := types.DecodeAddress(txn["sender"].(string)); sender != lookupAccount {
				account = sender
			}
			idx := &fakeIndexer{pages: [][]map[string]any{{txn}}}
			got := lookup(t, lookupReaderFor(idx.serve(t)), account, lookupAuthorizer)
			if got.Outcome != LookupNotAStageProgram {
				t.Fatalf("lookup = %+v, want not_a_stage_program", got)
			}
		})
	}
}

// A stage whose successor the stage table could not hold is refused, and
// n + 1 never overflows.
func TestLookupRefusesAStageWithoutARepresentableSuccessor(t *testing.T) {
	for _, n := range []uint64{math.MaxUint64 - 2, math.MaxUint64 - 1, math.MaxUint64} {
		idx := &fakeIndexer{pages: [][]map[string]any{{spend(lookupAccount, lookupAuthorizer, stageProgram(n, "top"), false)}}}
		got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer)
		if got.Outcome != LookupNotAStageProgram || got.Stage != 0 {
			t.Fatalf("stage %d: lookup = %+v, want refused", n, got)
		}
	}
	// The last stage with a representable successor is still a candidate.
	n := uint64(math.MaxUint64 - 3)
	idx := &fakeIndexer{pages: [][]map[string]any{{spend(lookupAccount, lookupAuthorizer, stageProgram(n, "top"), false)}}}
	if got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer); got.Outcome != LookupCandidate || got.Stage != n+1 {
		t.Fatalf("stage %d: lookup = %+v", n, got)
	}
}

func TestLookupUnreadableIndexerIsUnavailableWithoutTheToken(t *testing.T) {
	over := strings.Repeat(" ", MaxIndexerResponseBytes) + `{"transactions":[]}`
	unconfirmed := spend(lookupAccount, lookupAuthorizer, stageProgram(2, "x"), false)
	delete(unconfirmed, "confirmed-round")
	cases := map[string]http.HandlerFunc{
		// A hostile server echoes the token back; it reaches no message.
		"HTTP 500": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"message":"`+r.Header.Get("X-Indexer-API-Token")+`"}`, http.StatusInternalServerError)
		},
		"HTTP 401": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, r.Header.Get("X-Indexer-API-Token"), http.StatusUnauthorized)
		},
		"malformed JSON": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"transactions": [` + r.Header.Get("X-Indexer-API-Token")))
		},
		"body over the cap": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(over))
		},
		"unconfirmed transaction": func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"transactions": []map[string]any{unconfirmed}})
		},
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			idx := &fakeIndexer{handler: handler}
			got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer)
			if got.Outcome != LookupUnavailable || got.Reason == "" {
				t.Fatalf("lookup = %+v, want unavailable with a reason", got)
			}
		})
	}
	// A body of exactly the cap is read whole.
	exact := `{"transactions":[]}`
	exact = strings.Repeat(" ", MaxIndexerResponseBytes-len(exact)) + exact
	idx := &fakeIndexer{handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(exact)) }}
	if got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer); got.Outcome != LookupNoOutgoingRekey {
		t.Fatalf("body at the cap: %+v, want no_outgoing_rekey", got)
	}
	// Nothing listens: unavailable too.
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	if got := lookup(t, lookupReaderFor(dead), lookupAccount, lookupAuthorizer); got.Outcome != LookupUnavailable {
		t.Fatalf("closed server: %+v", got)
	}
}

// A redirect is refused, not followed: the lookup makes only the requests
// it counts, and never sends the token to another host.
func TestLookupRefusesARedirect(t *testing.T) {
	target := &fakeIndexer{noRequests: true, pages: [][]map[string]any{{spend(lookupAccount, lookupAuthorizer, stageProgram(2, "x"), false)}}}
	targetSrv := target.serve(t)
	idx := &fakeIndexer{handler: func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetSrv.URL+r.URL.RequestURI(), http.StatusFound)
	}}
	got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer)
	if got.Outcome != LookupUnavailable {
		t.Fatalf("lookup = %+v, want unavailable", got)
	}
	if target.requestCount() != 0 {
		t.Fatal("the redirect was followed")
	}
}

func TestLookupStallingIndexerIsUnavailableAtTheTimeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	idx := &fakeIndexer{handler: func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}}
	r := lookupReaderFor(idx.serve(t))
	r.LookupTimeout = 200 * time.Millisecond
	started := time.Now()
	got := lookup(t, r, lookupAccount, lookupAuthorizer)
	if got.Outcome != LookupUnavailable || !strings.Contains(got.Reason, "in time") {
		t.Fatalf("lookup = %+v, want unavailable at the timeout", got)
	}
	if took := time.Since(started); took > 3*time.Second {
		t.Fatalf("lookup took %v", took)
	}
	if DefaultLookupTimeout != 10*time.Second {
		t.Fatalf("DefaultLookupTimeout = %v, want 10s", DefaultLookupTimeout)
	}
}

// A lock cancels the pass's context: the lookup returns at once.
func TestLookupReturnsAtOnceWhenItsContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	idx := &fakeIndexer{handler: func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}}
	r := lookupReaderFor(idx.serve(t))
	go func() {
		<-entered
		cancel()
	}()
	started := time.Now()
	got, err := r.LookupLastRotation(ctx, testnetGenesis, lookupAccount, lookupAuthorizer)
	if err != nil || got.Outcome != LookupUnavailable {
		t.Fatalf("lookup = %+v, %v; want unavailable", got, err)
	}
	if took := time.Since(started); took > 3*time.Second {
		t.Fatalf("cancelled lookup took %v", took)
	}
}

// An Indexer ID that is not a transaction ID is not passed on.
func TestLookupDropsAnIDThatIsNotATransactionID(t *testing.T) {
	txn := spend(lookupAccount, lookupAuthorizer, stageProgram(2, "x"), false)
	txn["id"] = "\x1b[2Jnot-an-id"
	idx := &fakeIndexer{pages: [][]map[string]any{{txn}}}
	got := lookup(t, lookupReaderFor(idx.serve(t)), lookupAccount, lookupAuthorizer)
	if got.Outcome != LookupCandidate || got.TxID != "" {
		t.Fatalf("lookup = %+v, want a candidate without the ID", got)
	}
}
