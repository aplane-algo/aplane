// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/signerops"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const lookupWorkerTxID = "LOOKUPWORKERTXIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// indexerSpendFrom is the Indexer's record of the account's rotation from
// stage n to stage n + 1, signed by stage n's real program.
func indexerSpendFrom(t *testing.T, secret *coresigning.RotatingKeyMaterial, account types.Address, n uint64) map[string]any {
	t.Helper()
	signed, err := signerops.StageOps{}.SignStage(secret, n, 0, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	next, err := signerops.StageOps{}.StageAddress(secret, n+1)
	if err != nil {
		t.Fatal(err)
	}
	txn := map[string]any{
		"id":              lookupWorkerTxID,
		"confirmed-round": 777,
		"genesis-hash":    testnetGenesisB64,
		"sender":          account.String(),
		"rekey-to":        next.String(),
		"tx-type":         "pay",
		"signature":       map[string]any{"logicsig": map[string]any{"logic": base64.StdEncoding.EncodeToString(signed.Program)}},
	}
	if n > 0 {
		stage, err := signerops.StageOps{}.StageAddress(secret, n)
		if err != nil {
			t.Fatal(err)
		}
		txn["auth-addr"] = stage.String()
	}
	return txn
}

// mockIndexer answers the lookup's search with txns; before runs first.
type mockIndexer struct {
	txns     []map[string]any
	before   func(req *http.Request) error
	requests atomic.Int32
}

func (m *mockIndexer) transport() http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		m.requests.Add(1)
		if m.before != nil {
			if err := m.before(req); err != nil {
				return nil, err
			}
		}
		if req.URL.Path != "/v2/transactions" {
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
		}
		raw, _ := json.Marshal(map[string]any{"current-round": 800, "transactions": m.txns})
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(string(raw))),
			Request:    req,
		}, nil
	})
}

// lookupWorkerSigner is a test signer with a mock node and a mock Indexer
// for testnet, and one rotating account.
func lookupWorkerSigner(t *testing.T) (*Signer, *mockAccountNode, *mockIndexer, types.Address, *coresigning.RotatingKeyMaterial) {
	t.Helper()
	server, cleanup := setupTestSigner(t)
	t.Cleanup(cleanup)
	node := &mockAccountNode{}
	idx := &mockIndexer{}
	server.config.Algod = config.AlgodConfig{"testnet": &config.AlgodNetworkConfig{Server: "http://mock-algod"}}
	server.config.Indexer = map[string]*config.IndexerNetworkConfig{"testnet": {Server: "http://mock-indexer", Token: "mock-indexer-token"}}
	server.config.Rotating.StageHorizon = 2
	server.stageFillBatch, server.stageFillMaxDeriv = 4, 4
	server.makeAlgod = func(serverURL, token string) (*algod.Client, error) {
		return algod.MakeClientWithTransport(serverURL, token, nil, node.transport())
	}
	server.indexerTransport = idx.transport()
	account, secret := installRotatingKey(t, server)
	return server, node, idx, account, secret
}

// After a restore, or on a new machine, the account resolves on the
// worker's next pass: one derivation, the candidate read from the last
// spend.
func TestWorkerResolvesTheStageFromTheIndexerAfterOneDerivation(t *testing.T) {
	server, node, idx, account, secret := lookupWorkerSigner(t)
	ir := server.productRuntime()
	logs := &syncBuffer{}
	appLogger.SetOutput(logs)
	t.Cleanup(func() { appLogger.SetOutput(os.Stderr) })
	stage9, _ := signerops.StageOps{}.StageAddress(secret, 9)
	idx.txns = []map[string]any{indexerSpendFrom(t, secret, account, 8)}
	node.set(stage9.String(), 900)

	server.fillStageTables(context.Background(), ir)
	gh, _ := base64.StdEncoding.DecodeString(testnetGenesisB64)
	table, err := ir.StageTables().Table(account, gh, nil, "aplane.rotating-triple-wotsc.v1")
	if err != nil {
		t.Fatal(err)
	}
	if stage, ok := table.Lookup(stage9); !ok || stage != 9 {
		t.Fatalf("stage 9 not resolved: %d, %v", stage, ok)
	}
	statuses := ir.RotatingAccountStatuses()
	if len(statuses) != 1 || statuses[0].Stage == nil || *statuses[0].Stage != 9 {
		t.Fatalf("statuses = %+v", statuses)
	}
	rec := statuses[0].Recovery
	if rec == nil || rec.Stopped != signersigning.StopFound || rec.StoppedStage == nil || *rec.StoppedStage != 9 || rec.AllowanceSpent != 1 {
		t.Fatalf("recovery = %+v, want found at 9 with one stage charged", rec)
	}
	if _, ok := table.Address(0); ok {
		t.Fatal("the search ran from stage 0 although the lookup matched")
	}
	if idx.requests.Load() != 1 {
		t.Fatalf("Indexer requests = %d, want 1", idx.requests.Load())
	}
	stage := uint64(9)
	want := &signerapi.RotatingStageLookupStatus{Outcome: "candidate", Stage: &stage, Probe: "matched", TxID: lookupWorkerTxID, Round: 777}
	if !reflect.DeepEqual(rec.Lookup, want) {
		t.Fatalf("status lookup = %+v, want %+v", rec.Lookup, want)
	}
	// One info line for the lookup, naming the account, the network, the
	// Indexer's host, the outcome, the candidate and its probe.
	var lines []string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "stage lookup") {
			lines = append(lines, line)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("lookup log lines = %q, want one", lines)
	}
	for _, want := range []string{"[INFO]", account.String(), "network testnet", "Indexer mock-indexer", "candidate", "stage 9", lookupWorkerTxID, "probe matched"} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("log line %q lacks %q", lines[0], want)
		}
	}
	if strings.Contains(logs.String(), "mock-indexer-token") {
		t.Fatal("the Indexer's token was logged")
	}
}

// An Indexer that cannot be read is logged and reported as unavailable, the
// search runs without it, and its token reaches neither the log nor the
// status, even when the server echoes it back.
func TestUnreadableIndexerIsReportedWithoutItsToken(t *testing.T) {
	server, node, idx, _, secret := lookupWorkerSigner(t)
	ir := server.productRuntime()
	logs := &syncBuffer{}
	appLogger.SetOutput(logs)
	t.Cleanup(func() { appLogger.SetOutput(os.Stderr) })
	idx.before = func(req *http.Request) error {
		return fmt.Errorf("refused, token %s", req.Header.Get("X-Indexer-API-Token"))
	}
	stage2, _ := signerops.StageOps{}.StageAddress(secret, 2)
	node.set(stage2.String(), 900)
	server.fillStageTables(context.Background(), ir)
	statuses := ir.RotatingAccountStatuses()
	if len(statuses) != 1 || statuses[0].Recovery == nil || statuses[0].Recovery.Lookup == nil || statuses[0].Recovery.Lookup.Outcome != "unavailable" {
		t.Fatalf("statuses = %+v", statuses)
	}
	// The search ran without the lookup: stages 0, 1 and 2.
	if statuses[0].Stage == nil || *statuses[0].Stage != 2 {
		t.Fatalf("status = %+v, want stage 2 found by the search", statuses[0])
	}
	raw, _ := json.Marshal(server.restServiceWithSigningAudit(nil).Status(ir))
	if strings.Contains(string(raw), "mock-indexer-token") || !strings.Contains(string(raw), `"outcome":"unavailable"`) {
		t.Fatalf("/status = %s", raw)
	}
	if !strings.Contains(logs.String(), "stage lookup on network testnet through Indexer mock-indexer: unavailable") {
		t.Fatalf("logs = %s", logs.String())
	}
	if strings.Contains(logs.String(), "mock-indexer-token") {
		t.Fatalf("the Indexer's token was logged: %s", logs.String())
	}
}

// A lock during the lookup is not held up by it, since the lookup is not a
// key use, and the pass it cancels publishes nothing.
func TestLockDuringTheLookupPublishesNothing(t *testing.T) {
	server, node, idx, account, secret := lookupWorkerSigner(t)
	ir := server.productRuntime()
	node.set("", 100)
	server.fillStageTables(context.Background(), ir)
	before := ir.RotatingAccountStatuses()
	if len(before) != 1 || before[0].Stage == nil || *before[0].Stage != 0 {
		t.Fatalf("statuses after a full pass = %+v", before)
	}
	gh, _ := base64.StdEncoding.DecodeString(testnetGenesisB64)
	table, err := ir.StageTables().Table(account, gh, nil, "aplane.rotating-triple-wotsc.v1")
	if err != nil {
		t.Fatal(err)
	}
	scanned := table.Len()

	stage9, _ := signerops.StageOps{}.StageAddress(secret, 9)
	idx.txns = []map[string]any{indexerSpendFrom(t, secret, account, 8)}
	node.set(stage9.String(), 900)
	locked := make(chan struct{})
	idx.before = func(req *http.Request) error {
		go func() {
			ir.Lock()
			close(locked)
		}()
		select {
		case <-locked:
		case <-time.After(5 * time.Second):
			t.Error("the lock waited for the lookup")
		}
		return req.Context().Err()
	}
	server.fillStageTables(context.Background(), ir)
	select {
	case <-locked:
	default:
		t.Fatal("the lock never landed during the lookup")
	}
	if after := ir.RotatingAccountStatuses(); !reflect.DeepEqual(after, before) {
		t.Fatalf("statuses after the cut pass = %+v, want %+v", after, before)
	}
	if table.Len() != scanned {
		t.Fatalf("table grew from %d to %d in a pass the lock cut during the lookup", scanned, table.Len())
	}
}

// A lock whose first step lands after the lookup refuses the probe's key
// use: the pass is cut and publishes nothing.
func TestLockDuringTheProbePublishesNothing(t *testing.T) {
	server, node, idx, account, secret := lookupWorkerSigner(t)
	ir := server.productRuntime()
	node.set("", 100)
	server.fillStageTables(context.Background(), ir)
	before := ir.RotatingAccountStatuses()
	if len(before) != 1 {
		t.Fatalf("statuses after a full pass = %+v", before)
	}
	stage9, _ := signerops.StageOps{}.StageAddress(secret, 9)
	idx.txns = []map[string]any{indexerSpendFrom(t, secret, account, 8)}
	node.set(stage9.String(), 900)
	idx.before = func(*http.Request) error {
		ir.SetRecovery()
		return nil
	}
	if wait := server.fillStageTables(context.Background(), ir); wait != stageTableIdleInterval {
		t.Fatalf("wait after the cut pass = %v, want idle", wait)
	}
	if idx.requests.Load() != 1 {
		t.Fatalf("Indexer requests = %d, want the one lookup", idx.requests.Load())
	}
	if after := ir.RotatingAccountStatuses(); !reflect.DeepEqual(after, before) {
		t.Fatalf("statuses after the pass cut at the probe = %+v, want %+v", after, before)
	}
	gh, _ := base64.StdEncoding.DecodeString(testnetGenesisB64)
	table, err := ir.StageTables().Table(account, gh, nil, "aplane.rotating-triple-wotsc.v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Lookup(stage9); ok {
		t.Fatal("the refused probe derived stage 9")
	}
}

// The log line names the spend as rotate status does, leaving out what the
// lookup did not keep.
func TestStageLookupLogLineNamesTheSpendItRead(t *testing.T) {
	record := func(txid string, round uint64) *signersigning.StageLookupRecord {
		l := &signersigning.StageLookupRecord{Probe: signersigning.ProbeMissed}
		l.Outcome, l.Network, l.Host, l.Stage, l.TxID, l.Round = chainread.LookupCandidate, "testnet", "indexer.example", 418, txid, round
		return l
	}
	for _, tc := range []struct {
		l    *signersigning.StageLookupRecord
		want string
	}{
		{record(lookupWorkerTxID, 1234), "stage 418 from the last spend (" + lookupWorkerTxID + ", round 1234), probe missed"},
		{record("", 1234), "stage 418 from the last spend (round 1234), probe missed"},
		{record("", 0), "stage 418 from the last spend, probe missed"},
	} {
		got := stageLookupLogLine("ACCOUNT", tc.l)
		want := "rotating account ACCOUNT: stage lookup on network testnet through Indexer indexer.example: candidate, " + tc.want
		if got != want {
			t.Errorf("log line\n got %q\nwant %q", got, want)
		}
	}
}

// When the Indexer's one result is a clawback another address sent, which
// the sender role also matches, there is no outgoing rekey: the lookup
// looks no further, and the worker finds the stage by its search.
func TestWorkerSearchesWhenTheNewestResultIsAnotherSendersClawback(t *testing.T) {
	server, node, idx, account, secret := lookupWorkerSigner(t)
	ir := server.productRuntime()
	other, _ := signerops.StageOps{}.StageAddress(secret, 40)
	idx.txns = []map[string]any{{
		"id": lookupWorkerTxID, "confirmed-round": 800, "genesis-hash": testnetGenesisB64,
		"sender": other.String(), "rekey-to": other.String(), "tx-type": "axfer",
		"asset-transfer-transaction": map[string]any{"asset-id": 7, "amount": 1, "receiver": other.String(), "sender": account.String()},
	}}
	stage2, _ := signerops.StageOps{}.StageAddress(secret, 2)
	node.set(stage2.String(), 900)
	server.fillStageTables(context.Background(), ir)
	statuses := ir.RotatingAccountStatuses()
	if len(statuses) != 1 || statuses[0].Stage == nil || *statuses[0].Stage != 2 {
		t.Fatalf("statuses = %+v, want stage 2 found by the search", statuses)
	}
	rec := statuses[0].Recovery
	if rec == nil || rec.Lookup == nil || rec.Lookup.Outcome != signerapi.RotatingLookupNoOutgoingRekey || rec.StoppedStage == nil || *rec.StoppedStage != 2 || rec.AllowanceSpent != 3 {
		t.Fatalf("recovery = %+v, lookup %+v; want no_outgoing_rekey and stages 0, 1, 2 searched", rec, rec.Lookup)
	}
	if idx.requests.Load() != 1 {
		t.Fatalf("Indexer requests = %d, want 1", idx.requests.Load())
	}
}
