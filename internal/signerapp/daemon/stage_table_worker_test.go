// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keys"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/lsig/rotatingtriple/signerops"
	rotatingsignerreg "github.com/aplane-algo/aplane/lsig/rotatingtriple/signerreg"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// testnetGenesisB64 maps to the built-in "testnet" token.
const testnetGenesisB64 = "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="

// mockAccountNode answers the two algod calls the chain reader makes.
type mockAccountNode struct {
	mu       sync.Mutex
	authAddr string
	round    uint64
}

func (n *mockAccountNode) set(authAddr string, round uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.authAddr, n.round = authAddr, round
}

func (n *mockAccountNode) transport() http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		n.mu.Lock()
		defer n.mu.Unlock()
		var body any
		switch {
		case req.URL.Path == "/versions":
			body = map[string]any{"genesis_hash_b64": testnetGenesisB64, "genesis_id": "testnet-v1.0", "versions": []string{"v2"}, "build": map[string]any{}}
		case strings.HasPrefix(req.URL.Path, "/v2/accounts/"):
			account := map[string]any{"address": strings.TrimPrefix(req.URL.Path, "/v2/accounts/"), "round": n.round}
			if n.authAddr != "" {
				account["auth-addr"] = n.authAddr
			}
			body = account
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
		}
		raw, _ := json.Marshal(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(string(raw))),
			Request:    req,
		}, nil
	})
}

// installRotatingKey saves a fresh rotating key into the signer's store and
// returns its account and a copy of its seed for deriving stage addresses.
func installRotatingKey(t *testing.T, server *Signer) (types.Address, *coresigning.RotatingKeyMaterial) {
	t.Helper()
	rotatingsignerreg.Register()
	ir := server.productRuntime()
	var seed rotatinghybrid.Seed
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	defer seed.Zero()
	var genesis [rotatinghybrid.GenesisHashSize]byte
	gh, _ := base64.StdEncoding.DecodeString(testnetGenesisB64)
	copy(genesis[:], gh)
	payload, address, err := rotatingsignerreg.NewKeyPayload(&seed, genesis)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.ZeroSecrets()
	active, err := ir.ActiveKeyPaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		_, err := keys.SavePayload(active, payload, kr)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ir.Reload(); err != nil {
		t.Fatal(err)
	}
	account, _ := types.DecodeAddress(address)
	secret := &coresigning.RotatingKeyMaterial{Seed: append([]byte(nil), seed[:]...), GenesisHash: genesis[:]}
	t.Cleanup(secret.Zero)
	return account, secret
}

func TestStageTableWorkerFillsResolvedAndUnresolvedAccounts(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()

	node := &mockAccountNode{}
	server.config.Algod = config.AlgodConfig{"testnet": &config.AlgodNetworkConfig{Server: "http://mock-algod"}}
	server.config.Rotating.StageHorizon = 2
	server.stageFillBatch, server.stageFillMaxDeriv = 2, 4
	server.makeAlgod = func(serverURL, token string) (*algod.Client, error) {
		return algod.MakeClientWithTransport(serverURL, token, nil, node.transport())
	}
	account, secret := installRotatingKey(t, server)
	gh, _ := base64.StdEncoding.DecodeString(testnetGenesisB64)

	// Fresh account: no auth address, so stage 0; the table covers 0 … 2 and
	// the worker goes idle.
	node.set("", 100)
	if wait := server.fillStageTables(context.Background(), ir); wait != stageTableIdleInterval {
		t.Fatalf("wait after resolved pass = %v, want idle interval", wait)
	}
	table, err := ir.StageTables().Table(account, gh, nil)
	if err != nil {
		t.Fatal(err)
	}
	if table.Len() != 3 {
		t.Fatalf("table len = %d, want 3 (stage 0 plus horizon 2)", table.Len())
	}
	if _, statErr := os.Stat(ir.KeyPaths().StageTablePath(account.String())); statErr != nil {
		t.Fatalf("table file not written beside the key store: %v", statErr)
	}
	for i := uint64(0); i < 3; i++ {
		want, err := signerops.StageOps{}.StageAddress(secret, i)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := table.Address(i); got != want {
			t.Fatalf("stage %d in table does not match derivation", i)
		}
	}

	// The account is ahead of the table: with four derivations per pass the
	// worker reports it as not yet found and asks to be called back soon,
	// instead of stopping at the horizon (2) or calling it foreign.
	stage9, _ := signerops.StageOps{}.StageAddress(secret, 9)
	node.set(stage9.String(), 200)
	if wait := server.fillStageTables(context.Background(), ir); wait != stageTableBusyInterval {
		t.Fatalf("wait after unresolved pass = %v, want busy interval", wait)
	}
	if table.Len() != 7 {
		t.Fatalf("unresolved pass len = %d, want 7 (stages 3 … 6 derived)", table.Len())
	}
	// The next pass reaches stage 9 after three derivations, spends its last
	// one on lookahead, and asks to continue; the pass after finishes the
	// lookahead through 11 and goes idle.
	wait := server.fillStageTables(context.Background(), ir)
	if stage, ok := table.Lookup(stage9); !ok || stage != 9 {
		t.Fatalf("stage 9 not resolved after two passes: %d, %v (len %d)", stage, ok, table.Len())
	}
	if wait != stageTableBusyInterval || table.Len() != 11 {
		t.Fatalf("after resolving: wait %v, len %d; want busy and 11", wait, table.Len())
	}
	if wait = server.fillStageTables(context.Background(), ir); wait != stageTableIdleInterval || table.Len() != 12 {
		t.Fatalf("after lookahead: wait %v, len %d; want idle and 12", wait, table.Len())
	}

	// A locked signer cannot reach the seed: the pass changes nothing and
	// falls back to the idle interval.
	ir.Lock()
	before := table.Len()
	if wait := server.fillStageTables(context.Background(), ir); wait != stageTableIdleInterval {
		t.Fatalf("wait while locked = %v, want idle interval", wait)
	}
	if table.Len() != before {
		t.Fatalf("locked pass changed the table: %d -> %d", before, table.Len())
	}
}

func TestLockingTheSignerStopsAndDrainsTheStageTableWorker(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()

	node := &mockAccountNode{}
	server.config.Algod = config.AlgodConfig{"testnet": &config.AlgodNetworkConfig{Server: "http://mock-algod"}}
	// A long pass: plenty of lookahead and budget, so only the lock can end it.
	server.config.Rotating.StageHorizon = 200
	server.stageFillBatch, server.stageFillMaxDeriv = 4, 200
	server.makeAlgod = func(serverURL, token string) (*algod.Client, error) {
		return algod.MakeClientWithTransport(serverURL, token, nil, node.transport())
	}
	account, _ := installRotatingKey(t, server)
	gh, _ := base64.StdEncoding.DecodeString(testnetGenesisB64)
	node.set("", 100)

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.fillStageTables(context.Background(), ir)
	}()
	// Let a few derivations happen, then lock. Lock drains every window in
	// which the seed is held, so when it returns no copy of the seed exists;
	// the pass may still write the prefix it had already derived and finish
	// its pacing sleep, holding nothing sensitive.
	time.Sleep(400 * time.Millisecond)
	ir.Lock()
	table, err := ir.StageTables().Table(account, gh, nil)
	if err != nil {
		t.Fatal(err)
	}
	atLock := table.Len()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stage table pass did not end after the signer locked")
	}
	n := table.Len()
	if n == 0 || n > 8 {
		t.Fatalf("table len after lock = %d; want a few stages, not a whole pass", n)
	}
	if n > atLock+uint64(server.stageFillBatch) {
		t.Fatalf("table grew from %d to %d after lock; more than the already-derived batch", atLock, n)
	}
	// Nothing derives after the pass ends.
	time.Sleep(300 * time.Millisecond)
	if table.Len() != n {
		t.Fatalf("table grew after the pass ended: %d -> %d", n, table.Len())
	}
	// A pass while locked does nothing and reports idle.
	if wait := server.fillStageTables(context.Background(), ir); wait != stageTableIdleInterval || table.Len() != n {
		t.Fatalf("locked pass: wait %v, len %d", wait, table.Len())
	}
}

// TestLockCompletesWhileATableWriteIsStalled pins that the seed is released
// before table I/O: a stalled fsync must not keep the lock from completing,
// because nothing sensitive is in memory during the write.
func TestLockCompletesWhileATableWriteIsStalled(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()

	node := &mockAccountNode{}
	server.config.Algod = config.AlgodConfig{"testnet": &config.AlgodNetworkConfig{Server: "http://mock-algod"}}
	server.config.Rotating.StageHorizon = 50
	server.stageFillBatch, server.stageFillMaxDeriv = 2, 50
	server.makeAlgod = func(serverURL, token string) (*algod.Client, error) {
		return algod.MakeClientWithTransport(serverURL, token, nil, node.transport())
	}
	account, _ := installRotatingKey(t, server)
	gh, _ := base64.StdEncoding.DecodeString(testnetGenesisB64)
	node.set("", 100)

	stalled := make(chan struct{})
	proceed := make(chan struct{})
	var once sync.Once
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && strings.Contains(path, "stages") {
			once.Do(func() { close(stalled) })
			<-proceed
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.fillStageTables(context.Background(), ir)
	}()
	select {
	case <-stalled:
	case <-time.After(10 * time.Second):
		t.Fatal("table write never started")
	}

	// The write is blocked. Lock must still complete promptly, because the
	// seed was released before the write began.
	locked := make(chan struct{})
	go func() {
		ir.Lock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(2 * time.Second):
		close(proceed)
		t.Fatal("Lock waited on a stalled table write")
	}
	close(proceed)
	<-done

	table, err := ir.StageTables().Table(account, gh, nil)
	if err != nil {
		t.Fatal(err)
	}
	n := table.Len()
	time.Sleep(200 * time.Millisecond)
	if table.Len() != n || n > 4 {
		t.Fatalf("table len %d -> %d after lock; want a short, stable prefix", n, table.Len())
	}
}

// stallingBody sends no bytes until released, the way a node that returned
// headers and then hung would. Like the real transport, it gives up when
// the request's context ends.
type stallingBody struct {
	ctx     context.Context
	release <-chan struct{}
	entered chan<- struct{}
	once    sync.Once
}

func (b *stallingBody) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	select {
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	case <-b.release:
		return 0, io.EOF
	}
}

func (b *stallingBody) Close() error { return nil }

func TestLockingCancelsAStalledChainRead(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()

	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	server.config.Algod = config.AlgodConfig{"testnet": &config.AlgodNetworkConfig{Server: "http://mock-algod"}}
	server.makeAlgod = func(serverURL, token string) (*algod.Client, error) {
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/versions" {
				raw, _ := json.Marshal(map[string]any{"genesis_hash_b64": testnetGenesisB64, "genesis_id": "testnet-v1.0", "versions": []string{"v2"}, "build": map[string]any{}})
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw))), Request: req}, nil
			}
			// Headers arrive; the body never does.
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       &stallingBody{ctx: req.Context(), release: release, entered: entered},
				Request:    req,
			}, nil
		})
		return algod.MakeClientWithTransport(serverURL, token, nil, rt)
	}
	installRotatingKey(t, server)

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.fillStageTables(context.Background(), ir)
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("chain read never started")
	}

	// The worker is blocked inside the node's response. Locking must free it
	// without waiting on the node, so the next unlock gets a working worker.
	ir.Lock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stage table pass stayed blocked on a stalled chain read after lock")
	}
}

// TestWorkerPublishesRotatingStatus drives a release through the real signer
// service and checks that the worker's pass turns the release memory into
// status: a note while in flight, a warning once expired, nothing once landed,
// each reaching /status and apadmin.
func TestWorkerPublishesRotatingStatus(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	hub := &recordingAdminHub{}
	server.hub = hub
	ir := server.productRuntime()

	node := &mockAccountNode{}
	server.config.Algod = config.AlgodConfig{"testnet": &config.AlgodNetworkConfig{Server: "http://mock-algod"}}
	server.config.Rotating.StageHorizon = 2
	server.makeAlgod = func(serverURL, token string) (*algod.Client, error) {
		return algod.MakeClientWithTransport(serverURL, token, nil, node.transport())
	}
	account, secret := installRotatingKey(t, server)
	node.set("", 100)

	// Release a rotation from stage 0 through the audited signing service, as
	// the HTTP endpoint would. Approval is auto.
	ir.Config().SetUserAutoApprove(true)
	svc := server.newSigningServiceWithAudit(ir, &signingAuditLogger{log: server.auditLog})
	gh, _ := base64.StdEncoding.DecodeString(testnetGenesisB64)
	var genesis [32]byte
	copy(genesis[:], gh)
	txn := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: account, Fee: 1000, FirstValid: 100, LastValid: 200, GenesisHash: genesis},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: account},
	}
	prep, svcErr := svc.PrepareRotatingWithContext(context.Background(), signerapi.RotatingPrepareRequest{
		Account: account.String(), TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
	}, ir.SnapshotKeySession())
	if svcErr != nil {
		t.Fatalf("prepare: %v", svcErr)
	}
	resp, svcErr := svc.SignRotatingWithContext(context.Background(), signerapi.RotatingSignRequest{
		Account: account.String(), Transactions: prep.Transactions,
	}, ir.SnapshotKeySession())
	if svcErr != nil {
		t.Fatalf("sign: %v", svcErr)
	}

	// In flight: a note, no warning, apadmin told nothing new.
	node.set("", 150)
	server.fillStageTables(context.Background(), ir)
	if w := ir.RotatingAlerts(); len(w) != 0 {
		t.Fatalf("warnings while in flight: %v", w)
	}
	if n := ir.RotatingNotes(); len(n) != 1 || !strings.Contains(n[0], "in flight") {
		t.Fatalf("notes while in flight: %v", n)
	}

	// Expired without landing: a warning, pushed to apadmin and /status.
	node.set("", 201)
	hub.statusCalled = false
	server.fillStageTables(context.Background(), ir)
	warnings := ir.RotatingAlerts()
	if len(warnings) != 1 || !strings.Contains(warnings[0], account.String()) || !strings.Contains(warnings[0], resp.TxID) {
		t.Fatalf("warnings after expiry: %v", warnings)
	}
	if !hub.statusCalled || len(hub.statusWarnings) != 1 {
		t.Fatalf("apadmin not told: called %v, warnings %v", hub.statusCalled, hub.statusWarnings)
	}
	status := server.restServiceWithSigningAudit(nil).Status(ir)
	if len(status.Warnings) == 0 || status.Warnings[len(status.Warnings)-1] != warnings[0] {
		t.Fatalf("/status warnings = %v", status.Warnings)
	}
	// Unchanged on the next pass: not re-notified.
	hub.statusCalled = false
	node.set("", 230)
	server.fillStageTables(context.Background(), ir)
	if hub.statusCalled {
		t.Fatal("an unchanged warning was published again")
	}

	// The rotation lands late: everything clears.
	stage1, _ := signerops.StageOps{}.StageAddress(secret, 1)
	node.set(stage1.String(), 260)
	server.fillStageTables(context.Background(), ir)
	if w, n := ir.RotatingAlerts(), ir.RotatingNotes(); len(w) != 0 || len(n) != 0 {
		t.Fatalf("after landing: warnings %v, notes %v", w, n)
	}
	if !hub.statusCalled {
		t.Fatal("apadmin not told the warning cleared")
	}

	// After a restart the memory is empty; the unlock path rebuilds it from
	// the audit log with verified addresses.
	server.rotatingReleases.Reset()
	server.rebuildReleaseMemory(context.Background(), ir)
	rec, ok := server.rotatingReleases.Get(account.String())
	if !ok || rec.Stage != 0 || rec.TxID != resp.TxID || rec.StageAddr != account || rec.NextAddr != stage1 {
		t.Fatalf("rebuilt release memory = %+v, %v", rec, ok)
	}
}
