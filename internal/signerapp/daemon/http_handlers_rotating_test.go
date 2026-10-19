// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingtriple/signerops"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func recoverRequest(t *testing.T, req signerapi.RotatingRecoverRequest) *http.Request {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return requestWithIdentity(http.MethodPost, "/admin/rotating/recover", body)
}

func TestHandleRotatingRecoverStartsCancelsAndNeedsUnlockToStart(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	node := &mockAccountNode{}
	server.config.Algod = config.AlgodConfig{"testnet": &config.AlgodNetworkConfig{Server: "http://mock-algod"}}
	server.config.Rotating.StageHorizon = 2
	server.config.Rotating.RecoveryMaxStages = 0
	server.stageFillBatch, server.stageFillMaxDeriv = 4, 4
	server.makeAlgod = func(serverURL, token string) (*algod.Client, error) {
		return algod.MakeClientWithTransport(serverURL, token, nil, node.transport())
	}
	account, secret := installRotatingKey(t, server)
	acct := account.String()

	// Not a rotating account: refused before anything else.
	w := httptest.NewRecorder()
	server.handleRotatingRecover(w, recoverRequest(t, signerapi.RotatingRecoverRequest{Account: types.Address{1}.String(), Action: "start"}))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "no key found") {
		t.Fatalf("unknown account: %d %s", w.Code, w.Body.String())
	}

	hint := uint64(5)
	w = httptest.NewRecorder()
	server.handleRotatingRecover(w, recoverRequest(t, signerapi.RotatingRecoverRequest{Account: acct, Action: "start", Stage: &hint, MaxStages: 50}))
	if w.Code != http.StatusOK {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	var started signerapi.RotatingRecoverResponse
	if err := json.Unmarshal(w.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	if started.GrantID == 0 || !started.Recovery.Active || started.Recovery.Kind != "operator" || started.Recovery.Hint == nil || *started.Recovery.Hint != 5 {
		t.Fatalf("start response = %+v", started)
	}

	// A second start while one runs is refused.
	w = httptest.NewRecorder()
	server.handleRotatingRecover(w, recoverRequest(t, signerapi.RotatingRecoverRequest{Account: acct, Action: "start"}))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "cancel it first") {
		t.Fatalf("second start: %d %s", w.Code, w.Body.String())
	}

	// The worker runs the grant: the account is at stage 5, the hint is
	// exact, and /status reports the search and then the resolved stage.
	stage5, err := signerops.StageOps{}.StageAddress(secret, 5)
	if err != nil {
		t.Fatal(err)
	}
	node.set(stage5.String(), 100)
	for i := 0; i < 8; i++ {
		if wait := server.fillStageTables(context.Background(), ir); wait == stageTableIdleInterval {
			break
		}
	}
	status := server.restService().Status(ir)
	if len(status.Rotating) != 1 || status.Rotating[0].Account != acct || status.Rotating[0].Classification != signerapi.RotatingClassStage || status.Rotating[0].Stage == nil || *status.Rotating[0].Stage != 5 {
		t.Fatalf("/status rotating = %+v", status.Rotating)
	}
	if rec := status.Rotating[0].Recovery; rec == nil || rec.Active || rec.Stopped != "found" || rec.StoppedGrantID != started.GrantID || rec.StoppedStage == nil || *rec.StoppedStage != 5 {
		t.Fatalf("/status recovery = %+v", status.Rotating[0].Recovery)
	}

	// Cancel with nothing running is a success that cancelled nothing.
	w = httptest.NewRecorder()
	server.handleRotatingRecover(w, recoverRequest(t, signerapi.RotatingRecoverRequest{Account: acct, Action: "cancel"}))
	var cancelled signerapi.RotatingRecoverResponse
	if err := json.Unmarshal(w.Body.Bytes(), &cancelled); w.Code != http.StatusOK || err != nil || cancelled.GrantID != 0 {
		t.Fatalf("cancel of nothing: %d %s", w.Code, w.Body.String())
	}

	// Locked: start is refused like signing; cancel still succeeds.
	server.lock()
	w = httptest.NewRecorder()
	server.handleRotatingRecover(w, recoverRequest(t, signerapi.RotatingRecoverRequest{Account: acct, Action: "start"}))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "signer is locked") {
		t.Fatalf("locked start: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	server.handleRotatingRecover(w, recoverRequest(t, signerapi.RotatingRecoverRequest{Account: acct, Action: "cancel"}))
	if w.Code != http.StatusOK {
		t.Fatalf("locked cancel: %d %s", w.Code, w.Body.String())
	}
}

func TestHandleRotatingRecoverRequiresPOST(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	w := httptest.NewRecorder()
	server.handleRotatingRecover(w, requestWithIdentity(http.MethodGet, "/admin/rotating/recover", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", w.Code)
	}
}

// TestStageTableWorkerBoundsAnUnknownAuthorizer pins the worker-level
// contract: an authorizer the signer cannot place is searched for at most
// recovery_max_stages past the table per unlock, then left unresolved with
// a note, and a lock followed by an unlock grants a fresh allowance.
func TestStageTableWorkerBoundsAnUnknownAuthorizer(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	node := &mockAccountNode{}
	server.config.Algod = config.AlgodConfig{"testnet": &config.AlgodNetworkConfig{Server: "http://mock-algod"}}
	server.config.Rotating.StageHorizon = 2
	server.config.Rotating.RecoveryMaxStages = 3
	server.stageFillBatch, server.stageFillMaxDeriv = 2, 2
	server.makeAlgod = func(serverURL, token string) (*algod.Client, error) {
		return algod.MakeClientWithTransport(serverURL, token, nil, node.transport())
	}
	account, _ := installRotatingKey(t, server)
	foreign := types.Address{0xde, 0xad, 31: 1}
	node.set(foreign.String(), 100)

	if wait := server.fillStageTables(context.Background(), ir); wait != stageTableBusyInterval {
		t.Fatalf("first pass wait = %v, want busy", wait)
	}
	if wait := server.fillStageTables(context.Background(), ir); wait != stageTableIdleInterval {
		t.Fatalf("exhausting pass wait = %v, want idle", wait)
	}
	status := server.restService().Status(ir)
	if len(status.Rotating) != 1 || status.Rotating[0].Classification != signerapi.RotatingClassUnknown || status.Rotating[0].CachedStages != 3 {
		t.Fatalf("/status rotating = %+v", status.Rotating)
	}
	if rec := status.Rotating[0].Recovery; rec == nil || rec.Active || rec.Stopped != "allowance exhausted" || rec.AllowanceSpent != 3 || rec.SuppressedAuthorizer != foreign.String() {
		t.Fatalf("/status recovery = %+v", status.Rotating[0].Recovery)
	}
	if notes := ir.RotatingNotes(); len(notes) != 1 || !strings.Contains(notes[0], "rotate recover") || !strings.Contains(notes[0], account.String()) {
		t.Fatalf("notes = %v", notes)
	}
	if alerts := ir.RotatingAlerts(); len(alerts) != 0 {
		t.Fatalf("an unresolved authorizer raised an alert: %v", alerts)
	}
	// Idle from here: the table does not move.
	server.fillStageTables(context.Background(), ir)
	if got := server.restService().Status(ir).Rotating[0].CachedStages; got != 3 {
		t.Fatalf("cached stages after suppression = %d, want 3", got)
	}

	// Lock, then unlock between two worker ticks: the allowance is keyed
	// by the lock generation, so the worker never has to notice the lock
	// for the allowance to be renewed.
	server.lock()
	if ok, _, msg := ir.TryUnlock(testPassphrase, nil); !ok {
		t.Fatalf("unlock failed: %s", msg)
	}
	if wait := server.fillStageTables(context.Background(), ir); wait != stageTableBusyInterval {
		t.Fatalf("pass after unlock wait = %v, want busy", wait)
	}
	if got := server.restService().Status(ir).Rotating[0].CachedStages; got != 5 {
		t.Fatalf("cached stages after unlock = %d, want 5", got)
	}
}

// TestPassSessionPairsTheSessionWithItsContext pins the capture rule: a
// lock in force leaves the context born cancelled and the pass refused; a
// lock and unlock between reading the session and creating the context
// leave a live context whose session the recovery memory then refuses,
// because it validates every entry against the runtime's live generation.
func TestPassSessionPairsTheSessionWithItsContext(t *testing.T) {
	gen := uint64(4)
	generation := func() uint64 { return gen }
	liveContext := func(parent context.Context) (context.Context, context.CancelFunc) {
		return context.WithCancel(parent)
	}
	rec := &signersigning.RotatingRecovery{MaxStages: 10}
	rec.SetGenerationSource(generation)

	session, _, cancel, ok := passSession(context.Background(), generation, liveContext)
	cancel()
	if !ok || session != 4 || !rec.Admit(session) {
		t.Fatalf("steady session: ok %v, session %d", ok, session)
	}

	lockedBetween := func(parent context.Context) (context.Context, context.CancelFunc) {
		gen++
		return context.WithCancel(parent)
	}
	session, _, cancel, ok = passSession(context.Background(), generation, lockedBetween)
	cancel()
	if !ok || session != 4 {
		t.Fatalf("lock between: ok %v, session %d", ok, session)
	}
	if rec.Admit(session) {
		t.Fatal("memory admitted a session a lock has ended")
	}
	if !rec.Admit(5) {
		t.Fatal("memory refused the live session")
	}

	cancelledContext := func(parent context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, cancel
	}
	_, _, cancel, ok = passSession(context.Background(), generation, cancelledContext)
	cancel()
	if ok {
		t.Fatal("pass accepted a cancelled context")
	}
}
