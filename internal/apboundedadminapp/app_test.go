// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apboundedadminapp

import (
	"context"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	boundedauthorization "github.com/aplane-algo/aplane/internal/boundedadmin/authorization"
	boundedprotocol "github.com/aplane-algo/aplane/internal/boundedadmin/protocol"
	"github.com/aplane-algo/aplane/internal/engine"
)

type fakeRuntime struct {
	resolved       map[string]string
	currentAuth    string
	preparedParams engine.RekeyParams
	prepared       *engine.BoundedAdminPreparation
	completedWait  bool
	completeResult *engine.SubmitResult
	prepareCalls   int
	completeCalls  int
}

func (f *fakeRuntime) ResolveSingle(raw string) (string, error) { return f.resolved[raw], nil }
func (f *fakeRuntime) RefreshAuthAddressWithContext(context.Context, string) (string, error) {
	return f.currentAuth, nil
}
func (f *fakeRuntime) PrepareRekey(_ context.Context, params engine.RekeyParams) (*engine.TransactionPrepResult, *engine.RekeyCheckResult, error) {
	f.prepareCalls++
	f.preparedParams = params
	return &engine.TransactionPrepResult{}, &engine.RekeyCheckResult{IsUnrekey: params.From == params.To}, nil
}
func (f *fakeRuntime) PrepareExternalBoundedAdmin(context.Context, *engine.TransactionPrepResult) (*engine.BoundedAdminPreparation, error) {
	return f.prepared, nil
}
func (f *fakeRuntime) SubmitCompletedBoundedAdmin(_ context.Context, _ *engine.BoundedAdminPreparation, _ [][]byte, _ []types.Transaction, wait bool) (*engine.SubmitResult, error) {
	f.completeCalls++
	f.completedWait = wait
	return f.completeResult, nil
}

func TestCompleteUsesPreparedCeremonyWithoutReplanning(t *testing.T) {
	runtime := &fakeRuntime{completeResult: &engine.SubmitResult{TxID: "TXID"}}
	signer := &fakeSigner{}
	app := &App{
		runtime: runtime, signer: signer,
		completeAuthorization: func(boundedprotocol.Request, boundedprotocol.Response) ([][]byte, []types.Transaction, error) {
			return [][]byte{{1}}, []types.Transaction{{}}, nil
		},
	}
	prepared := &Prepared{Request: boundedprotocol.Request{
		Schema: boundedprotocol.RequestSchemaV1,
		Payload: boundedprotocol.RequestPayload{
			CurrentAuthAddress: "CURRENT",
		},
	}, From: "ACCOUNT", To: "TARGET", CurrentAuthAddress: "CURRENT"}

	result, err := app.Complete(context.Background(), prepared, boundedprotocol.Response{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.prepareCalls != 0 || runtime.completeCalls != 1 || signer.calls != 0 {
		t.Fatalf("completion crossed preparation/signing boundary: prepare=%d complete=%d sign=%d", runtime.prepareCalls, runtime.completeCalls, signer.calls)
	}
	if result.TxID != "TXID" || result.CurrentAuthAddress != "CURRENT" || result.To != "TARGET" {
		t.Fatalf("result = %#v", result)
	}
}
func (*fakeRuntime) Close() error { return nil }

type fakeSigner struct {
	artifact string
	request  boundedprotocol.Request
	calls    int
}

func (f *fakeSigner) Sign(_ context.Context, artifact string, request boundedprotocol.Request) (boundedprotocol.Response, error) {
	f.calls++
	f.artifact = artifact
	f.request = request
	return boundedprotocol.Response{}, nil
}

func TestExecuteRekeyCoordinatesExternalSignature(t *testing.T) {
	runtime := &fakeRuntime{
		resolved: map[string]string{"account": "ACCOUNT", "target": "TARGET"},
		prepared: &engine.BoundedAdminPreparation{Request: boundedprotocol.Request{
			Payload: boundedprotocol.RequestPayload{CurrentAuthAddress: "CURRENT"},
		}},
		completeResult: &engine.SubmitResult{
			TxID:               "TXID",
			Confirmed:          true,
			Output:             "confirmed\n",
			AuthRefreshWarning: "stale cache",
		},
	}
	signer := &fakeSigner{}
	app := &App{
		runtime: runtime, signer: signer,
		validateRequest: func(request boundedprotocol.Request) (*boundedauthorization.ValidatedRequest, error) {
			return &boundedauthorization.ValidatedRequest{Request: request}, nil
		},
		completeAuthorization: func(boundedprotocol.Request, boundedprotocol.Response) ([][]byte, []types.Transaction, error) {
			return [][]byte{{1}}, []types.Transaction{{}}, nil
		},
	}

	result, err := app.Execute(context.Background(), Options{
		Operation:  OperationRekey,
		Artifact:   "/cold/key.wit",
		Account:    "account",
		Target:     "target",
		Fee:        4000,
		UseFlatFee: true,
		Wait:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.preparedParams.From != "ACCOUNT" || runtime.preparedParams.To != "TARGET" || runtime.preparedParams.Fee != 4000 || !runtime.preparedParams.UseFlatFee {
		t.Fatalf("prepared params = %#v", runtime.preparedParams)
	}
	if signer.calls != 1 || signer.artifact != "/cold/key.wit" || signer.request.Payload.CurrentAuthAddress != "CURRENT" {
		t.Fatalf("signer call = calls %d, artifact %q, request %#v", signer.calls, signer.artifact, signer.request)
	}
	if !runtime.completedWait {
		t.Fatal("completion did not wait")
	}
	if result.From != "ACCOUNT" || result.To != "TARGET" || result.CurrentAuthAddress != "CURRENT" || result.TxID != "TXID" || !result.Confirmed || result.RefreshWarning != "stale cache" {
		t.Fatalf("result = %#v", result)
	}
}

func TestExecuteUnrekeyRequiresCurrentRekey(t *testing.T) {
	runtime := &fakeRuntime{
		resolved:    map[string]string{"account": "ACCOUNT"},
		currentAuth: "ACCOUNT",
	}
	signer := &fakeSigner{}
	app := &App{runtime: runtime, signer: signer}

	_, err := app.Execute(context.Background(), Options{
		Operation: OperationUnrekey,
		Artifact:  "/cold/key.wit",
		Account:   "account",
	})
	if err == nil {
		t.Fatal("Execute() error = nil, want account-not-rekeyed error")
	}
	if runtime.prepareCalls != 0 || signer.calls != 0 {
		t.Fatalf("workflow continued after guard: prepare=%d sign=%d", runtime.prepareCalls, signer.calls)
	}
}

func TestHelperEnvironmentExcludesCredentials(t *testing.T) {
	t.Setenv("APLANE_TOKEN", "secret")
	t.Setenv("ALGOD_TOKEN", "secret")
	t.Setenv("SSH_AUTH_SOCK", "/secret/socket")
	t.Setenv("PATH", "/secret/bin")
	t.Setenv("HOME", "/home/test")

	env := helperEnvironment()
	for _, entry := range env {
		switch entry {
		case "APLANE_TOKEN=secret", "ALGOD_TOKEN=secret", "SSH_AUTH_SOCK=/secret/socket", "PATH=/secret/bin":
			t.Fatalf("sensitive environment entry was propagated: %q", entry)
		}
	}
	foundHome := false
	for _, entry := range env {
		if entry == "HOME=/home/test" {
			foundHome = true
		}
	}
	if !foundHome {
		t.Fatalf("HOME missing from helper environment: %v", env)
	}
}
