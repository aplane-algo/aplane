// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/appspec"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/config"
)

func testFixturePath(t *testing.T, elems ...string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	parts := append([]string{filepath.Dir(filename), "..", "..", "test", "fixtures"}, elems...)
	return filepath.Clean(filepath.Join(parts...))
}

func TestPrepareAppCallRaw_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")

	_, err := eng.PrepareAppCallRaw(context.Background(), RawAppCallParams{
		AppID: 123,
		From:  testAddress(1).String(),
	})
	if err != ErrNoAlgodClient {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestPrepareAppCallRaw_UpdateIncludesPrograms(t *testing.T) {
	approvalSource := []byte("#pragma version 10\nint 1\nreturn\n")
	approvalCompiled := []byte{0x01, 0x20, 0x01, 0x01, 0x22}
	clearCompiled := []byte{0x02, 0x20, 0x01, 0x01, 0x22}

	client := newMockAlgodClient(t, map[string][]byte{
		string(approvalSource): approvalCompiled,
	})
	approvalPath := writeTempProgram(t, "approval.teal", approvalSource)
	clearPath := writeTempProgram(t, "clear.bin", clearCompiled)

	from := testAddress(1).String()
	eng := newAppCallTestEngine(t, client, from)

	prep, err := eng.PrepareAppCallRaw(context.Background(), RawAppCallParams{
		AppID:        123,
		From:         from,
		OnCompletion: types.UpdateApplicationOC,
		Approval: AppProgramSource{
			Path: approvalPath,
		},
		Clear: AppProgramSource{
			Path:     clearPath,
			Compiled: true,
		},
	})
	if err != nil {
		t.Fatalf("PrepareAppCallRaw(update) error = %v", err)
	}

	if prep.Transaction.OnCompletion != types.UpdateApplicationOC {
		t.Fatalf("OnCompletion = %v, want update", prep.Transaction.OnCompletion)
	}
	if got := uint64(prep.Transaction.ApplicationID); got != 123 {
		t.Fatalf("ApplicationID = %d, want 123", got)
	}
	if got := prep.Transaction.ApprovalProgram; string(got) != string(approvalCompiled) {
		t.Fatalf("ApprovalProgram = %v, want %v", got, approvalCompiled)
	}
	if got := prep.Transaction.ClearStateProgram; string(got) != string(clearCompiled) {
		t.Fatalf("ClearStateProgram = %v, want %v", got, clearCompiled)
	}
}

func TestPrepareAppCallRaw_RejectsProgramsWithoutUpdate(t *testing.T) {
	client := newMockAlgodClient(t, nil)
	approvalPath := writeTempProgram(t, "approval.bin", []byte{0x01})
	clearPath := writeTempProgram(t, "clear.bin", []byte{0x02})

	from := testAddress(1).String()
	eng := newAppCallTestEngine(t, client, from)

	_, err := eng.PrepareAppCallRaw(context.Background(), RawAppCallParams{
		AppID:        123,
		From:         from,
		OnCompletion: types.NoOpOC,
		Approval: AppProgramSource{
			Path:     approvalPath,
			Compiled: true,
		},
		Clear: AppProgramSource{
			Path:     clearPath,
			Compiled: true,
		},
	})
	if err == nil || err.Error() != "approval and clear programs are only supported with oncomp=update" {
		t.Fatalf("expected non-update program rejection, got %v", err)
	}
}

func TestPrepareAppCallRaw_UpdateRequiresPrograms(t *testing.T) {
	client := newMockAlgodClient(t, nil)
	from := testAddress(1).String()
	eng := newAppCallTestEngine(t, client, from)

	_, err := eng.PrepareAppCallRaw(context.Background(), RawAppCallParams{
		AppID:        123,
		From:         from,
		OnCompletion: types.UpdateApplicationOC,
	})
	if err == nil || err.Error() != "missing approval program for app update" {
		t.Fatalf("expected missing-approval error, got %v", err)
	}
}

func TestEnsureAppReferences(t *testing.T) {
	result := ensureAppReferences(10, []uint64{11, 12, 11, 10}, []types.AppBoxReference{
		{AppID: 10, Name: []byte("self")},
		{AppID: 13, Name: []byte("foreign")},
		{AppID: 12, Name: []byte("dup")},
	})

	want := []uint64{11, 12, 13}
	if len(result) != len(want) {
		t.Fatalf("len(result) = %d, want %d (%v)", len(result), len(want), result)
	}
	for i := range want {
		if result[i] != want[i] {
			t.Fatalf("result[%d] = %d, want %d (full=%v)", i, result[i], want[i], result)
		}
	}
}

func TestPrepareAppCallMethod_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")

	_, err := eng.PrepareAppCallMethod(context.Background(), MethodAppCallParams{
		ABIPath: testFixturePath(t, "testapp", "aplane_test.json"),
		Method:  "increment",
		Args:    []string{"5"},
		RawAppCallParams: RawAppCallParams{
			AppID: 123,
			From:  testAddress(1).String(),
		},
	})
	if err != ErrNoAlgodClient {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestPrepareAppCallMethod_EmptyABIPath(t *testing.T) {
	client := newMockAlgodClient(t, nil)
	from := testAddress(1).String()
	eng := newAppCallTestEngine(t, client, from)

	_, err := eng.PrepareAppCallMethod(context.Background(), MethodAppCallParams{
		Method: "increment",
		Args:   []string{"5"},
		RawAppCallParams: RawAppCallParams{
			AppID: 123,
			From:  from,
		},
	})
	if err == nil || err.Error() != "ABI path is required" {
		t.Fatalf("expected missing ABI path error, got %v", err)
	}
}

func TestPrepareAppCallRaw_SuccessIncludesReferencesAndLsigArgs(t *testing.T) {
	client := newMockAlgodClient(t, nil)
	from := testAddress(1).String()
	account := testAddress(2).String()
	eng := newAppCallTestEngine(t, client, from)

	lsigArgs := map[string][]byte{"preimage": []byte("secret")}
	prep, err := eng.PrepareAppCallRaw(context.Background(), RawAppCallParams{
		AppID:         123,
		From:          from,
		AppArgs:       [][]byte{[]byte("arg1"), []byte("arg2")},
		Accounts:      []string{account},
		ForeignApps:   []uint64{456, 123, 456},
		ForeignAssets: []uint64{999},
		Boxes: []types.AppBoxReference{
			{AppID: 123, Name: []byte("self")},
			{AppID: 789, Name: []byte("foreign")},
		},
		OnCompletion: types.OptInOC,
		Note:         "memo",
		Fee:          2000,
		UseFlatFee:   true,
		LsigArgs:     lsigArgs,
	})
	if err != nil {
		t.Fatalf("PrepareAppCallRaw(success) error = %v", err)
	}

	if got := uint64(prep.Transaction.ApplicationID); got != 123 {
		t.Fatalf("ApplicationID = %d, want 123", got)
	}
	if prep.Transaction.OnCompletion != types.OptInOC {
		t.Fatalf("OnCompletion = %v, want optin", prep.Transaction.OnCompletion)
	}
	if string(prep.Transaction.Note) != "memo" {
		t.Fatalf("Note = %q, want memo", string(prep.Transaction.Note))
	}
	if prep.Transaction.Fee != 2000 {
		t.Fatalf("Fee = %d, want 2000", prep.Transaction.Fee)
	}
	if len(prep.Transaction.ApplicationArgs) != 2 {
		t.Fatalf("ApplicationArgs len = %d, want 2", len(prep.Transaction.ApplicationArgs))
	}
	if len(prep.Transaction.Accounts) != 1 || prep.Transaction.Accounts[0].String() != account {
		t.Fatalf("Accounts = %#v, want [%s]", prep.Transaction.Accounts, account)
	}
	if len(prep.Transaction.ForeignApps) != 2 || prep.Transaction.ForeignApps[0] != 456 || prep.Transaction.ForeignApps[1] != 789 {
		t.Fatalf("ForeignApps = %#v, want [456 789]", prep.Transaction.ForeignApps)
	}
	if len(prep.Transaction.ForeignAssets) != 1 || prep.Transaction.ForeignAssets[0] != 999 {
		t.Fatalf("ForeignAssets = %#v, want [999]", prep.Transaction.ForeignAssets)
	}
	if string(prep.LsigArgs["preimage"]) != "secret" {
		t.Fatalf("LsigArgs = %#v, want preimage", prep.LsigArgs)
	}
	if prep.AppCallInfo == nil || prep.AppCallInfo.Mode != "raw" {
		t.Fatalf("AppCallInfo = %#v, want raw metadata", prep.AppCallInfo)
	}
}

func TestPrepareAppCallRaw_RejectsInvalidAccount(t *testing.T) {
	client := newMockAlgodClient(t, nil)
	from := testAddress(1).String()
	eng := newAppCallTestEngine(t, client, from)

	_, err := eng.PrepareAppCallRaw(context.Background(), RawAppCallParams{
		AppID:    123,
		From:     from,
		Accounts: []string{"not-an-address"},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid account 1 address") {
		t.Fatalf("expected invalid account error, got %v", err)
	}
}

func TestPrepareAppCallRaw_RejectsZeroForeignAsset(t *testing.T) {
	client := newMockAlgodClient(t, nil)
	from := testAddress(1).String()
	eng := newAppCallTestEngine(t, client, from)

	_, err := eng.PrepareAppCallRaw(context.Background(), RawAppCallParams{
		AppID:         123,
		From:          from,
		ForeignAssets: []uint64{0},
	})
	if err == nil || err.Error() != "invalid foreign asset 1: asset id must be non-zero" {
		t.Fatalf("expected zero-asset error, got %v", err)
	}
}

func TestPrepareAppCallRaw_RejectsEmptyBoxName(t *testing.T) {
	client := newMockAlgodClient(t, nil)
	from := testAddress(1).String()
	eng := newAppCallTestEngine(t, client, from)

	_, err := eng.PrepareAppCallRaw(context.Background(), RawAppCallParams{
		AppID: 123,
		From:  from,
		Boxes: []types.AppBoxReference{{AppID: 123, Name: nil}},
	})
	if err == nil || err.Error() != "invalid box 1 name: box name must be non-empty" {
		t.Fatalf("expected empty-box-name error, got %v", err)
	}
}

func TestPrepareAppCallMethod_SuccessEncodesMethodAndPropagatesLsigArgs(t *testing.T) {
	client := newMockAlgodClient(t, nil)
	from := testAddress(1).String()
	eng := newAppCallTestEngine(t, client, from)

	abiPath := testFixturePath(t, "testapp", "aplane_test.json")
	spec, err := appspec.Load(abiPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	method, err := spec.ResolveMethod("increment")
	if err != nil {
		t.Fatalf("ResolveMethod() error = %v", err)
	}
	wantArgs, err := method.EncodeArgs([]string{"5"})
	if err != nil {
		t.Fatalf("EncodeArgs() error = %v", err)
	}

	prepared, err := eng.PrepareAppCallMethod(context.Background(), MethodAppCallParams{
		ABIPath: abiPath,
		Method:  "increment",
		Args:    []string{"5"},
		RawAppCallParams: RawAppCallParams{
			AppID:        123,
			From:         from,
			Note:         "abi-call",
			LsigArgs:     map[string][]byte{"preimage": []byte("open")},
			OnCompletion: types.NoOpOC,
		},
	})
	if err != nil {
		t.Fatalf("PrepareAppCallMethod(success) error = %v", err)
	}

	if prepared.Method.Signature() != method.Signature() {
		t.Fatalf("Method.Signature() = %q, want %q", prepared.Method.Signature(), method.Signature())
	}
	if len(prepared.Prep.Transaction.ApplicationArgs) != len(wantArgs) {
		t.Fatalf("ApplicationArgs len = %d, want %d", len(prepared.Prep.Transaction.ApplicationArgs), len(wantArgs))
	}
	for i := range wantArgs {
		if !bytes.Equal(prepared.Prep.Transaction.ApplicationArgs[i], wantArgs[i]) {
			t.Fatalf("ApplicationArgs[%d] = %x, want %x", i, prepared.Prep.Transaction.ApplicationArgs[i], wantArgs[i])
		}
	}
	if string(prepared.Prep.Transaction.Note) != "abi-call" {
		t.Fatalf("Note = %q, want abi-call", string(prepared.Prep.Transaction.Note))
	}
	if string(prepared.Prep.LsigArgs["preimage"]) != "open" {
		t.Fatalf("LsigArgs = %#v, want propagated arg", prepared.Prep.LsigArgs)
	}
	if prepared.Prep.AppCallInfo == nil || prepared.Prep.AppCallInfo.Mode != "abi" || prepared.Prep.AppCallInfo.Method != method.Signature() {
		t.Fatalf("AppCallInfo = %#v, want abi metadata for %q", prepared.Prep.AppCallInfo, method.Signature())
	}
}

func newAppCallTestEngine(t *testing.T, client *algod.Client, address string) *Engine {
	t.Helper()

	eng, err := NewEngine("testnet",
		WithAlgodClient(client),
		WithAliasCache(cache.AliasCache{Aliases: map[string]string{}}),
		WithSignerCache(cache.NewSignerCache()),
		WithAuthCache(cache.NewAuthAddressCache()),
	)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	eng.SignerCache.AddAddress(address, "ed25519")
	eng.AuthCache.AuthAddresses[address] = ""
	return eng
}

func newMockAlgodClient(t *testing.T, compileResults map[string][]byte) *algod.Client {
	t.Helper()

	client, err := algod.MakeClientWithTransport(
		"http://mock-algod",
		"",
		nil,
		&mockAlgodTransport{t: t, compileResults: compileResults},
	)
	if err != nil {
		t.Fatalf("MakeClient() error = %v", err)
	}
	return client
}

type mockAlgodTransport struct {
	t              *testing.T
	compileResults map[string][]byte
}

func (m *mockAlgodTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.t.Helper()

	var (
		status = http.StatusOK
		body   []byte
	)

	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/v2/transactions/params":
		genesisHash, _ := base64.StdEncoding.DecodeString(config.AlgorandTestnetGenesisHash)
		payload, err := json.Marshal(models.TransactionParametersResponse{
			Fee:              1000,
			GenesisHash:      genesisHash,
			GenesisId:        "testnet-v1.0",
			LastRound:        77,
			ConsensusVersion: string(protocol.ConsensusV42),
			MinFee:           1000,
		})
		if err != nil {
			return nil, err
		}
		body = payload
	case req.Method == http.MethodPost && req.URL.Path == "/v2/teal/compile":
		source, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		compiled, ok := m.compileResults[string(source)]
		if !ok {
			status = http.StatusBadRequest
			body = []byte(`{"message":"unexpected compile input"}`)
			break
		}
		payload, err := json.Marshal(models.CompileResponse{
			Result: base64.StdEncoding.EncodeToString(compiled),
			Hash:   "TESTHASH",
		})
		if err != nil {
			return nil, err
		}
		body = payload
	default:
		status = http.StatusNotFound
		body = []byte(`{"message":"unexpected request"}`)
	}

	return &http.Response{
		StatusCode: status,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:    io.NopCloser(bytes.NewReader(body)),
		Request: req,
	}, nil
}

func writeTempProgram(t *testing.T, name string, data []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}
	return path
}
