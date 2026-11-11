// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestDecodeStrictJSON(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{name: "known fields", body: `{"requests":[{"txn_bytes_hex":"00","lsig_args":{"x":"00"}}]}`},
		{name: "trailing whitespace", body: "{\"requests\":[]}\n \t"},
		{name: "unknown top-level field", body: `{"requests":[],"network":"testnet"}`, wantErr: `request has unknown field "network"`},
		{name: "unknown nested field", body: `{"requests":[{"txn_bytes_hex":"00","lsig_size":4000}]}`, wantErr: `request has unknown field "lsig_size"`},
		{name: "unknown field inside an object value", body: `{"requests":[{"txn_bytes_hex":"00","app_call_info":{"mode":"abi","label":"x"}}]}`, wantErr: `request has unknown field "label"`},
		{name: "case variant of a retired field", body: `{"requests":[{"txn_bytes_hex":"00","LSIG_SIZE":4000}]}`, wantErr: `request has unknown field "LSIG_SIZE"`},
		{name: "second JSON value", body: `{"requests":[]}{"requests":[]}`, wantErr: "request body has data after the JSON value"},
		{name: "trailing garbage", body: `{"requests":[]} x`, wantErr: "request body has data after the JSON value"},
		{name: "control characters are quoted", body: `{"requests":[],"a\u001b[31m":1}`, wantErr: `request has unknown field "a\x1b[31m"`},
		{name: "non-ASCII is quoted as ASCII", body: `{"requests":[],"r` + string(rune(0xe9)) + string(rune(0x202e)) + `":1}`, wantErr: `request has unknown field "r\u00e9\u202e"`},
		{name: "long name is cut", body: `{"requests":[],"` + strings.Repeat("y", 200) + `":1}`, wantErr: `request has unknown field "` + strings.Repeat("y", maxQuotedFieldNameBytes) + `"...`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req signerapi.GroupSignRequest
			err := decodeStrictJSON(strings.NewReader(tt.body), &req)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("decodeStrictJSON() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("decodeStrictJSON() accepted %s", tt.body)
			}
			status, msg := decodeError(err)
			if status != http.StatusBadRequest || msg != tt.wantErr {
				t.Fatalf("decodeError() = %d %q, want 400 %q", status, msg, tt.wantErr)
			}
		})
	}
}

func TestDecodeStrictJSONKeepsGenericRefusalForMalformedJSON(t *testing.T) {
	var req signerapi.GroupSignRequest
	err := decodeStrictJSON(strings.NewReader(`{"requests":[`), &req)
	if err == nil {
		t.Fatal("decodeStrictJSON() accepted truncated JSON")
	}
	if status, msg := decodeError(err); status != http.StatusBadRequest || msg != "invalid JSON" {
		t.Fatalf("decodeError() = %d %q, want 400 \"invalid JSON\"", status, msg)
	}
}

// strictBodyEndpoints is every signer HTTP route that reads a request body.
func strictBodyEndpoints(server *Signer) []struct {
	path    string
	handler http.HandlerFunc
} {
	return []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/sign", server.handleSign},
		{"/plan", server.handlePlan},
		{"/sign/cancel", server.handleSignCancel},
		{"/sign/component", server.handleSignComponent},
		{"/sign/assemble", server.handleSignAssemble},
		{"/sign/rotating/prepare", server.handleRotatingPrepare},
		{"/sign/rotating/sign", server.handleRotatingSign},
		{"/admin/generate", server.handleAdminGenerate},
		{"/admin/rotating/recover", server.handleRotatingRecover},
	}
}

func TestEveryBodyEndpointRefusesUnknownFields(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	for _, endpoint := range strictBodyEndpoints(server) {
		t.Run(endpoint.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			endpoint.handler(w, requestWithIdentity(http.MethodPost, endpoint.path, []byte(`{"request_idd":"x"}`)))
			assertUnknownFieldRefusal(t, w, `request has unknown field "request_idd"`)
		})
	}
}

func TestSignAndPlanRefuseRetiredLogicSigSize(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	body := []byte(`{"requests":[{"txn_bytes_hex":"00","lsig_size":4000}]}`)
	for _, endpoint := range strictBodyEndpoints(server)[:2] {
		w := httptest.NewRecorder()
		endpoint.handler(w, requestWithIdentity(http.MethodPost, endpoint.path, body))
		assertUnknownFieldRefusal(t, w, `request has unknown field "lsig_size"`)
	}
}

func assertUnknownFieldRefusal(t *testing.T, w *httptest.ResponseRecorder, want string) {
	t.Helper()
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	var resp signerapi.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.Code != signerapi.ErrCodeBadRequest || resp.Error != want {
		t.Fatalf("error = %q code %q, want %q code %q", resp.Error, resp.Code, want, signerapi.ErrCodeBadRequest)
	}
}

// Every request type's encoding, with every field set, decodes strictly into
// the same type: no field is written that the server would refuse.
func TestRequestDTOsRoundTripThroughStrictDecoder(t *testing.T) {
	for _, value := range []any{
		&signerapi.GroupSignRequest{},
		&signerapi.CancelSignRequest{},
		&signerapi.ComponentRequest{},
		&signerapi.AssemblyRequest{},
		&signerapi.RotatingPrepareRequest{},
		&signerapi.RotatingSignRequest{},
		&signerapi.AdminGenerateRequest{},
		&signerapi.RotatingRecoverRequest{},
	} {
		typ := reflect.TypeOf(value).Elem()
		t.Run(typ.Name(), func(t *testing.T) {
			filled := reflect.New(typ)
			fillEveryField(t, filled.Elem())
			encoded, err := json.Marshal(filled.Interface())
			if err != nil {
				t.Fatal(err)
			}
			decoded := reflect.New(typ)
			if err := decodeStrictJSON(bytes.NewReader(encoded), decoded.Interface()); err != nil {
				t.Fatalf("decodeStrictJSON(%s) error = %v", encoded, err)
			}
			if !reflect.DeepEqual(decoded.Interface(), filled.Interface()) {
				t.Fatalf("round trip changed the request\nsent: %s", encoded)
			}
		})
	}
}

func fillEveryField(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fillEveryField(t, v.Elem())
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fillEveryField(t, v.Index(0))
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		key := reflect.New(v.Type().Key()).Elem()
		fillEveryField(t, key)
		elem := reflect.New(v.Type().Elem()).Elem()
		fillEveryField(t, elem)
		v.SetMapIndex(key, elem)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				fillEveryField(t, v.Field(i))
			}
		}
	default:
		t.Fatalf("fillEveryField: unsupported kind %s", v.Kind())
	}
}

// The request fixtures pin the SDKs' request shapes; each decodes strictly.
func TestRequestContractFixturesDecodeStrictly(t *testing.T) {
	fixtures := map[string]func() any{
		"group_sign_request_mixed.json":            func() any { return &signerapi.GroupSignRequest{} },
		"group_sign_request_native_pq.json":        func() any { return &signerapi.GroupSignRequest{} },
		"group_sign_request_passthrough_lsig.json": func() any { return &signerapi.GroupSignRequest{} },
		"assembly_request_mixed.json":              func() any { return &signerapi.AssemblyRequest{} },
		"component_request.json":                   func() any { return &signerapi.ComponentRequest{} },
		"cancel_sign_request.json":                 func() any { return &signerapi.CancelSignRequest{} },
		"rotating_prepare_request.json":            func() any { return &signerapi.RotatingPrepareRequest{} },
		"rotating_sign_request.json":               func() any { return &signerapi.RotatingSignRequest{} },
		"rotating_recover_request.json":            func() any { return &signerapi.RotatingRecoverRequest{} },
		"admin_generate_request_generic.json":      func() any { return &signerapi.AdminGenerateRequest{} },
	}
	dir := filepath.Join("..", "..", "..", "test", "contracts", "signerapi")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "_request") {
			if _, ok := fixtures[entry.Name()]; !ok {
				t.Fatalf("request fixture %s is not checked here", entry.Name())
			}
		}
	}
	for name, newValue := range fixtures {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := decodeStrictJSON(bytes.NewReader(raw), newValue()); err != nil {
			t.Fatalf("%s: decodeStrictJSON() error = %v", name, err)
		}
	}
}

// The in-repo client sends every body endpoint a request the strict decoder
// accepts. The capture server decodes each body as the signer would, then
// refuses it so the client stops there.
func TestSignerClientRequestsDecodeStrictly(t *testing.T) {
	requestTypes := map[string]func() any{
		"/sign":                   func() any { return &signerapi.GroupSignRequest{} },
		"/plan":                   func() any { return &signerapi.GroupSignRequest{} },
		"/sign/cancel":            func() any { return &signerapi.CancelSignRequest{} },
		"/sign/component":         func() any { return &signerapi.ComponentRequest{} },
		"/sign/assemble":          func() any { return &signerapi.AssemblyRequest{} },
		"/sign/rotating/prepare":  func() any { return &signerapi.RotatingPrepareRequest{} },
		"/sign/rotating/sign":     func() any { return &signerapi.RotatingSignRequest{} },
		"/admin/generate":         func() any { return &signerapi.AdminGenerateRequest{} },
		"/admin/rotating/recover": func() any { return &signerapi.RotatingRecoverRequest{} },
	}
	var mu sync.Mutex
	decoded := map[string]int{}
	var failures []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			writeJSON(w, http.StatusOK, signerapi.StatusResponse{State: "unlocked", ReadyForSigning: true, ApprovalWaitSeconds: 60})
			return
		}
		newValue, ok := requestTypes[r.URL.Path]
		mu.Lock()
		defer mu.Unlock()
		if !ok {
			failures = append(failures, "unexpected path "+r.URL.Path)
		} else if err := decodeStrictJSON(r.Body, newValue()); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", r.URL.Path, err))
		} else {
			decoded[r.URL.Path]++
		}
		writeErrorJSON(w, http.StatusBadRequest, "captured")
	}))
	defer ts.Close()

	client := signerclient.NewSignerClient(ts.URL)
	client.ProgressOut = io.Discard
	ctx := context.Background()
	appCall := &signerapi.AppCallInfo{Mode: "abi", Method: "pay(uint64)void"}
	resources := &signerapi.LogicSigResourceUsage{ProgramBytes: 100, ArgumentBytes: 10, MaxOpcodeCost: 700}
	signEntry := signerapi.SignRequest{AuthAddress: "AUTH", TxnSender: "SENDER", TxnBytesHex: "00", LsigArgs: map[string]string{"a": "00"}, AppCallInfo: appCall}
	withForeign := []signerapi.SignRequest{
		signEntry,
		{TxnBytesHex: "01", LsigResources: resources},
		{TxnBytesHex: "02", PQScheme: signerapi.PQSchemeFalcon1024},
	}
	withPassthrough := []signerapi.SignRequest{signEntry, {SignedTxnHex: "03", LsigResources: resources}}

	calls := []func() error{
		func() error { _, err := client.RequestGroupPlanWithContext(ctx, withForeign); return err },
		func() error { _, err := client.RequestGroupPlanWithContext(ctx, withPassthrough); return err },
		func() error { _, err := client.RequestGroupSignWithContext(ctx, withForeign); return err },
		func() error { _, err := client.RequestGroupSignWithContext(ctx, withPassthrough); return err },
		func() error { return client.CancelSignRequestWithContext(ctx, "req-1") },
		func() error {
			_, err := client.RequestComponentsWithContext(ctx, signerapi.ComponentRequest{
				RequestID:     "req-2",
				GroupBytesHex: []string{"00", "01", "02", "03", "04"},
				Targets: []signerapi.ComponentTarget{{
					TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: "AUTH",
					LsigArgs: map[string]string{"a": "00"}, AppCallInfo: appCall,
				}},
				ContextualPositions: []signerapi.ComponentContextPosition{
					{TargetIndex: 1, AuthAddress: "HELD", LsigArgs: map[string]string{"b": "00"}, AppCallInfo: appCall},
					{TargetIndex: 2, LsigResources: resources},
					{TargetIndex: 3, PQScheme: signerapi.PQSchemeFalcon1024},
				},
				DummyPositions: []signerapi.ComponentDummyPosition{{TargetIndex: 4}},
			})
			return err
		},
		func() error {
			_, err := client.RequestComponentsWithContext(ctx, signerapi.ComponentRequest{
				RequestID:     "req-3",
				GroupBytesHex: []string{"00", "01"},
				Targets:       []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindCosigner, ComponentKey: "KEY", AppCallInfo: appCall}},
				ContextualPositions: []signerapi.ComponentContextPosition{
					{TargetIndex: 1, LsigResources: resources},
				},
			})
			return err
		},
		func() error {
			_, err := client.RequestAssembleWithContext(ctx, signerapi.AssemblyRequest{
				RequestID:     "req-4",
				GroupBytesHex: []string{"00", "01"},
				Targets: []signerapi.AssemblyTarget{{
					TargetIndex: 0, Kind: signerapi.AssemblyTargetKindBoundedCosigner, AuthAddress: "AUTH",
					BaseSignatures: []string{"aa"}, BoundedRuntimeArgs: map[string]string{"a": "00"},
					AssemblyReceipt: "bb", BaseSourceRequestID: "req-2",
					CosignerSignature: "cc", CosignerSourceRequestID: "req-3",
				}},
				Passthrough: []signerapi.AssemblyPassthroughItem{{TargetIndex: 1, SignedTxnHex: "03"}},
			})
			return err
		},
		func() error {
			_, err := client.PrepareRotatingWithContext(ctx, signerapi.RotatingPrepareRequest{RequestID: "req-5", Account: "ACCT", TxnBytesHex: "00"})
			return err
		},
		func() error {
			_, err := client.SignRotatingWithContext(ctx, signerapi.RotatingSignRequest{RequestID: "req-6", Account: "ACCT", Transactions: []string{"00"}, AppCallInfo: appCall})
			return err
		},
		func() error {
			_, err := client.AdminGenerateWithContext(ctx, "aplane.ed25519.v1", map[string]string{"p": "v"})
			return err
		},
		func() error {
			stage := uint64(7)
			_, err := client.RotatingRecoverWithContext(ctx, signerapi.RotatingRecoverRequest{
				Account: "ACCT", Action: signerapi.RotatingRecoverActionStart, Stage: &stage, Window: 2, MaxStages: 3, TimeoutSeconds: 4,
			})
			return err
		},
	}
	for i, call := range calls {
		if err := call(); err == nil || !strings.Contains(err.Error(), "captured") {
			t.Fatalf("call %d: error = %v, want the capture server's refusal", i, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(failures) != 0 {
		t.Fatalf("strict decode refused client requests:\n%s", strings.Join(failures, "\n"))
	}
	var missing []string
	for path := range requestTypes {
		if decoded[path] == 0 {
			missing = append(missing, path)
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Fatalf("no client request reached %v", missing)
	}
}
