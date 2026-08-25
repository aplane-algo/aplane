// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
)

type connectRoundTripper struct {
	t       *testing.T
	handler func(*http.Request) (*http.Response, error)
}

func (rt connectRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.handler(req)
}

func TestConnectionStateSignerClientErrorsWhenDisconnected(t *testing.T) {
	state := NewState()

	if _, err := state.GetKeys(); err == nil || !strings.Contains(err.Error(), "not connected to Signer") {
		t.Fatalf("GetKeys() error = %v, want not connected", err)
	}
	if _, err := state.GetKeyTypes(); err == nil || !strings.Contains(err.Error(), "not connected to Signer") {
		t.Fatalf("GetKeyTypes() error = %v, want not connected", err)
	}
	if _, err := state.GetSignerStatus(); err == nil || !strings.Contains(err.Error(), "not connected to Signer") {
		t.Fatalf("GetSignerStatus() error = %v, want not connected", err)
	}
	if _, err := state.AdminGenerate("ed25519", nil); err == nil || !strings.Contains(err.Error(), "not connected to Signer") {
		t.Fatalf("AdminGenerate() error = %v, want not connected", err)
	}
	if _, err := state.RequestComponentsWithContext(t.Context(), signerapi.ComponentRequest{}); err == nil || !strings.Contains(err.Error(), "not connected to Signer") {
		t.Fatalf("RequestComponentsWithContext() error = %v, want not connected", err)
	}
	if _, err := state.RequestAssembleWithContext(t.Context(), signerapi.AssemblyRequest{}); err == nil || !strings.Contains(err.Error(), "not connected to Signer") {
		t.Fatalf("RequestAssembleWithContext() error = %v, want not connected", err)
	}
}

func TestConnectionStateSignerClientInheritsProgressWriter(t *testing.T) {
	var progress bytes.Buffer
	client := signerclient.NewSignerClientWithToken("http://signer.test", "token")
	state := &ConnectionState{
		SignerClient:      client,
		SignerProgressOut: &progress,
	}

	got, err := state.signerClient()
	if err != nil {
		t.Fatalf("signerClient() error = %v", err)
	}
	if got.ProgressOut != &progress {
		t.Fatal("signer client did not inherit progress writer")
	}
}

func TestConnectionStateClientWrappersCallSignerEndpoints(t *testing.T) {
	client := signerclient.NewSignerClientWithToken("http://signer.test", "token")
	client.Client = &http.Client{Transport: connectRoundTripper{t: t, handler: func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/keys":
			return connectJSONResponse(t, http.StatusOK, signerapi.KeysResponse{
				Count: 1,
				Keys:  []signerapi.KeyInfo{{Address: "ADDR1", KeyType: "ed25519"}},
			}, req), nil
		case req.Method == http.MethodGet && req.URL.Path == "/keytypes":
			return connectJSONResponse(t, http.StatusOK, signerapi.KeyTypesResponse{
				KeyTypes: []signerapi.KeyTypeInfo{{KeyType: "ed25519"}},
			}, req), nil
		case req.Method == http.MethodGet && req.URL.Path == "/status":
			return connectJSONResponse(t, http.StatusOK, signerapi.StatusResponse{
				KeyCount:       1,
				KeysetRevision: 2,
			}, req), nil
		case req.Method == http.MethodPost && req.URL.Path == "/admin/generate":
			return connectJSONResponse(t, http.StatusOK, signerapi.AdminGenerateResponse{
				Address: "ADDR2",
				KeyType: "ed25519",
			}, req), nil
		case req.Method == http.MethodDelete && req.URL.Path == "/admin/keys":
			return connectJSONResponse(t, http.StatusOK, signerapi.AdminDeleteResponse{Success: true}, req), nil
		case req.Method == http.MethodPost && req.URL.Path == "/sign/component":
			var componentReq signerapi.ComponentRequest
			if err := json.NewDecoder(req.Body).Decode(&componentReq); err != nil {
				t.Fatal(err)
			}
			return connectJSONResponse(t, http.StatusOK, signerapi.ComponentResponse{
				RequestID: componentReq.RequestID,
				Components: []signerapi.Component{{
					TargetIndex:     0,
					Kind:            signerapi.ComponentTargetKindSentry,
					Signature:       "aabb",
					SignatureScheme: "aplane.witness-falcon1024.v1",
				}},
			}, req), nil
		case req.Method == http.MethodPost && req.URL.Path == "/sign/assemble":
			var assemblyReq signerapi.AssemblyRequest
			if err := json.NewDecoder(req.Body).Decode(&assemblyReq); err != nil {
				t.Fatal(err)
			}
			return connectJSONResponse(t, http.StatusOK, signerapi.AssemblyResponse{
				RequestID:   assemblyReq.RequestID,
				SignedGroup: []string{"ccdd"},
			}, req), nil
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
			return nil, nil
		}
	}}}

	state := &ConnectionState{SignerClient: client}

	keys, err := state.GetKeys()
	if err != nil || keys.Count != 1 {
		t.Fatalf("GetKeys() = (%+v, %v), want count=1 nil", keys, err)
	}
	keyTypes, err := state.GetKeyTypes()
	if err != nil || len(keyTypes.KeyTypes) != 1 {
		t.Fatalf("GetKeyTypes() = (%+v, %v), want one key type nil", keyTypes, err)
	}
	identity, err := state.GetSignerStatus()
	if err != nil || identity.KeysetRevision != 2 {
		t.Fatalf("GetSignerStatus() = (%+v, %v), want revision=2 nil", identity, err)
	}
	gen, err := state.AdminGenerate("ed25519", nil)
	if err != nil || gen.Address != "ADDR2" {
		t.Fatalf("AdminGenerate() = (%+v, %v), want ADDR2 nil", gen, err)
	}
	del, err := state.AdminDeleteKey("ADDR2")
	if err != nil || !del.Success {
		t.Fatalf("AdminDeleteKey() = (%+v, %v), want success nil", del, err)
	}
	component, err := state.RequestComponentsWithContext(t.Context(), signerapi.ComponentRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets: []signerapi.ComponentTarget{{
			TargetIndex: 0, Kind: signerapi.ComponentTargetKindSentry,
			ComponentKey: "75OU3CR55IDLKDFEZSFWLIRGE2I5Q337D3NTKAEHJ6K7FGYON5AA",
		}},
	})
	if err != nil || len(component.Components) != 1 {
		t.Fatalf("RequestComponentsWithContext() = (%+v, %v), want one signature nil", component, err)
	}
	assembly, err := state.RequestAssembleWithContext(t.Context(), signerapi.AssemblyRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets: []signerapi.AssemblyTarget{{
			TargetIndex:     0,
			Kind:            signerapi.AssemblyTargetKindGuarded,
			AuthAddress:     "ADDR1",
			UserSignature:   "aabb",
			SentrySignature: "bbcc",
		}},
	})
	if err != nil || len(assembly.SignedGroup) != 1 {
		t.Fatalf("RequestAssembleWithContext() = (%+v, %v), want one signed txn nil", assembly, err)
	}
}

func connectJSONResponse(t *testing.T, status int, body interface{}, req *http.Request) *http.Response {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(data)),
		Request:    req,
	}
}
