// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package chainread

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// testnetGenesis is TestNet's genesis hash, which the default resolver maps
// to the "testnet" token.
var testnetGenesis = mustDecode("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=")

func mustDecode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

type fakeNode struct {
	genesis  []byte
	authAddr string
	round    uint64
	failAcct bool
	// asset is served at /v2/assets/<assetIndex>; assetIndex 0 serves none.
	assetIndex uint64
	asset      map[string]any
}

func (f *fakeNode) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/versions":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"genesis_hash_b64": base64.StdEncoding.EncodeToString(f.genesis),
				"genesis_id":       "test",
				"versions":         []string{"v2"},
				"build":            map[string]any{},
			})
		case strings.HasPrefix(r.URL.Path, "/v2/accounts/"):
			if f.failAcct {
				http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
				return
			}
			if r.URL.Query().Get("exclude") != "all" {
				t.Errorf("account read did not exclude holdings: %s", r.URL.RawQuery)
			}
			body := map[string]any{"address": strings.TrimPrefix(r.URL.Path, "/v2/accounts/"), "round": f.round}
			if f.authAddr != "" {
				body["auth-addr"] = f.authAddr
			}
			_ = json.NewEncoder(w).Encode(body)
		case strings.HasPrefix(r.URL.Path, "/v2/assets/"):
			if f.assetIndex == 0 || r.URL.Path != fmt.Sprintf("/v2/assets/%d", f.assetIndex) {
				http.Error(w, `{"message":"asset does not exist"}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"index": f.assetIndex, "params": f.asset})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func readerFor(srv *httptest.Server) Reader {
	return Reader{
		Resolver: apconfig.DefaultGenesisHashNetworkResolver,
		AlgodConfig: func(network string) (*apconfig.AlgodNetworkConfig, error) {
			if network != "testnet" {
				return nil, errors.New("not configured")
			}
			return &apconfig.AlgodNetworkConfig{Server: srv.URL}, nil
		},
		MakeClient: func(server, token string) (*algod.Client, error) { return algod.MakeClient(server, token) },
	}
}

var account = types.Address{7}

func TestReadAccountWithoutAuthAddressIsSelfAuthorized(t *testing.T) {
	node := &fakeNode{genesis: testnetGenesis, round: 1234}
	view, err := readerFor(node.serve(t)).ReadAccount(context.Background(), testnetGenesis, account)
	if err != nil {
		t.Fatal(err)
	}
	if view.Authorizer != account || view.Round != 1234 {
		t.Fatalf("view = %+v", view)
	}
}

func TestReadAccountReturnsAuthAddress(t *testing.T) {
	stage := types.Address{9}
	node := &fakeNode{genesis: testnetGenesis, round: 99, authAddr: stage.String()}
	view, err := readerFor(node.serve(t)).ReadAccount(context.Background(), testnetGenesis, account)
	if err != nil {
		t.Fatal(err)
	}
	if view.Authorizer != stage {
		t.Fatalf("authorizer = %s, want %s", view.Authorizer, stage)
	}
}

func TestReadAccountFailsClosed(t *testing.T) {
	otherGenesis := make([]byte, 32)
	tests := []struct {
		name    string
		node    fakeNode
		genesis []byte
		mutate  func(*Reader)
	}{
		{name: "node on another network", node: fakeNode{genesis: otherGenesis, round: 5}, genesis: testnetGenesis},
		{name: "unmapped genesis hash", node: fakeNode{genesis: otherGenesis, round: 5}, genesis: otherGenesis},
		{name: "no algod for network", node: fakeNode{genesis: testnetGenesis, round: 5}, genesis: testnetGenesis, mutate: func(r *Reader) {
			r.AlgodConfig = func(string) (*apconfig.AlgodNetworkConfig, error) { return nil, errors.New("not configured") }
		}},
		{name: "account read error", node: fakeNode{genesis: testnetGenesis, failAcct: true}, genesis: testnetGenesis},
		{name: "zero round", node: fakeNode{genesis: testnetGenesis}, genesis: testnetGenesis},
		{name: "invalid auth address", node: fakeNode{genesis: testnetGenesis, round: 5, authAddr: "NOTANADDRESS"}, genesis: testnetGenesis},
		{name: "unconfigured reader", node: fakeNode{genesis: testnetGenesis, round: 5}, genesis: testnetGenesis, mutate: func(r *Reader) { r.MakeClient = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := tt.node
			r := readerFor(node.serve(t))
			if tt.mutate != nil {
				tt.mutate(&r)
			}
			if _, err := r.ReadAccount(context.Background(), tt.genesis, account); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestReadAssetFromTheVerifiedNode(t *testing.T) {
	creator := types.Address{3}.String()
	node := &fakeNode{genesis: testnetGenesis, assetIndex: 42, asset: map[string]any{
		"creator": creator, "decimals": 6, "total": 1000, "unit-name": "XYZ", "name": "Example", "clawback": creator,
	}}
	params, err := readerFor(node.serve(t)).ReadAsset(context.Background(), testnetGenesis, 42)
	if err != nil {
		t.Fatal(err)
	}
	if params.UnitName != "XYZ" || params.Decimals != 6 || params.Creator != creator || params.Clawback != creator {
		t.Fatalf("params = %+v", params)
	}
}

func TestReadAssetFailsClosed(t *testing.T) {
	for name, node := range map[string]fakeNode{
		"node on another network": {genesis: make([]byte, 32), assetIndex: 42, asset: map[string]any{"creator": types.Address{3}.String()}},
		"no such asset":           {genesis: testnetGenesis},
	} {
		t.Run(name, func(t *testing.T) {
			node := node
			if _, err := readerFor(node.serve(t)).ReadAsset(context.Background(), testnetGenesis, 42); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("ReadAsset() error = %v, want ErrUnavailable", err)
			}
		})
	}
}
