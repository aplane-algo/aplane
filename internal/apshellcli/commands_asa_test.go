// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/config"
)

// TestCmdInfoShowsTheAssetsSupplyAndRoles pins that `info <asa-id>` prints
// the real total supply and creator, and that its machine result (what MCP
// returns) carries every field ASAInfo reads, the role addresses and
// default-frozen included.
func TestCmdInfoShowsTheAssetsSupplyAndRoles(t *testing.T) {
	params := models.AssetParams{
		Creator: types.Address{81}.String(), Manager: types.Address{82}.String(),
		Reserve: types.Address{83}.String(), Freeze: types.Address{84}.String(),
		Clawback: types.Address{85}.String(), DefaultFrozen: true,
		Total: 10_000_000_000_000_000_000, Decimals: 6, Name: "Token", UnitName: "TOK", Url: "https://example.test",
	}
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/assets/777" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.Asset{Index: 777, Params: params})
	}))
	defer node.Close()

	eng := newIsolatedTestEngine(t, "testnet")
	algodClient, err := algod.MakeClient(node.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	eng.AlgodClient = algodClient
	eng.AsaCache = cache.LoadASACacheFromStore(eng.CacheStore, "testnet")
	repl := &REPLState{App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir()), DataDir: t.TempDir()}

	result, err := repl.cmdInfo([]string{"777"}, nil)
	if err != nil {
		t.Fatalf("cmdInfo() error = %v", err)
	}
	var text bytes.Buffer
	if err := result.RenderText(&text); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"Total Supply: 10000000000000000000", "Creator: " + params.Creator, "URL: https://example.test"} {
		if !strings.Contains(text.String(), line) {
			t.Errorf("text output lacks %q:\n%s", line, text.String())
		}
	}

	machine, err := result.MarshalMachine()
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(machine))
	decoder.UseNumber()
	var got map[string]interface{}
	if err := decoder.Decode(&got); err != nil {
		t.Fatal(err)
	}
	want := map[string]interface{}{
		"asset_id": json.Number("777"), "name": "Token", "unit_name": "TOK", "decimals": json.Number("6"),
		"total": json.Number("10000000000000000000"), "url": "https://example.test",
		"creator": params.Creator, "manager": params.Manager, "reserve": params.Reserve,
		"freeze": params.Freeze, "clawback": params.Clawback, "default_frozen": true,
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("machine result %s = %v, want %v", key, got[key], value)
		}
	}
}
