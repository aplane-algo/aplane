// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	algoCrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
)

// holders() returns addresses, which leave no room for a warning, so an
// account it could not query, and which may hold the asset, makes it throw,
// naming the account, rather than drop out. In the filter form only the
// failures of the addresses asked about count.
func TestJSHoldersThrowsForAnAccountItCouldNotQuery(t *testing.T) {
	alice, bob, carol := algoCrypto.GenerateAccount().Address.String(),
		algoCrypto.GenerateAccount().Address.String(), algoCrypto.GenerateAccount().Address.String()
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		address, ok := strings.CutPrefix(r.URL.Path, "/v2/accounts/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		if address == bob {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		amount := uint64(1_000_000)
		if address == carol {
			amount = 0
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.Account{Address: address, Amount: amount, Status: "Offline"})
	}))
	t.Cleanup(node.Close)
	client, err := algod.MakeClient(node.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	eng, vm, _ := newTestAPI(t)
	eng.AlgodClient = client
	eng.AliasCache.Aliases = map[string]string{"alice": alice, "bob": bob, "carol": carol}

	failure := "holders() error: could not query 1 account(s), bob (" + bob + "): "
	for _, script := range []string{`holders("algo")`, `holders(["` + alice + `", "` + bob + `"], "algo")`} {
		if got, err := vm.RunString(script); err == nil || !strings.Contains(err.Error(), failure) {
			t.Fatalf("%s = %v, %v; want the error %q", script, got, err, failure)
		}
	}
	got, err := vm.RunString(`JSON.stringify(holders(["` + alice + `", "` + carol + `"], "algo"))`)
	if err != nil || got.String() != `["`+alice+`"]` {
		t.Fatalf("holders([alice, carol]) = %v, %v; want [alice], bob's failure not counting", got, err)
	}
}
