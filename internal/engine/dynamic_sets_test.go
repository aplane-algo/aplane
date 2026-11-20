// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
)

// @all and @signers list their accounts sorted, so a command over one, and
// the error that names its first failed account, is the same every time.
func TestDynamicSetsAreSorted(t *testing.T) {
	eng := setupTestEngine(t)
	eng.AliasCache.Aliases = map[string]string{}
	var want []string
	for i := 0; i < 20; i++ {
		address := crypto.GenerateAccount().Address.String()
		eng.AliasCache.Aliases[fmt.Sprintf("a%02d", i)] = address
		eng.SignerCache.AddAddress(address, "ed25519", "ed25519")
		want = append(want, address)
	}
	sort.Strings(want)

	for _, set := range []string{"@all", "@signers"} {
		got, err := eng.NewAddressResolver().ResolveList([]string{set})
		if err != nil {
			t.Fatalf("%s: %v", set, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s = %v, want the accounts sorted %v", set, got, want)
		}
	}
	if got, err := eng.ListAllAddresses(); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ListAllAddresses() = %v, %v; want the accounts sorted", got, err)
	}
}

// @holders(<asset>) fails when an account could not be queried, naming it,
// rather than leaving out an account that may hold the asset: the set drives
// sends and sweeps.
func TestHoldersSetFailsWhenAnAccountCannotBeQueried(t *testing.T) {
	alice, bob := crypto.GenerateAccount().Address.String(), crypto.GenerateAccount().Address.String()
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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.Account{Address: address, Amount: 1_000_000, Status: "Offline"})
	}))
	t.Cleanup(node.Close)
	client, err := algod.MakeClient(node.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	eng := setupTestEngine(t)
	eng.AlgodClient = client
	eng.AliasCache.Aliases = map[string]string{"alice": alice, "bob": bob}

	got, err := eng.NewAddressResolver().ResolveList([]string{"@holders(algo)"})
	want := "@holders(algo): could not query 1 account(s), bob (" + bob + "): "
	if err == nil || !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("@holders(algo) = %v, %v; want the error %q", got, err, want)
	}

	eng.AliasCache.Aliases = map[string]string{"alice": alice}
	if got, err := eng.NewAddressResolver().ResolveList([]string{"@holders(algo)"}); err != nil || !reflect.DeepEqual(got, []string{alice}) {
		t.Fatalf("@holders(algo) with every account answering = %v, %v; want [alice]", got, err)
	}
}
