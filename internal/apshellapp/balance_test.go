// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

const testAddress = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

func TestBalanceSingleAccountRequiresAlgod(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	res, err := app.Balance(context.Background(), BalanceRequest{Args: []string{testAddress, "algo"}})
	if !errors.Is(err, engine.ErrNoAlgodClient) {
		t.Fatalf("Balance() error = %v, want %v", err, engine.ErrNoAlgodClient)
	}
	if res != nil {
		t.Fatalf("Balance() result = %#v, want nil on error", res)
	}
}

func TestBalanceRejectsTooManyArgs(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	if _, err := app.Balance(context.Background(), BalanceRequest{Args: []string{"a", "b", "c"}}); err == nil {
		t.Fatal("Balance() error = nil, want usage error")
	}
}

// A set none of whose accounts can be queried is an error that names the
// count and the first failure, not an empty listing: here there is no algod.
func TestBalanceOfASetNoAccountOfWhichCanBeQueriedFails(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	cfg := config.DefaultConfig()
	eng.SetCache.Sets = map[string][]string{
		"team": {testAddress},
	}
	app := New(eng, cfg, t.TempDir())
	res, err := app.Balance(context.Background(), BalanceRequest{Args: []string{"@team"}})
	if !errors.Is(err, engine.ErrNoAlgodClient) || !strings.Contains(err.Error(), "none of the 1 account(s) could be queried: "+testAddress) {
		t.Fatalf("Balance() = %+v, %v; want the failed query of every account as the error", res, err)
	}
}

// balanceQueryApp is an app on an algod that answers each account's query
// with a balance of 1 ALGO, except for the accounts in failing, whose every
// query fails, and those in failingAgain, whose queries after the first fail.
// The accounts are aliased by name and form the set "team".
func balanceQueryApp(t *testing.T, aliases map[string]string, failing, failingAgain map[string]bool) *App {
	t.Helper()
	var mu sync.Mutex
	queries := map[string]int{}
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		address, ok := strings.CutPrefix(r.URL.Path, "/v2/accounts/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		queries[address]++
		n := queries[address]
		mu.Unlock()
		if failing[address] || (failingAgain[address] && n > 1) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.Account{Address: address, Amount: 1_000_000, MinBalance: 100_000, Status: "Offline"})
	}))
	t.Cleanup(node.Close)
	client, err := algod.MakeClient(node.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AlgodClient = client
	eng.AliasCache.Aliases = aliases
	team := make([]string, 0, len(aliases))
	for _, address := range aliases {
		team = append(team, address)
	}
	sort.Strings(team)
	eng.SetCache.Sets = map[string][]string{"team": team}
	return New(eng, config.DefaultConfig(), t.TempDir())
}

// An account of a set or of @all whose balance query fails is a
// balance_query_failed warning naming it and the error, not an account left
// out in silence; every account whose query succeeded is listed. The
// warnings come in the set's order, which for @all is sorted, and when no
// account can be queried the error names the first of them by its alias.
func TestMultiAccountBalanceWarnsOfEveryFailedQuery(t *testing.T) {
	alice, bob, carol := crypto.GenerateAccount().Address.String(), crypto.GenerateAccount().Address.String(), crypto.GenerateAccount().Address.String()
	aliases := map[string]string{"alice": alice, "bob": bob, "carol": carol}
	label := map[string]string{bob: "bob (" + bob + ")", carol: "carol (" + carol + ")", alice: "alice (" + alice + ")"}
	failed := []string{bob, carol}
	sort.Strings(failed)
	app := balanceQueryApp(t, aliases, map[string]bool{bob: true, carol: true}, nil)
	for _, set := range []string{"@team", "@all"} {
		res, err := app.Balance(context.Background(), BalanceRequest{Args: []string{set}})
		if err != nil {
			t.Fatalf("balance %s: %v", set, err)
		}
		if len(res.Balances) != 1 || res.Balances[0].Address != alice {
			t.Fatalf("balance %s listed %+v, want alice's balance only", set, res.Balances)
		}
		if len(res.Warnings) != 2 {
			t.Fatalf("balance %s warnings = %+v, want one for bob and one for carol", set, res.Warnings)
		}
		for i, address := range failed {
			warning := res.Warnings[i]
			if warning.Code != "balance_query_failed" || !strings.HasPrefix(warning.Message, "could not query "+label[address]+": ") ||
				!strings.Contains(warning.Message, "rate limited") {
				t.Fatalf("balance %s warnings = %+v, want balance_query_failed warnings naming %v in order", set, res.Warnings, failed)
			}
		}
	}

	all := []string{alice, bob, carol}
	sort.Strings(all)
	app = balanceQueryApp(t, aliases, map[string]bool{alice: true, bob: true, carol: true}, nil)
	want := "none of the 3 account(s) could be queried: " + label[all[0]] + ": "
	for i := 0; i < 5; i++ {
		if res, err := app.Balance(context.Background(), BalanceRequest{Args: []string{"@all"}}); err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Fatalf("balance @all = %+v, %v; want the error %q", res, err, want)
		}
	}
}

// A set with no accounts is an error, as for every command over a set: here
// a stored set emptied by removing its last member.
func TestBalanceOfAnEmptySetFails(t *testing.T) {
	app := balanceQueryApp(t, map[string]string{"alice": crypto.GenerateAccount().Address.String()}, nil, nil)
	app.eng.SetCache.Sets["team"] = []string{}
	if res, err := app.Balance(context.Background(), BalanceRequest{Args: []string{"@team"}}); err == nil || err.Error() != "no addresses resolved" {
		t.Fatalf("balance @team = %+v, %v; want the error for an empty set", res, err)
	}
}

// Holders lists every holder it found, with the balance it read to find it,
// whatever a later query of that account would answer, and warns of each
// account it could not query.
func TestHoldersKeepsEveryHolderFound(t *testing.T) {
	alice, bob, carol := crypto.GenerateAccount().Address.String(), crypto.GenerateAccount().Address.String(), crypto.GenerateAccount().Address.String()
	app := balanceQueryApp(t, map[string]string{"alice": alice, "bob": bob, "carol": carol},
		map[string]bool{carol: true}, map[string]bool{bob: true})
	res, err := app.Holders(context.Background(), nil)
	if err != nil {
		t.Fatalf("Holders() error = %v", err)
	}
	got := map[string]string{}
	for _, balance := range res.Balances {
		got[balance.Address] = balance.Alias
	}
	if !reflect.DeepEqual(got, map[string]string{alice: "alice", bob: "bob"}) || len(res.Addresses) != 2 {
		t.Fatalf("holders = %v (addresses %v), want alice and bob with their aliases", got, res.Addresses)
	}
	if len(res.Warnings) != 1 || res.Warnings[0].Code != "balance_query_failed" ||
		!strings.HasPrefix(res.Warnings[0].Message, "could not query carol ("+carol+"): ") {
		t.Fatalf("warnings = %+v, want one balance_query_failed warning naming carol", res.Warnings)
	}

	app = balanceQueryApp(t, map[string]string{"alice": alice}, map[string]bool{alice: true}, nil)
	if res, err := app.Holders(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "none of the 1 account(s) could be queried: alice ("+alice+"): ") {
		t.Fatalf("Holders() = %+v, %v; want the failed query of every account as the error", res, err)
	}
}

// ALGO is named in any case: "Algo" shows ALGO balances, as "algo" does, in
// each mode of balance and in holders, rather than an asset no account holds.
func TestBalanceAndHoldersNameAlgoInAnyCase(t *testing.T) {
	f := newArgsFixture(t)
	ctx := context.Background()
	for _, args := range [][]string{{"Algo"}, {"@all", "Algo"}, {argsNative, "Algo"}, {argsNative, "aLGO"}} {
		res, err := f.app.Balance(ctx, BalanceRequest{Args: args})
		if err != nil {
			t.Fatalf("balance %v: %v", args, err)
		}
		if res.Asset.AssetID != 0 || res.Asset.UnitName != "ALGO" {
			t.Fatalf("balance %v shows %+v, want ALGO", args, res.Asset)
		}
	}

	res, err := f.app.Holders(ctx, []string{"Algo"})
	if err != nil {
		t.Fatalf("holders Algo: %v", err)
	}
	if res.Asset.AssetID != 0 || len(res.Addresses) == 0 || len(res.Balances) != len(res.Addresses) {
		t.Fatalf("holders Algo = %+v, want the funded accounts' ALGO", res)
	}

	if _, err := f.app.Balance(ctx, BalanceRequest{Args: []string{argsNative, "nosuchcoin"}}); err == nil ||
		!strings.Contains(err.Error(), "unknown asset 'nosuchcoin'") {
		t.Fatalf("balance of an unknown asset: %v, want it refused", err)
	}
}
