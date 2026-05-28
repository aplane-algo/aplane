// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
)

// accountMockTransport implements http.RoundTripper for testing engine methods
// that depend on algod queries (AccountInformation, SuggestedParams, etc.)
// Named differently from mockAlgodTransport in app_call_test.go to avoid conflicts.
type accountMockTransport struct {
	t        *testing.T
	accounts map[string]models.Account
	txParams models.TransactionParametersResponse
	assets   map[uint64]models.Asset
}

func newAccountMockTransport(t *testing.T) *accountMockTransport {
	t.Helper()
	return &accountMockTransport{
		t:        t,
		accounts: make(map[string]models.Account),
		assets:   make(map[uint64]models.Asset),
		txParams: models.TransactionParametersResponse{
			ConsensusVersion: "test",
			Fee:              1000,
			GenesisId:        "testnet-v1.0",
			GenesisHash:      []byte("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="),
			LastRound:        1000,
			MinFee:           1000,
		},
	}
}

func (m *accountMockTransport) addAccount(addr string, amount uint64) {
	m.accounts[addr] = models.Account{
		Address:                     addr,
		Amount:                      amount,
		AmountWithoutPendingRewards: amount,
		MinBalance:                  100_000,
		Status:                      "Offline",
		Round:                       1,
	}
}

func (m *accountMockTransport) addAccountFull(acct models.Account) {
	m.accounts[acct.Address] = acct
}

func (m *accountMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	path := req.URL.Path

	// GET /v2/accounts/{address}
	if strings.HasPrefix(path, "/v2/accounts/") && req.Method == http.MethodGet {
		addr := path[len("/v2/accounts/"):]
		if idx := strings.Index(addr, "?"); idx >= 0 {
			addr = addr[:idx]
		}
		acct, ok := m.accounts[addr]
		if !ok {
			return makeJSONResp(http.StatusNotFound, map[string]string{"message": "account not found"}, req), nil
		}
		return makeJSONResp(http.StatusOK, acct, req), nil
	}

	// GET /v2/transactions/params
	if path == "/v2/transactions/params" && req.Method == http.MethodGet {
		return makeJSONResp(http.StatusOK, m.txParams, req), nil
	}

	return makeJSONResp(http.StatusNotFound, map[string]string{"message": fmt.Sprintf("unexpected request: %s %s", req.Method, path)}, req), nil
}

// makeJSONResp creates an http.Response with JSON body.
func makeJSONResp(status int, body interface{}, req *http.Request) *http.Response {
	data, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(data)),
		Request:    req,
	}
}

// newAccountMockAlgodClient creates an algod.Client backed by the accountMockTransport.
func newAccountMockAlgodClient(t *testing.T, transport *accountMockTransport) *algod.Client {
	t.Helper()
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, transport)
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	return client
}

// setupEngineWithMockAlgod creates an engine with mock algod and pre-populated caches.
func setupEngineWithMockAlgod(t *testing.T, transport *accountMockTransport) *Engine {
	t.Helper()

	client := newAccountMockAlgodClient(t, transport)

	signerCache := cache.NewSignerCache()
	for addr := range transport.accounts {
		signerCache.AddAddress(addr, "ed25519")
	}

	aliasCache := cache.AliasCache{Aliases: make(map[string]string)}
	cacheStore := cache.NewStore(t.TempDir())
	authCache := cache.NewAuthAddressCacheForStore(cacheStore)
	setCache := cache.SetCache{Sets: make(map[string][]string)}

	for addr, acct := range transport.accounts {
		if acct.AuthAddr != "" && acct.AuthAddr != addr {
			authCache.AuthAddresses[addr] = acct.AuthAddr
		}
	}

	eng, err := NewEngine("testnet",
		WithAlgodClient(client),
		WithCacheStore(cacheStore),
		WithSignerCache(signerCache),
		WithAliasCache(aliasCache),
		WithAuthCache(authCache),
		WithSetCache(setCache),
	)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return eng
}

// testAddr generates a deterministic Algorand address string for testing.
func testAddr(index int) string {
	var pk [32]byte
	pk[0] = byte(index)
	pk[1] = byte(index >> 8)
	return types.Address(pk).String()
}
