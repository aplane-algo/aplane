// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package testutil

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/util"
)

// MockAccountInfo represents mock account information for testing
type MockAccountInfo struct {
	Address              string
	Balance              uint64 // In microAlgos
	MinBalance           uint64
	Assets               []models.AssetHolding
	Status               string // "Offline", "Online"
	AuthAddr             string // Auth address for rekeyed accounts
	TotalAppsOptedIn     uint64
	TotalAssetsOptedIn   uint64
	TotalCreatedApps     uint64
	TotalCreatedAssets   uint64
	AppsLocalState       []models.ApplicationLocalState
	AppsOptedInToResults []models.ApplicationLocalState
}

// MockAlgodClient implements a mock Algorand client for testing
type MockAlgodClient struct {
	Accounts     map[string]*MockAccountInfo
	SuggestedFee uint64
	GenesisID    string
	GenesisHash  [32]byte
}

// NewMockAlgodClient creates a new mock Algod client with sensible defaults
func NewMockAlgodClient() *MockAlgodClient {
	return &MockAlgodClient{
		Accounts:     make(map[string]*MockAccountInfo),
		SuggestedFee: 1000,
		GenesisID:    "testnet-v1.0",
	}
}

// AddAccount adds a mock account with the given balance
func (m *MockAlgodClient) AddAccount(address string, balanceMicroAlgos uint64) {
	m.Accounts[address] = &MockAccountInfo{
		Address:    address,
		Balance:    balanceMicroAlgos,
		MinBalance: 100000, // 0.1 ALGO default min balance
		Status:     "Offline",
	}
}

// AddAccountWithInfo adds a mock account with full info
func (m *MockAlgodClient) AddAccountWithInfo(info *MockAccountInfo) {
	m.Accounts[info.Address] = info
}

// GetAccountInfo returns mock account information
func (m *MockAlgodClient) GetAccountInfo(address string) (*MockAccountInfo, bool) {
	info, ok := m.Accounts[address]
	return info, ok
}

// MockSignerServer creates a mock signer HTTP server for testing
type MockSignerServer struct {
	Server           *httptest.Server
	Keys             map[string]string // address -> key type
	SignatureHandler func(req util.SignRequest) (*util.SignResponse, error)
	KeysHandler      func() (*util.KeysResponse, error)
}

// NewMockSignerServer creates a new mock signer server
func NewMockSignerServer(t *testing.T) *MockSignerServer {
	t.Helper()

	m := &MockSignerServer{
		Keys: make(map[string]string),
	}

	// Default signature handler - returns 64-byte zero signature
	m.SignatureHandler = func(req util.SignRequest) (*util.SignResponse, error) {
		return &util.SignResponse{
			Approved:  true,
			Signature: hex.EncodeToString(make([]byte, 64)),
		}, nil
	}

	// Default keys handler
	m.KeysHandler = func() (*util.KeysResponse, error) {
		keys := make([]util.KeyInfo, 0, len(m.Keys))
		for addr, keyType := range m.Keys {
			keys = append(keys, util.KeyInfo{
				Address: addr,
				KeyType: keyType,
			})
		}
		return &util.KeysResponse{
			Count: len(keys),
			Keys:  keys,
		}, nil
	}

	// Create HTTP server
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sign":
			m.handleSign(w, r)
		case "/keys":
			m.handleKeys(w, r)
		case "/health":
			w.WriteHeader(200)
		default:
			http.NotFound(w, r)
		}
	}))

	return m
}

func (m *MockSignerServer) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req util.SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := m.SignatureHandler(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (m *MockSignerServer) handleKeys(w http.ResponseWriter, r *http.Request) {
	resp, err := m.KeysHandler()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// AddKey adds a key to the mock signer
func (m *MockSignerServer) AddKey(address, keyType string) {
	m.Keys[address] = keyType
}

// URL returns the server URL
func (m *MockSignerServer) URL() string {
	return m.Server.URL
}

// Close shuts down the mock server
func (m *MockSignerServer) Close() {
	m.Server.Close()
}

// NewSignerClient creates a SignerClient pointing to this mock server
func (m *MockSignerServer) NewSignerClient() *util.SignerClient {
	return &util.SignerClient{
		BaseURL: m.Server.URL,
		Client:  http.DefaultClient,
	}
}

// MockSignerCache creates a mock signer cache for testing
func MockSignerCache(keys map[string]string) *util.SignerCache {
	return &util.SignerCache{
		Keys: keys,
	}
}

// MockKeyStore implements keystore.KeyStore for testing
type MockKeyStore struct {
	Keys       map[string][]byte // address -> key data
	GetFunc    func(ctx context.Context, address string, passphrase []byte) (interface{}, error)
	StoreFunc  func(ctx context.Context, address string, keyData []byte, passphrase []byte) error
	DeleteFunc func(ctx context.Context, address string) error
}

// NewMockKeyStore creates a new mock key store
func NewMockKeyStore() *MockKeyStore {
	return &MockKeyStore{
		Keys: make(map[string][]byte),
	}
}

// MockTransaction creates a test transaction with sensible defaults
func MockTransaction(sender, receiver types.Address, amount uint64) types.Transaction {
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:     sender,
			Fee:        types.MicroAlgos(1000),
			FirstValid: 1000,
			LastValid:  2000,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: receiver,
			Amount:   types.MicroAlgos(amount),
		},
	}
}

// MockAssetTransferTransaction creates a test asset transfer transaction
func MockAssetTransferTransaction(sender, receiver types.Address, assetID, amount uint64) types.Transaction {
	return types.Transaction{
		Type: types.AssetTransferTx,
		Header: types.Header{
			Sender:     sender,
			Fee:        types.MicroAlgos(1000),
			FirstValid: 1000,
			LastValid:  2000,
		},
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset:     types.AssetIndex(assetID),
			AssetAmount:   amount,
			AssetReceiver: receiver,
		},
	}
}

// MockAddressZero returns an all-zero address for testing
func MockAddressZero() types.Address {
	return types.Address{}
}

// MockAddressFromByte creates an address where the first byte is set
func MockAddressFromByte(b byte) types.Address {
	var addr types.Address
	addr[0] = b
	return addr
}
