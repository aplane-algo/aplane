// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

var (
	keyregEligible   = types.Address{31}.String()
	keyregIneligible = types.Address{32}.String()
	// keyregUnknown is an account algod cannot answer for.
	keyregUnknown = types.Address{33}.String()
)

// keyregFixture is a script runtime whose network reports each account's
// incentive eligibility and whose signer records what it is asked to sign
// and refuses it.
type keyregFixture struct {
	api    *API
	mu     sync.Mutex
	signed []types.Transaction
}

func newKeyregFixture(t *testing.T) *keyregFixture {
	t.Helper()
	f := &keyregFixture{}
	genesis, err := base64.StdEncoding.DecodeString(config.AlgorandTestnetGenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/transactions/params":
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV43), MinFee: 1000, LastRound: 1000,
				GenesisId: "testnet-v1.0", GenesisHash: genesis,
			})
		case strings.HasPrefix(r.URL.Path, "/v2/accounts/"):
			address := strings.TrimPrefix(r.URL.Path, "/v2/accounts/")
			if address == keyregUnknown {
				http.Error(w, "test node", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(models.Account{
				Address: address, Amount: 10_000_000, MinBalance: 100_000, Status: "Online",
				IncentiveEligible: address == keyregEligible,
			})
		default:
			http.Error(w, "test node", http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(node.Close)
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/keys" {
			keys := []signerapi.KeyInfo{}
			for _, address := range []string{keyregEligible, keyregIneligible, keyregUnknown} {
				keys = append(keys, signerapi.KeyInfo{Address: address, KeyType: "ed25519"})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: len(keys), Keys: keys})
			return
		}
		if r.Method == http.MethodPost && (r.URL.Path == "/sign" || r.URL.Path == "/plan") {
			var req signerapi.GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode %s request: %v", r.URL.Path, err)
			}
			for _, entry := range req.Requests {
				txn, err := txnutil.DecodePrefixedHex(entry.TxnBytesHex)
				if err != nil {
					t.Errorf("decode %s transaction: %v", r.URL.Path, err)
					continue
				}
				f.mu.Lock()
				f.signed = append(f.signed, txn)
				f.mu.Unlock()
			}
		}
		http.Error(w, "test signer", http.StatusServiceUnavailable)
	}))
	t.Cleanup(signer.Close)

	eng, _, api := newTestAPI(t)
	if eng.AlgodClient, err = algod.MakeClient(node.URL, ""); err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
	eng.SignerCache.Keys = map[string]string{
		keyregEligible: "ed25519", keyregIneligible: "ed25519", keyregUnknown: "ed25519",
	}
	// Each account signs for itself, so only the eligibility read asks
	// algod about the account.
	if eng.AuthCache.AuthAddresses == nil {
		eng.AuthCache.AuthAddresses = map[string]string{}
	}
	for address := range eng.SignerCache.Keys {
		eng.AuthCache.AuthAddresses[address] = ""
	}
	f.api = api
	return f
}

// keyreg runs keyreg(account, "online", {..., eligible}) and returns the
// error the script sees: the signer always refuses, so there is one.
func (f *keyregFixture) keyreg(t *testing.T, account string, eligible bool) string {
	t.Helper()
	script := fmt.Sprintf(`keyreg(%q, "online", {
		votekey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		selkey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		sproofkey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		votefirst: 1, votelast: 2000, keydilution: 10, eligible: %v,
	})`, account, eligible)
	_, err := f.api.runtime.RunString(script)
	if err == nil {
		t.Fatal("keyreg() succeeded against a signer that refuses")
	}
	return err.Error()
}

func (f *keyregFixture) signedTxns() []types.Transaction {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]types.Transaction(nil), f.signed...)
}

// Audit finding 13: keyreg(..., {eligible: true}) paid the 2 ALGO incentive
// fee on every call, so a script that renews its participation key paid it
// each time. The fee is paid only to become eligible, as on the command line.
func TestKeyregPaysTheIncentiveFeeOnlyToBecomeEligible(t *testing.T) {
	tests := []struct {
		name     string
		account  string
		eligible bool
		wantFee  uint64
	}{
		{"eligible already", keyregEligible, true, 1000},
		{"not eligible yet", keyregIneligible, true, 2_000_000},
		{"not requested", keyregIneligible, false, 1000},
		// No request, no read: algod failing to answer for the account
		// does not stop a renewal.
		{"not requested, eligibility unreadable", keyregUnknown, false, 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newKeyregFixture(t)
			if got := f.keyreg(t, tt.account, tt.eligible); !strings.Contains(got, "error submitting transaction") {
				t.Fatalf("keyreg() error = %s, want the signer's refusal", got)
			}
			signed := f.signedTxns()
			if len(signed) == 0 {
				t.Fatal("the signer was asked to sign nothing")
			}
			for _, txn := range signed {
				if txn.Type != types.KeyRegistrationTx || txn.Sender.String() != tt.account {
					t.Fatalf("signed %s from %s, want a keyreg from %s", txn.Type, txn.Sender, tt.account)
				}
				if uint64(txn.Fee) != tt.wantFee {
					t.Errorf("keyreg fee = %d, want %d", txn.Fee, tt.wantFee)
				}
			}
		})
	}
}

// A request for eligibility that can't be read is refused before signing, so
// it neither pays a fee that may not be owed nor drops the request.
func TestKeyregRefusesWhenEligibilityCannotBeRead(t *testing.T) {
	f := newKeyregFixture(t)
	if got := f.keyreg(t, keyregUnknown, true); !strings.Contains(got, "failed to query incentive eligibility") {
		t.Fatalf("keyreg() error = %s, want the eligibility lookup error", got)
	}
	if signed := f.signedTxns(); len(signed) != 0 {
		t.Fatalf("the signer was asked to sign %d transaction(s)", len(signed))
	}
}
