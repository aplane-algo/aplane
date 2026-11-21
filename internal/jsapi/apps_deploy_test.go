// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// A deploy that confirmed is returned, not thrown, when the app it created
// cannot be looked up: the script gets its transaction ID and why app_id is
// missing, so nothing invites it to deploy again.
func TestAppDeployReturnsAConfirmedDeployWithoutItsApp(t *testing.T) {
	deployer := types.Address{41}.String()
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
			_ = json.NewEncoder(w).Encode(models.Account{
				Address: strings.TrimPrefix(r.URL.Path, "/v2/accounts/"), Amount: 10_000_000, MinBalance: 100_000,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v2/transactions":
			_ = json.NewEncoder(w).Encode(map[string]string{"txId": "DEPLOYTX"})
		case r.URL.Path == "/v2/status":
			_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: 1000})
		case strings.HasPrefix(r.URL.Path, "/v2/transactions/pending/"):
			// Confirmed, with no app created.
			w.Header().Set("Content-Type", "application/msgpack")
			_, _ = w.Write(msgpack.Encode(models.PendingTransactionInfoResponse{ConfirmedRound: 1001}))
		default:
			http.Error(w, "test node", http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(node.Close)
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/keys":
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Keys: []signerapi.KeyInfo{{Address: deployer, KeyType: "ed25519", AuthorizationKind: "ed25519"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/sign":
			var req signerapi.GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			signed := make([]string, len(req.Requests))
			for i, entry := range req.Requests {
				txn, err := txnutil.DecodePrefixedHex(entry.TxnBytesHex)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				signed[i] = hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn, Sig: types.Signature{1}}))
			}
			_ = json.NewEncoder(w).Encode(signerapi.GroupSignResponse{Signed: signed})
		default:
			http.Error(w, "test signer", http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(signer.Close)

	eng, vm, _ := newTestAPI(t)
	if eng.AlgodClient, err = algod.MakeClient(node.URL, ""); err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
	eng.SignerCache.AddAddress(deployer, "ed25519", "ed25519")
	if eng.AuthCache.AuthAddresses == nil {
		eng.AuthCache.AuthAddresses = map[string]string{}
	}
	eng.AuthCache.AuthAddresses[deployer] = ""
	program := filepath.Join(t.TempDir(), "program.bin")
	if err := os.WriteFile(program, []byte{0x06, 0x81, 0x01}, 0o600); err != nil {
		t.Fatal(err)
	}

	value, err := vm.RunString(fmt.Sprintf(`JSON.stringify(appDeploy(%q, %q, %q, {approvalCompiled: true, clearCompiled: true, wait: true}))`,
		deployer, program, program))
	if err != nil {
		t.Fatalf("appDeploy() threw %v, want the confirmed deploy returned", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(value.String()), &got); err != nil {
		t.Fatalf("decode %s: %v", value, err)
	}
	if got["tx_id"] == "" || got["confirmed"] != true || got["app_id"] != nil ||
		!strings.Contains(fmt.Sprint(got["app_lookup_error"]), "transaction did not create an application") {
		t.Fatalf("appDeploy() = %s, want the confirmed deploy, no app_id, and why", value)
	}
}
