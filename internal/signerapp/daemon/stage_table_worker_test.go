// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/keys"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatinghybrid/signerops"
	rotatingsignerreg "github.com/aplane-algo/aplane/lsig/rotatinghybrid/signerreg"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// testnetGenesisB64 maps to the built-in "testnet" token.
const testnetGenesisB64 = "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="

// mockAccountNode answers the two algod calls the chain reader makes.
type mockAccountNode struct {
	mu       sync.Mutex
	authAddr string
	round    uint64
}

func (n *mockAccountNode) set(authAddr string, round uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.authAddr, n.round = authAddr, round
}

func (n *mockAccountNode) transport() http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		n.mu.Lock()
		defer n.mu.Unlock()
		var body any
		switch {
		case req.URL.Path == "/versions":
			body = map[string]any{"genesis_hash_b64": testnetGenesisB64, "genesis_id": "testnet-v1.0", "versions": []string{"v2"}, "build": map[string]any{}}
		case strings.HasPrefix(req.URL.Path, "/v2/accounts/"):
			account := map[string]any{"address": strings.TrimPrefix(req.URL.Path, "/v2/accounts/"), "round": n.round}
			if n.authAddr != "" {
				account["auth-addr"] = n.authAddr
			}
			body = account
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
		}
		raw, _ := json.Marshal(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(string(raw))),
			Request:    req,
		}, nil
	})
}

// installRotatingKey saves a fresh rotating key into the signer's store and
// returns its account and a copy of its seed for deriving stage addresses.
func installRotatingKey(t *testing.T, server *Signer) (types.Address, *coresigning.RotatingKeyMaterial) {
	t.Helper()
	rotatingsignerreg.Register()
	ir := server.productRuntime()
	var seed rotatinghybrid.Seed
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	defer seed.Zero()
	var genesis [rotatinghybrid.GenesisHashSize]byte
	gh, _ := base64.StdEncoding.DecodeString(testnetGenesisB64)
	copy(genesis[:], gh)
	payload, address, err := rotatingsignerreg.NewKeyPayload(&seed, genesis)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.ZeroSecrets()
	active, err := ir.ActiveKeyPaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		_, err := keys.SavePayload(active, payload, kr)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ir.Reload(); err != nil {
		t.Fatal(err)
	}
	account, _ := types.DecodeAddress(address)
	secret := &coresigning.RotatingKeyMaterial{Seed: append([]byte(nil), seed[:]...), GenesisHash: genesis[:]}
	t.Cleanup(secret.Zero)
	return account, secret
}

func TestStageTableWorkerFillsResolvedAndUnresolvedAccounts(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()

	node := &mockAccountNode{}
	server.config.Algod = config.AlgodConfig{"testnet": &config.AlgodNetworkConfig{Server: "http://mock-algod"}}
	server.config.Rotating.StageHorizon = 2
	server.stageFillBatch, server.stageFillMaxDeriv = 2, 4
	server.makeAlgod = func(serverURL, token string) (*algod.Client, error) {
		return algod.MakeClientWithTransport(serverURL, token, nil, node.transport())
	}
	account, secret := installRotatingKey(t, server)
	gh, _ := base64.StdEncoding.DecodeString(testnetGenesisB64)

	// Fresh account: no auth address, so stage 0; the table covers 0 … 2 and
	// the worker goes idle.
	node.set("", 100)
	if wait := server.fillStageTables(context.Background(), ir); wait != stageTableIdleInterval {
		t.Fatalf("wait after resolved pass = %v, want idle interval", wait)
	}
	table, err := ir.StageTables().Table(account, gh)
	if err != nil {
		t.Fatal(err)
	}
	if table.Len() != 3 {
		t.Fatalf("table len = %d, want 3 (stage 0 plus horizon 2)", table.Len())
	}
	if _, statErr := os.Stat(ir.KeyPaths().StageTablePath(account.String())); statErr != nil {
		t.Fatalf("table file not written beside the key store: %v", statErr)
	}
	for i := uint64(0); i < 3; i++ {
		want, err := signerops.StageOps{}.StageAddress(secret, i)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := table.Address(i); got != want {
			t.Fatalf("stage %d in table does not match derivation", i)
		}
	}

	// The account is ahead of the table: with four derivations per pass the
	// worker reports it as not yet found and asks to be called back soon,
	// instead of stopping at the horizon (2) or calling it foreign.
	stage9, _ := signerops.StageOps{}.StageAddress(secret, 9)
	node.set(stage9.String(), 200)
	if wait := server.fillStageTables(context.Background(), ir); wait != stageTableBusyInterval {
		t.Fatalf("wait after unresolved pass = %v, want busy interval", wait)
	}
	if table.Len() != 7 {
		t.Fatalf("unresolved pass len = %d, want 7 (stages 3 … 6 derived)", table.Len())
	}
	// The next pass reaches stage 9, stops there, and looks ahead to 11.
	wait := server.fillStageTables(context.Background(), ir)
	if stage, ok := table.Lookup(stage9); !ok || stage != 9 {
		t.Fatalf("stage 9 not resolved after two passes: %d, %v (len %d)", stage, ok, table.Len())
	}
	if wait != stageTableIdleInterval || table.Len() < 12 {
		t.Fatalf("after resolving: wait %v, len %d; want idle and lookahead through 11", wait, table.Len())
	}

	// A locked signer cannot reach the seed: the pass changes nothing and
	// falls back to the idle interval.
	ir.Lock()
	before := table.Len()
	if wait := server.fillStageTables(context.Background(), ir); wait != stageTableIdleInterval {
		t.Fatalf("wait while locked = %v, want idle interval", wait)
	}
	if table.Len() != before {
		t.Fatalf("locked pass changed the table: %d -> %d", before, table.Len())
	}
}
