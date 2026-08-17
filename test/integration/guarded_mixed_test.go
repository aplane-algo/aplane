// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// TestMixedGuardedGroupTransaction exercises the end-to-end mixed guarded group
// flow: a single atomic group whose first sender is a guarded account and whose
// second sender is an ordinary signer-managed (non-guarded falcon) account.
//
// The real apsigner process holds both the guarded account and the non-guarded
// falcon account, and performs the user-role component signature, the
// non-guarded /sign, and the final /sign/assemble. The sentry role is served by
// an in-process mock endpoint that holds the test-generated sentry key — the
// sentry's only job is to produce a valid sentry-role signature over the key
// embedded in the guarded account at generation time, so a test-held key is
// faithful to the on-chain assembly and verification path.
//
// This is the integration counterpart to the unit coverage in
// internal/engine/mixed_guarded_submit_test.go and the planner coverage in
// internal/signerapp/signing/planner_runtime_test.go. It validates the real
// Falcon LogicSig assembly and on-chain submission of a mixed group, including
// the LogicSig-budget accounting that must span both LogicSig senders.
func TestMixedGuardedGroupTransaction(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping mixed guarded group integration test")
	}

	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("Failed to connect to network: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("Failed to load funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("Failed to start Signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("Failed to start background unlock: %v", err)
	}
	t.Cleanup(apadmin.StopUnlockBackground)

	// Test-held sentry key. The "sentry node" is the mock endpoint below; the
	// guarded account embeds this public key at generation time.
	sentrySeed := make([]byte, 64)
	if _, err := cryptorand.Read(sentrySeed); err != nil {
		t.Fatalf("Failed to generate sentry seed: %v", err)
	}
	sentryPub, sentryPriv, err := signerops.New(nil).GenerateKeypair(sentrySeed)
	if err != nil {
		t.Fatalf("Failed to generate sentry key: %v", err)
	}
	sentryPubHex := hex.EncodeToString(sentryPub)
	const sentryToken = "mixed-guarded-sentry-token"
	sentry := startMockSentryEndpoint(t, sentryPub, sentryPriv, sentryToken)
	t.Cleanup(sentry.Close)
	sentryTokenFile := writeGuardedSentryTokenFile(t, sentryToken)

	// Generate the guarded account (embeds the sentry public key) and a plain
	// non-guarded falcon account on the real signer. Guarded account key types
	// are library-gated (AvailabilityLibrary), so activate it for this identity
	// before generation; the non-guarded falcon type is default-enabled.
	t.Log("Generating guarded account and non-guarded falcon account...")
	if err := apadmin.ActivateKeyType(keytypes.GuardedFalcon1024Sentry1024V1); err != nil {
		t.Fatalf("Failed to activate guarded key type: %v", err)
	}
	guardedAddr, err := apadmin.GenerateKeyWithTypeAndParams(
		keytypes.GuardedFalcon1024Sentry1024V1,
		map[string]string{keytypes.ParameterSentryPublicKey: sentryPubHex},
	)
	if err != nil {
		t.Fatalf("Failed to generate guarded account: %v", err)
	}
	falconAddr, err := apadmin.GenerateKey("non-guarded falcon for mixed group")
	if err != nil {
		t.Fatalf("Failed to generate non-guarded falcon account: %v", err)
	}
	t.Logf("guarded=%s non-guarded falcon=%s", guardedAddr, falconAddr)

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, guardedAddr, 10*time.Second) {
		t.Fatalf("Signer did not reload guarded key %s", guardedAddr)
	}
	if !waitForKey(t, signerd.GetURL(), token, falconAddr, 10*time.Second) {
		t.Fatalf("Signer did not reload falcon key %s", falconAddr)
	}

	// In-process engine wired to the real signer (user component sign,
	// non-guarded /sign, assemble), the mock sentry (sentry component sign), and
	// real algod (submission). IsConnected() is satisfied by setting SignerClient.
	eng, err := engine.NewEngine(
		harness.IntegrationNetwork(),
		engine.WithAlgodClient(testnet.Client),
		engine.WithCacheStore(cache.NewStore(t.TempDir())),
	)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClientWithToken(signerd.GetURL(), token)
	eng.SentryEndpoints = config.SentryEndpointConfigs{
		sentryPubHex: {URL: sentry.URL, TokenFile: sentryTokenFile},
	}
	if err := eng.EnsureSignerCache(context.Background()); err != nil {
		t.Fatalf("Failed to populate signer cache from signer /keys: %v", err)
	}

	// Reclaim funds where possible after the test. The non-guarded falcon closes
	// through the normal path; the guarded account closes through the guarded
	// path. Both are best-effort so a cleanup hiccup never fails the test.
	t.Cleanup(func() { bestEffortCloseAccount(t, eng, testnet, falconAddr, funder.GetAddress()) })
	t.Cleanup(func() { bestEffortCloseAccount(t, eng, testnet, guardedAddr, funder.GetAddress()) })

	t.Log("Funding guarded and falcon accounts...")
	if err := funder.FundMicroAlgosAndWait(guardedAddr, 500_000); err != nil {
		t.Fatalf("Failed to fund guarded account %s: %v", guardedAddr, err)
	}
	if err := funder.FundMicroAlgosAndWait(falconAddr, 500_000); err != nil {
		t.Fatalf("Failed to fund falcon account %s: %v", falconAddr, err)
	}

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("Failed to get suggested params: %v", err)
	}

	guardedTxn, err := transaction.MakePaymentTxn(guardedAddr, integrationBurnAddress, 0, []byte("mixed-guarded"), "", sp)
	if err != nil {
		t.Fatalf("Failed to build guarded txn: %v", err)
	}
	falconTxn, err := transaction.MakePaymentTxn(falconAddr, integrationBurnAddress, 0, []byte("mixed-falcon"), "", sp)
	if err != nil {
		t.Fatalf("Failed to build falcon txn: %v", err)
	}

	// Submit the mixed group through the engine. This routes through
	// signAndSubmitGuardedGroup's mixed path: plan (budget over both LogicSigs)
	// → user/sentry component signatures for the guarded position → non-guarded
	// /sign for the falcon position → /sign/assemble → submit.
	t.Log("Submitting mixed guarded+falcon atomic group...")
	result, err := eng.SignAndSubmitTransactions(
		context.Background(),
		[]types.Transaction{guardedTxn, falconTxn},
		true,
	)
	if err != nil {
		t.Fatalf("Mixed guarded group submission failed: %v\nOutput: %s", err, engineOutput(result))
	}
	if len(result.TxIDs) < 2 {
		t.Fatalf("Expected at least 2 submitted txids for the mixed group, got %d", len(result.TxIDs))
	}
	if !result.Confirmed {
		t.Fatalf("Mixed guarded group was not confirmed: %s", result.Output)
	}
	if _, err := testnet.WaitForConfirmation(result.TxIDs[0], 10); err != nil {
		t.Fatalf("Mixed guarded group failed to confirm on-chain: %v", err)
	}
	t.Logf("✓ Mixed guarded+falcon atomic group confirmed on-chain (%d txids)", len(result.TxIDs))
}

func engineOutput(result *engine.SignTransactionsResult) string {
	if result == nil {
		return ""
	}
	return result.Output
}

// bestEffortCloseAccount closes an account back to the funding account through
// the engine, routing automatically through the normal or guarded path based on
// the sender. Failures are logged, not fatal, so leftover dust never fails a run.
func bestEffortCloseAccount(t *testing.T, eng *engine.Engine, testnet *harness.TestnetConfig, from, to string) {
	t.Helper()
	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Logf("cleanup: suggested params for closing %s failed: %v", from, err)
		return
	}
	closeTxn, err := transaction.MakePaymentTxn(from, to, 0, nil, to, sp)
	if err != nil {
		t.Logf("cleanup: building close txn for %s failed: %v", from, err)
		return
	}
	if _, err := eng.SignAndSubmitTransactions(context.Background(), []types.Transaction{closeTxn}, true); err != nil {
		t.Logf("cleanup: closing %s to %s failed (funds left in place): %v", from, to, err)
		return
	}
	t.Logf("cleanup: closed %s to funding account", from)
}

// startMockSentryEndpoint stands up an HTTP endpoint that behaves like a sentry
// node for one sentry key: it advertises the Witness Key ID on /keys (so the
// client's endpoint-advertisement check passes) and produces real sentry-role
// component signatures on /sign/component using the test-held private key.
func startMockSentryEndpoint(t *testing.T, publicKey, privateKey []byte, token string) *httptest.Server {
	t.Helper()
	componentSelector, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("Failed to derive Witness Key ID: %v", err)
	}
	publicKeyHex := hex.EncodeToString(publicKey)

	authorized := func(r *http.Request) bool {
		return token == "" || r.Header.Get("Authorization") == "aplane "+token
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{
			Count: 1,
			Keys: []signerapi.KeyInfo{{
				Address:      componentSelector,
				PublicKeyHex: publicKeyHex,
				KeyType:      witness.Falcon1024V1,
				IsWitnessKey: true,
			}},
		})
	})
	mux.HandleFunc("/sign/component", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req signerapi.ComponentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.TargetKind() != signerapi.ComponentTargetKindSentry || len(req.Targets) == 0 || req.Targets[0].ComponentKey != componentSelector {
			http.Error(w, "wrong Witness Key ID", http.StatusBadRequest)
			return
		}
		group, err := canonical.DecodeGroupHex(req.GroupBytesHex)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := signerapi.ComponentResponse{
			RequestID:  req.RequestID,
			Components: make([]signerapi.Component, 0, len(req.Targets)),
		}
		for _, target := range req.Targets {
			index := target.TargetIndex
			if index < 0 || index >= len(group.Entries) {
				http.Error(w, "target index out of range", http.StatusBadRequest)
				return
			}
			msg := message.ComponentMessage(message.RoleSentry, group.Entries[index].TxID)
			signature, err := signerops.New(nil).Sign(privateKey, msg[:])
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			resp.Components = append(resp.Components, signerapi.Component{
				TargetIndex:     index,
				Kind:            signerapi.ComponentTargetKindSentry,
				SignatureScheme: witness.Falcon1024V1,
				Signature:       hex.EncodeToString(signature),
			})
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	return httptest.NewServer(mux)
}

func writeGuardedSentryTokenFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sentry.token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("Failed to write sentry token file: %v", err)
	}
	return path
}
