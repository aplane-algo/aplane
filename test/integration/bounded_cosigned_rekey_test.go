// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel/sshtest"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/lsig/plainhost"
	"github.com/aplane-algo/aplane/pkg/signerapi"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// cosignedNode is a signer, a mock cosigner endpoint that signs whatever it is
// asked, and an in-process engine wired to both, with a count of the cosigner
// component requests. The mock applies no policy, so these tests show what the
// signer and client ask of a cosigner; the four-node Docker smoke runs a real
// cosigner node's policy.
type cosignedNode struct {
	network       *harness.TestnetConfig
	funder        *harness.FundTestAccount
	signerd       *harness.SignerHarness
	client        *signerclient.Client
	eng           *engine.Engine
	cosignerCalls *atomic.Int32
}

const cosignedReferenceName = "integration-cosigned"

func newCosignedNode(t *testing.T) *cosignedNode {
	t.Helper()
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed test")
	}
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to network: %v", err)
	}
	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("load funding account: %v", err)
	}
	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("start background unlock: %v", err)
	}
	t.Cleanup(apadmin.StopUnlockBackground)

	seed := make([]byte, 64)
	if _, err := cryptorand.Read(seed); err != nil {
		t.Fatalf("cosigner seed: %v", err)
	}
	cosignerPublic, cosignerPrivate, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("generate cosigner key: %v", err)
	}
	clientDataDir := t.TempDir()
	var discoveryCalls, componentCalls atomic.Int32
	mock := mockCosignerEndpoint(t, cosignerPublic, cosignerPrivate, &discoveryCalls)
	counting := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sign/component" {
			componentCalls.Add(1)
		}
		mock.ServeHTTP(w, r)
	})
	cosigner := sshtest.ServeWithOptions(t, counting, sshtest.Options{Dir: filepath.Join(clientDataDir, ".ssh")})

	cosignerID, err := witness.ID(witness.Falcon1024V1, cosignerPublic)
	if err != nil {
		t.Fatalf("Witness Key ID: %v", err)
	}
	reference, err := witness.NewPublicReference(witness.Falcon1024V1, cosignerID, hex.EncodeToString(cosignerPublic))
	if err != nil {
		t.Fatalf("cosigner reference: %v", err)
	}
	keyFile, err := witness.MarshalPublicReference(reference)
	if err != nil {
		t.Fatalf("compose cosigner key file: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "integration-cosigned.cos.json")
	if err := os.WriteFile(keyPath, keyFile, 0o600); err != nil {
		t.Fatalf("write cosigner key file: %v", err)
	}
	output, err := apadmin.RunWithInput(os.Getenv("TEST_PASSPHRASE")+"\n", "cosigner", "import", keyPath, cosignedReferenceName)
	if err != nil || !strings.Contains(output, "cosigner reference "+cosignedReferenceName+" imported") {
		t.Fatalf("import cosigner reference: %v\n%s", err, output)
	}

	clientEngine, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatal(err)
	}
	const alias = "integration-cosigned-route"
	if _, err := apshellapp.New(clientEngine, config.DefaultConfig(), clientDataDir).EndpointCreateCosigner(context.Background(),
		apshellapp.EndpointCreateCosignerRequest{Alias: alias, URL: cosigner.URL}); err != nil {
		t.Fatal(err)
	}
	registry, err := config.LoadClientEndpointRegistry(clientDataDir)
	if err != nil {
		t.Fatalf("load cosigner endpoint: %v", err)
	}
	eng, err := engine.NewEngine(harness.IntegrationNetwork(),
		engine.WithAlgodClient(network.Client), engine.WithCacheStore(cache.NewStore(t.TempDir())))
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClient(signerd.GetURL())
	eng.EndpointRegistry = registry
	return &cosignedNode{
		network: network, funder: funder, signerd: signerd,
		client: signerclient.NewSignerClient(signerd.GetURL()), eng: eng, cosignerCalls: &componentCalls,
	}
}

// account generates a cosigned bounded account on the plain host keyType that
// pays the funder only, with the given rekey authority and rekey-to list, and
// funds it. Its signer cache is refreshed so the engine routes it on cosigned1.
func (n *cosignedNode) account(t *testing.T, keyType, rekey string, rekeyTo ...string) string {
	t.Helper()
	params := map[string]string{
		plainhost.ParameterSpendEffects:   "pay",
		plainhost.ParameterRecipients:     n.funder.GetAddress(),
		plainhost.ParameterRekeyAuthority: rekey,
		cosignerrefs.ParamCosignerName:    cosignedReferenceName,
	}
	if len(rekeyTo) > 0 {
		params[plainhost.ParameterRekeyTo] = strings.Join(rekeyTo, ",")
	}
	address := mustAdminGenerateKeyNoCleanup(t, n.client, n.signerd, keyType, params)
	if err := n.funder.FundMicroAlgosAndWait(address, 1_000_000); err != nil {
		t.Fatalf("fund %s: %v", address, err)
	}
	keys, err := n.client.GetKeysWithContext(context.Background())
	if err != nil {
		t.Fatalf("read keys: %v", err)
	}
	for _, key := range keys.Keys {
		if key.Address != address {
			continue
		}
		if key.SigningFlow != signerapi.SigningFlowCosigned1 {
			t.Fatalf("%s signing flow = %q, want %s", address, key.SigningFlow, signerapi.SigningFlowCosigned1)
		}
		if key.BoundedAuthorization == nil || key.BoundedAuthorization.Contract != signerapi.BoundedContractBounded2 {
			t.Fatalf("%s contract = %+v, want %s", address, key.BoundedAuthorization, signerapi.BoundedContractBounded2)
		}
	}
	if err := n.eng.EnsureSignerCache(context.Background()); err != nil {
		t.Fatalf("refresh signer cache: %v", err)
	}
	return address
}

// spend pays the funder from account and checks the cosigner was asked.
func (n *cosignedNode) spend(t *testing.T, account string, amount uint64) {
	t.Helper()
	sp, err := n.network.GetSuggestedParams()
	if err != nil {
		t.Fatalf("suggested params: %v", err)
	}
	spend, err := transaction.MakePaymentTxn(account, n.funder.GetAddress(), amount, []byte("cosigned-spend"), "", sp)
	if err != nil {
		t.Fatal(err)
	}
	before := n.cosignerCalls.Load()
	if err := n.submit(t, spend); err != nil {
		t.Fatalf("cosigned spend: %v", err)
	}
	if n.cosignerCalls.Load() == before {
		t.Fatal("a spend confirmed without asking the cosigner")
	}
}

// submit signs one transaction through the engine and waits for the network.
func (n *cosignedNode) submit(t *testing.T, txn types.Transaction) error {
	t.Helper()
	result, err := n.eng.SignAndSubmitTransactions(context.Background(), []types.Transaction{txn}, true)
	if err != nil {
		return err
	}
	if !result.Confirmed || len(result.TxIDs) == 0 {
		t.Fatalf("submission was not confirmed: %s", result.Output)
	}
	return nil
}

func (n *cosignedNode) rekeyTxn(t *testing.T, account, target string) types.Transaction {
	t.Helper()
	sp, err := n.network.GetSuggestedParams()
	if err != nil {
		t.Fatalf("suggested params: %v", err)
	}
	txn, err := transaction.MakePaymentTxn(account, account, 0, nil, "", sp)
	if err != nil {
		t.Fatalf("build rekey: %v", err)
	}
	if err := txn.Rekey(target); err != nil {
		t.Fatalf("set rekey target: %v", err)
	}
	return txn
}

// rekey hands account to target and checks how many cosigner requests it took.
func (n *cosignedNode) rekey(t *testing.T, account string, target algocrypto.Account, cosignerRequests int32) {
	t.Helper()
	before := n.cosignerCalls.Load()
	if err := n.submit(t, n.rekeyTxn(t, account, target.Address.String())); err != nil {
		t.Fatalf("rekey %s to %s: %v", account, target.Address, err)
	}
	if got := n.cosignerCalls.Load() - before; got != cosignerRequests {
		t.Fatalf("rekey %s took %d cosigner requests, want %d", account, got, cosignerRequests)
	}
	if got := authAddress(t, n.network, account); got != target.Address.String() {
		t.Fatalf("%s authorizer = %q, want %s", account, got, target.Address)
	}
	t.Cleanup(func() { bestEffortCloseRekeyedAccount(t, n.network, account, n.funder.GetAddress(), target.PrivateKey) })
}

// Corridor's behavior as a plain host's bounds offer it, a cosigner plus only
// these: a spend needs the cosigner; an unlisted rekey is refused at the signer,
// before the cosigner sees anything; a listed rekey confirms with the spending key
// alone and no cosigner request. Under plus cosigned, an unlisted rekey asks the
// cosigner and confirms, and a listed one confirms with no cosigner request. A
// cosigned spending-key rekey asks the cosigner, and a refused account takes no
// rekey at all. Both bases host the bounds with a cosigner, Ed25519 as well as
// Falcon-1024, so each case runs on both.
func TestCosignedRekeysThroughSigner(t *testing.T) {
	n := newCosignedNode(t)
	activatePlainHosts(t, n)
	bases := []string{plainFalconKeyType, plainEd25519KeyType}

	for _, keyType := range bases {
		t.Run(keyType+"/Corridor: a cosigner plus only these", func(t *testing.T) {
			listed := algocrypto.GenerateAccount()
			account := n.account(t, keyType, plainhost.RekeyOnlyThese, listed.Address.String())
			n.spend(t, account, 10_000)
			before := n.cosignerCalls.Load()
			unlisted := algocrypto.GenerateAccount().Address.String()
			if err := n.submit(t, n.rekeyTxn(t, account, unlisted)); err == nil || !strings.Contains(err.Error(), "is not on this account's rekey-to list") {
				t.Fatalf("an unlisted rekey: error = %v, want the signer's not-listed refusal", err)
			}
			if n.cosignerCalls.Load() != before {
				t.Fatal("the cosigner was asked about a rekey the signer refuses")
			}
			if got := authAddress(t, n.network, account); got != "" {
				t.Fatalf("%s was rekeyed to %s", account, got)
			}
			// Under the default reject_foreign_rekey, a listed target counts as
			// declared even though this signer doesn't hold it (O8).
			n.rekey(t, account, listed, 0)
		})
		// A refused account's only way to move funds is a spend: the signer refuses
		// every rekey before the cosigner sees it, and the spend that returns the
		// funds leaves only the minimum balance behind.
		t.Run(keyType+"/refused: the signer refuses every rekey", func(t *testing.T) {
			account := n.account(t, keyType, plainhost.RekeyRefused)
			n.spend(t, account, 10_000)
			before := n.cosignerCalls.Load()
			err := n.submit(t, n.rekeyTxn(t, account, algocrypto.GenerateAccount().Address.String()))
			if err == nil || !strings.Contains(err.Error(), "permanently disables rekey") {
				t.Fatalf("a refused account's rekey: error = %v, want the signer's refusal", err)
			}
			if n.cosignerCalls.Load() != before {
				t.Fatal("the cosigner was asked about a rekey the signer refuses")
			}
			if got := authAddress(t, n.network, account); got != "" {
				t.Fatalf("%s was rekeyed to %s", account, got)
			}
			info, err := n.network.Client.AccountInformation(account).Do(context.Background())
			if err != nil {
				t.Fatalf("read %s: %v", account, err)
			}
			// The signer refuses a fee above the account's ceiling, so this leaves at
			// least the minimum balance.
			if reserve := info.MinBalance + plainhost.MaxFee; info.Amount > reserve {
				n.spend(t, account, info.Amount-reserve)
			}
		})
	}

	// Cosigned rekeys go to addresses this signer doesn't hold, which only
	// allow_rekeys lets through; the cosigner's own policy would decide next.
	ipc := mustConnectIPCClient(t, n.signerd.GetWorkDir())
	mustReplaceIPCPolicySetting(t, ipc, "rekeys", string(policy.RekeysAllow))
	ipc.Close()

	for _, keyType := range bases {
		t.Run(keyType+"/plus cosigned: an unlisted rekey asks the cosigner", func(t *testing.T) {
			account := n.account(t, keyType, plainhost.RekeyPlusCosigned, algocrypto.GenerateAccount().Address.String())
			n.rekey(t, account, algocrypto.GenerateAccount(), 1)
		})
		t.Run(keyType+"/plus cosigned: a listed rekey needs no cosigner", func(t *testing.T) {
			listed := algocrypto.GenerateAccount()
			account := n.account(t, keyType, plainhost.RekeyPlusCosigned, listed.Address.String())
			n.rekey(t, account, listed, 0)
		})
		t.Run(keyType+"/spending key and cosigner", func(t *testing.T) {
			account := n.account(t, keyType, plainhost.RekeySpendingKey)
			n.rekey(t, account, algocrypto.GenerateAccount(), 1)
		})
	}
}
