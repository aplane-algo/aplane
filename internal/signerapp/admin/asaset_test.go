// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/asasetstore"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig/clientreg"
)

const (
	asaTestChain   = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	asaTestCreator = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"
)

// fakeASAChain maps private-dev to asaTestChain and serves asset 9 there.
type fakeASAChain struct {
	mu     sync.Mutex
	params models.AssetParams
	reads  int
	// beforeRead runs before every read, to change the chain between reads.
	beforeRead func(reads int, params *models.AssetParams)
}

func (c *fakeASAChain) Networks() apconfig.GenesisHashNetworkResolver {
	r, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{asaTestChain: "private-dev"})
	if err != nil {
		panic(err)
	}
	return r
}

func (c *fakeASAChain) ReadAsset(_ context.Context, genesisHash []byte, assetID uint64) (models.AssetParams, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if c.beforeRead != nil {
		c.beforeRead(c.reads, &c.params)
	}
	want, _ := asaset.ParseGenesisHash(asaTestChain)
	if string(genesisHash) != string(want[:]) || assetID != 9 {
		return models.AssetParams{}, errors.New("no such asset")
	}
	return c.params, nil
}

// setupASAAdmin is an unlocked signer whose reload loads policy and the ASA
// set together, as the daemon does, with private-dev mapped in its config.
func setupASAAdmin(t *testing.T) (Service, *productruntime.Runtime, *fakeASAChain) {
	t.Helper()
	clientreg.RegisterClient()
	root := t.TempDir()
	paths := storepaths.NewPaths(root)
	if _, err := storeinit.Initialize([]byte(adminPolicyPassphrase), storeinit.Options{ValidateCandidate: storevalidate.FirstGeneration, DataDir: root, Paths: paths, Role: noderole.RoleSigner}); err != nil {
		t.Fatal(err)
	}
	cfg := serverconfig.DefaultServerConfig()
	cfg.GenesisHashNetworks = map[string]string{asaTestChain: "private-dev"}
	ir := productruntime.New(productruntime.Config{
		KeyStore: keystore.NewAtomicFileKeyStoreForPaths(paths),
		KeyPaths: paths,
		NodeRole: noderole.RoleSigner,
	})
	if err := ir.KeyStore().Unlock([]byte(adminPolicyPassphrase)); err != nil {
		t.Fatal(err)
	}
	ir.SetUnlocked()
	reload := func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return &signertemplates.ReloadReport{}, ir.KeyStore().WithKeyring(func(kr *crypto.Keyring) error {
			active, err := genstore.ResolveStoreRootWithKeyring(paths, kr)
			if err != nil {
				return err
			}
			np, err := policyruntime.Load(noderole.RoleSigner, root, &cfg, active, kr)
			if err != nil {
				return err
			}
			set, err := asasetstore.Load(active, kr)
			if err != nil {
				return err
			}
			ir.SetVerifiedPolicyState(np, set)
			return nil
		})
	}
	ir.SetReloadFunc(reload)
	if _, err := reload(nil, nil); err != nil {
		t.Fatal(err)
	}
	chain := &fakeASAChain{params: models.AssetParams{
		Creator: asaTestCreator, Decimals: 2, Total: 1_000_000, UnitName: "XYZ", Name: "Example", Clawback: asaTestCreator,
	}}
	svc := Service{
		Deps:     &fakeDeps{dataDir: root, config: &cfg, keyPaths: paths},
		Runtime:  ir,
		ASAChain: chain,
		Now:      func() time.Time { return time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC) },
	}
	return svc, ir, chain
}

func confirmASA9(t *testing.T, svc Service) adminproto.AddASAResult {
	t.Helper()
	looked := svc.LookupASA(adminproto.LookupASARequest{Network: "private-dev", AssetID: 9})
	if !looked.Success || looked.Asset.UnitName != "XYZ" || looked.Asset.Clawback != asaTestCreator || looked.Asset.GenesisHash != asaTestChain {
		t.Fatalf("LookupASA() = %+v", looked)
	}
	return svc.AddASA(adminproto.AddASARequest{Confirmed: looked.Asset})
}

func TestAddASAMintsAndReloads(t *testing.T) {
	svc, ir, _ := setupASAAdmin(t)
	before := currentGeneration(t, svc, ir)
	added := confirmASA9(t, svc)
	if !added.Success || added.GenerationID == "" || added.Asset.UnitName != "XYZ" || added.Asset.Network != "private-dev" {
		t.Fatalf("AddASA() = %+v", added)
	}
	if after := currentGeneration(t, svc, ir); after == before || after != added.GenerationID {
		t.Fatalf("generation %s -> %s, result %s", before, after, added.GenerationID)
	}
	_, set := ir.PolicyState()
	if e := set.Entries(); len(e) != 1 || e[0].UnitName != "XYZ" || e[0].NetworkAtConfirmation != "private-dev" {
		t.Fatalf("runtime set after add = %+v", e)
	}
	list := svc.ListASASet()
	var mine, usdc bool
	for _, a := range list.Assets {
		mine = mine || (a.Origin == "operator" && a.AssetID == 9 && a.Network == "private-dev")
		usdc = usdc || (a.Origin == "builtin" && a.AssetID == 31566704 && a.Network == "mainnet")
	}
	if !mine || !usdc {
		t.Fatalf("ListASASet() lacks the confirmation or the built-ins: %+v", list)
	}
	// The same asset twice is refused, and nothing new is minted.
	again := confirmASA9Again(t, svc)
	if again.Code != "asa_already_confirmed" || currentGeneration(t, svc, ir) != added.GenerationID {
		t.Fatalf("second add = %+v", again)
	}
}

func confirmASA9Again(t *testing.T, svc Service) adminproto.LookupASAResult {
	t.Helper()
	return svc.LookupASA(adminproto.LookupASARequest{Network: "private-dev", AssetID: 9})
}

func TestAddASARefusesWhatChangedOrCannotBeConfirmed(t *testing.T) {
	svc, ir, chain := setupASAAdmin(t)
	before := currentGeneration(t, svc, ir)
	looked := svc.LookupASA(adminproto.LookupASARequest{Network: "private-dev", AssetID: 9})
	if !looked.Success {
		t.Fatal(looked)
	}
	// The clawback address moves between the confirmation and the add.
	chain.beforeRead = func(reads int, p *models.AssetParams) { p.Clawback = "" }
	if got := svc.AddASA(adminproto.AddASARequest{Confirmed: looked.Asset}); got.Code != "confirmation_stale" {
		t.Fatalf("AddASA() after a change = %+v", got)
	}
	chain.beforeRead = nil
	// A confirmation edited by the client is refused the same way.
	edited := looked.Asset
	edited.Decimals = 6
	if got := svc.AddASA(adminproto.AddASARequest{Confirmed: edited}); got.Code != "confirmation_stale" {
		t.Fatalf("AddASA() of an edited confirmation = %+v", got)
	}
	wrongChain := looked.Asset
	wrongChain.GenesisHash = apconfig.AlgorandTestnetGenesisHash
	if got := svc.AddASA(adminproto.AddASARequest{Confirmed: wrongChain}); got.Code != "confirmation_stale" {
		t.Fatalf("AddASA() for another chain = %+v", got)
	}
	if got := svc.LookupASA(adminproto.LookupASARequest{Network: "nowhere", AssetID: 9}); got.Code != "unknown_network" {
		t.Fatalf("LookupASA(unknown network) = %+v", got)
	}
	if got := svc.LookupASA(adminproto.LookupASARequest{Network: "mainnet", AssetID: 31566704}); got.Code != "asa_builtin" {
		t.Fatalf("LookupASA(built-in USDC) = %+v", got)
	}
	if got := svc.LookupASA(adminproto.LookupASARequest{Network: "private-dev", AssetID: 10}); got.Code != "lookup_failed" {
		t.Fatalf("LookupASA(missing asset) = %+v", got)
	}
	if currentGeneration(t, svc, ir) != before {
		t.Fatal("a refused add minted a generation")
	}
}

func applyDefault(t *testing.T, svc Service, sparse string) {
	t.Helper()
	view := svc.GetPolicy()
	result := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: policytest.MustDocument(noderole.RoleSigner, policy.DefaultKey, sparse)}},
		ExpectedPolicySetSHA256: view.PolicySetSHA256,
	})
	if !result.Success {
		t.Fatalf("ApplyPolicy() = %+v", result)
	}
}

func TestRemoveASARefusesWhileReferenced(t *testing.T) {
	for name, tc := range map[string]struct {
		sparse  string
		pointer string
	}{
		"a limit": {`{"limits": {"private-dev": {"asa:9": {"reject_above": "5"}}}}`, "/limits/private-dev/asa:9"},
		// A direct term under "*" fails admission today, but it still names
		// asset 9 on private-dev, so it still blocks removal.
		"a direct term under every network": {`{"transfer_policy": {"routes": [{"id": "r", "networks": ["*"], "sources": ["*"], "assets": ["asa:9"], "destinations": ["*"]}]}}`,
			"/transfer_policy/routes/0/assets/0"},
	} {
		t.Run(name, func(t *testing.T) {
			svc, ir, _ := setupASAAdmin(t)
			if added := confirmASA9(t, svc); !added.Success {
				t.Fatal(added)
			}
			applyDefault(t, svc, tc.sparse)
			before := currentGeneration(t, svc, ir)
			got := svc.RemoveASA(adminproto.RemoveASARequest{Network: "private-dev", AssetID: 9})
			if got.Success || got.Code != "asa_referenced" || len(got.Blocking) != 1 ||
				got.Blocking[0].Document != policy.DefaultKey || got.Blocking[0].Pointer != tc.pointer {
				t.Fatalf("RemoveASA() = %+v", got)
			}
			if currentGeneration(t, svc, ir) != before {
				t.Fatal("a refused removal minted a generation")
			}
			applyDefault(t, svc, `{}`)
			if removed := svc.RemoveASA(adminproto.RemoveASARequest{Network: "private-dev", AssetID: 9}); !removed.Success {
				t.Fatalf("RemoveASA() once unreferenced = %+v", removed)
			}
			if _, set := ir.PolicyState(); len(set.Entries()) != 0 {
				t.Fatalf("runtime set after removal = %+v", set.Entries())
			}
		})
	}
}

func TestRemoveASARefusals(t *testing.T) {
	svc, _, _ := setupASAAdmin(t)
	if got := svc.RemoveASA(adminproto.RemoveASARequest{Network: "mainnet", AssetID: 31566704}); got.Code != "asa_builtin" {
		t.Fatalf("RemoveASA(built-in) = %+v", got)
	}
	if got := svc.RemoveASA(adminproto.RemoveASARequest{Network: "private-dev", AssetID: 9}); got.Code != "not_found" {
		t.Fatalf("RemoveASA(unconfirmed) = %+v", got)
	}
	if got := svc.RemoveASA(adminproto.RemoveASARequest{Network: "nowhere", AssetID: 9}); got.Code != "unknown_network" {
		t.Fatalf("RemoveASA(unknown network) = %+v", got)
	}
	// An entry can be named by its chain, as an inactive one must be.
	if added := confirmASA9(t, svc); !added.Success {
		t.Fatal(added)
	}
	if got := svc.RemoveASA(adminproto.RemoveASARequest{GenesisHash: asaTestChain, AssetID: 9}); !got.Success {
		t.Fatalf("RemoveASA(by genesis hash) = %+v", got)
	}
}

func TestASASetRequiresLoadedState(t *testing.T) {
	svc, ir, _ := setupASAAdmin(t)
	ir.SetVerifiedPolicyState(nil, nil)
	if got := svc.ListASASet(); got.Code != "policy_unavailable" {
		t.Fatalf("ListASASet() before load = %+v", got)
	}
	noChain := svc
	noChain.ASAChain = nil
	if got := noChain.LookupASA(adminproto.LookupASARequest{Network: "private-dev", AssetID: 9}); !strings.Contains(got.Code, "unavailable") {
		t.Fatalf("LookupASA() without a chain view = %+v", got)
	}
}
