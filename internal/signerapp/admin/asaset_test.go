// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/aplane-algo/aplane/internal/policycontext"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	"github.com/aplane-algo/aplane/internal/signerapp/policyapply"
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
			ir.SetVerifiedPolicyState(np, set, nil)
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
		ExpectedSnapshotSHA256:  svc.GetPolicyContext().SnapshotSHA256,
	})
	if !result.Success {
		t.Fatalf("ApplyPolicy() = %+v", result)
	}
}

func TestRemoveASARefusesWhileReferenced(t *testing.T) {
	for name, tc := range map[string]struct {
		sparse  string
		pointer string
		legacy  bool
	}{
		"a limit": {`{"limits": {"private-dev": {"asa:9": {"reject_above": "5"}}}}`, "/limits/private-dev/asa:9", false},
		// A direct term under "*" is refused when submitted, but one stored
		// before admission was enforced still names asset 9 on private-dev,
		// so it still blocks removal.
		"a stored direct term under every network": {`{"transfer_policy": {"routes": [{"id": "r", "networks": ["*"], "sources": ["*"], "assets": ["asa:9"], "destinations": ["*"]}]}}`,
			"/transfer_policy/routes/0/assets/0", true},
	} {
		t.Run(name, func(t *testing.T) {
			svc, ir, _ := setupASAAdmin(t)
			if added := confirmASA9(t, svc); !added.Success {
				t.Fatal(added)
			}
			if tc.legacy {
				storeLegacy(t, svc, ir, policy.DefaultKey, tc.sparse)
			} else {
				applyDefault(t, svc, tc.sparse)
			}
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
	ir.SetVerifiedPolicyState(nil, nil, nil)
	if got := svc.ListASASet(); got.Code != "policy_unavailable" {
		t.Fatalf("ListASASet() before load = %+v", got)
	}
	noChain := svc
	noChain.ASAChain = nil
	if got := noChain.LookupASA(adminproto.LookupASARequest{Network: "private-dev", AssetID: 9}); !strings.Contains(got.Code, "unavailable") {
		t.Fatalf("LookupASA() without a chain view = %+v", got)
	}
}

// policy check warns about what a submitted document names that the node does
// not know, and stops once the asset is confirmed. Nothing is refused yet.
func TestPolicyCheckRefusesWhatTheNodeCannotAdmit(t *testing.T) {
	svc, _, _ := setupASAAdmin(t)
	doc := policytest.MustDocument(noderole.RoleSigner, policy.DefaultKey, `{"limits": {"private-dev": {"asa:9": {"reject_above": "5"}}, "mainet": {"algo": {"reject_above": "5"}}}}`)
	check := func() []adminproto.PolicyProblem {
		t.Helper()
		result := svc.CheckPolicy(adminproto.CheckPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: doc}}})
		if !result.Success || result.Valid {
			t.Fatalf("CheckPolicy() = %+v, want it invalid", result)
		}
		return result.Errors
	}
	pointers := func(problems []adminproto.PolicyProblem) string {
		var out []string
		for _, p := range problems {
			if strings.HasPrefix(p.Pointer, "/limits") {
				out = append(out, p.Pointer)
			}
		}
		return strings.Join(out, " ")
	}
	if got := pointers(check()); got != "/limits/mainet /limits/private-dev/asa:9" {
		t.Fatalf("errors before confirming = %q", got)
	}
	if added := confirmASA9(t, svc); !added.Success {
		t.Fatal(added)
	}
	if got := pointers(check()); got != "/limits/mainet" {
		t.Fatalf("errors after confirming = %q", got)
	}
	fixed := policytest.MustDocument(noderole.RoleSigner, policy.DefaultKey, `{"limits": {"private-dev": {"asa:9": {"reject_above": "5"}}, "mainnet": {"algo": {"reject_above": "5"}}}}`)
	if result := svc.CheckPolicy(adminproto.CheckPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: fixed}}}); !result.Valid {
		t.Fatalf("CheckPolicy(fixed) = %+v", result)
	}
	// Apply refuses what check refuses, before anything is written.
	before := svc.GetPolicy().PolicySetSHA256
	got := svc.ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: doc}},
		ExpectedPolicySetSHA256: before,
		ExpectedSnapshotSHA256:  svc.GetPolicyContext().SnapshotSHA256,
	})
	if got.Success || got.Code != "policy_validation_failed" || len(got.Errors) == 0 || svc.GetPolicy().PolicySetSHA256 != before {
		t.Fatalf("ApplyPolicy(unadmissible) = %+v", got)
	}
}

// storeLegacy stores a document for key straight into the active
// generation, as one written before admission was enforced would be, and
// reloads the runtime.
func storeLegacy(t *testing.T, svc Service, ir *productruntime.Runtime, key, sparse string) string {
	t.Helper()
	doc := policytest.MustDocument(noderole.RoleSigner, key, sparse)
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		active, err := genstore.ResolveStoreRootWithKeyring(svc.Deps.KeyPaths(), kr)
		if err != nil {
			return err
		}
		if key == policy.DefaultKey {
			return policy.WriteDefault(active, noderole.RoleSigner, []byte(doc), kr, time.Unix(1_700_000_000, 0))
		}
		return policy.WriteKeyPolicy(active, noderole.RoleSigner, key, []byte(doc), kr, time.Unix(1_700_000_000, 0))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ir.Reload(); err != nil {
		t.Fatalf("a node with a legacy document did not reload: %v", err)
	}
	return doc
}

// A stored document that would not be admitted today keeps its meaning: the
// node loads it, and changes that leave it alone go ahead. Only submitting
// it again, even unchanged, requires fixing it; removing it needs no repair.
func TestLegacyDocumentsDoNotBlockOtherChanges(t *testing.T) {
	svc, ir, _ := setupASAAdmin(t)
	legacyDefault := storeLegacy(t, svc, ir, policy.DefaultKey, `{"limits": {"mainet": {"algo": {"reject_above": "5"}}}}`)
	const key = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"
	storeLegacy(t, svc, ir, key, `{"transfer_policy": {"routes": [{"id": "r", "networks": ["mainnet", "testnet"], "sources": ["*"], "assets": ["asa:31566704"], "destinations": ["*"]}]}}`)

	apply := func(req adminproto.ApplyPolicyRequest) adminproto.ApplyPolicyResult {
		t.Helper()
		req.ExpectedPolicySetSHA256 = svc.GetPolicy().PolicySetSHA256
		req.ExpectedSnapshotSHA256 = svc.GetPolicyContext().SnapshotSHA256
		return svc.ApplyPolicy(req)
	}
	other := "EIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDOHSEZI"
	if got := apply(adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: other, Document: policytest.MustDocument(noderole.RoleSigner, other, "")}}}); !got.Success {
		t.Fatalf("an unrelated apply beside legacy documents = %+v", got)
	}
	if added := confirmASA9(t, svc); !added.Success {
		t.Fatalf("an ASA set change beside legacy documents = %+v", added)
	}
	if got := apply(adminproto.ApplyPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: legacyDefault}}}); got.Success || got.Code != "policy_validation_failed" {
		t.Fatalf("resubmitting the legacy default unchanged = %+v, want it refused", got)
	}
	if got := apply(adminproto.ApplyPolicyRequest{Remove: []string{key}}); !got.Success {
		t.Fatalf("removing a legacy key document = %+v", got)
	}
}

// A confirmation a later release made built-in can be removed even while a
// document names the asset: the built-in entry stays in effect.
func TestRemoveASARemovesAShadowedConfirmationDespiteReferences(t *testing.T) {
	svc, ir, _ := setupASAAdmin(t)
	mainnet, err := asaset.ParseGenesisHash(apconfig.AlgorandMainnetGenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := asaset.New([]asaset.Entry{{
		Identity: asaset.Identity{Genesis: mainnet, AssetID: 31566704},
		UnitName: "OLDUSDC", Decimals: 6, Creator: asaTestCreator,
		ConfirmedAt: time.Unix(1_700_000_000, 0), NetworkAtConfirmation: "mainnet",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		active, err := genstore.ResolveStoreRootWithKeyring(svc.Deps.KeyPaths(), kr)
		if err != nil {
			return err
		}
		return asasetstore.Write(active, stale, kr, time.Unix(1_700_000_000, 0))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ir.Reload(); err != nil {
		t.Fatal(err)
	}
	applyDefault(t, svc, `{"limits": {"mainnet": {"asa:31566704": {"reject_above": "5"}}}}`)

	shadowed := false
	for _, a := range svc.ListASASet().Assets {
		shadowed = shadowed || (a.Origin == "operator" && a.AssetID == 31566704 && a.Shadowed)
	}
	if !shadowed {
		t.Fatal("the stale confirmation is not listed as shadowed")
	}
	got := svc.RemoveASA(adminproto.RemoveASARequest{Network: "mainnet", AssetID: 31566704})
	if !got.Success || len(got.Blocking) != 0 {
		t.Fatalf("RemoveASA(shadowed confirmation) = %+v", got)
	}
	if _, set := ir.PolicyState(); len(set.Entries()) != 0 {
		t.Fatalf("set after removing the shadowed confirmation = %+v", set.Entries())
	}
	builtin := false
	for _, a := range svc.ListASASet().Assets {
		builtin = builtin || (a.Origin == "builtin" && a.AssetID == 31566704 && a.Network == "mainnet")
	}
	if !builtin {
		t.Fatal("the built-in USDC is gone")
	}
}

// encodedSize is a response's size on the wire.
func encodedSize(t *testing.T, msg any) int {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	return len(data)
}

// A valid document can produce tens of thousands of findings; the check
// response must still fit one admin frame and say what it left out.
func TestPolicyCheckBoundsItsDiagnostics(t *testing.T) {
	svc, _, _ := setupASAAdmin(t)
	members := make([]string, 30000)
	for i := range members {
		members[i] = fmt.Sprintf(`"asa:%d"`, i+100)
	}
	doc := policytest.MustDocument(noderole.RoleSigner, policy.DefaultKey, `{
		"asset_sets": {"many": {"private-dev": [`+strings.Join(members, ",")+`]}},
		"transfer_policy": {"routes": [{"id": "two-nets", "networks": ["mainnet", "testnet"], "sources": ["*"], "assets": ["asa:5"], "destinations": ["*"]}]}}`)
	result := svc.CheckPolicy(adminproto.CheckPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: doc}}})
	if !result.Success || result.Valid {
		t.Fatalf("CheckPolicy() = code %q error %q valid %v", result.Code, result.Error, result.Valid)
	}
	if n := len(result.Errors) + len(result.Warnings); n > policyapply.MaxResponseProblems+1 {
		t.Fatalf("response carries %d problems", n)
	}
	last := result.Warnings[len(result.Warnings)-1].Message
	if !strings.Contains(last, "more problem(s) omitted") {
		t.Fatalf("the response does not say findings were omitted: %q", last)
	}
	for _, w := range append(result.Errors, result.Warnings...) {
		if len(w.Message) > policyapply.MaxProblemTextBytes || len(w.Pointer) > policyapply.MaxProblemTextBytes {
			t.Fatalf("a problem exceeds %d bytes: %d / %d", policyapply.MaxProblemTextBytes, len(w.Message), len(w.Pointer))
		}
	}
	if size := encodedSize(t, adminserver.ProtocolCheckPolicyResultMessage("check-1", result)); size > protocol.MaxAdminMessageBytes/4 {
		t.Fatalf("check response is %d bytes", size)
	}
}

func TestRemoveASABoundsBlockingReferences(t *testing.T) {
	svc, _, _ := setupASAAdmin(t)
	if added := confirmASA9(t, svc); !added.Success {
		t.Fatal(added)
	}
	sets := make([]string, 1000)
	for i := range sets {
		sets[i] = fmt.Sprintf(`"s%d": {"private-dev": ["asa:9"]}`, i)
	}
	applyDefault(t, svc, `{"asset_sets": {`+strings.Join(sets, ",")+`}}`)
	got := svc.RemoveASA(adminproto.RemoveASARequest{Network: "private-dev", AssetID: 9})
	if got.Code != "asa_referenced" || len(got.Blocking) != 256 || got.BlockingOmitted != 744 {
		t.Fatalf("RemoveASA() = code %q, %d blocking, %d omitted", got.Code, len(got.Blocking), got.BlockingOmitted)
	}
	if !strings.Contains(got.Error, "1000 policy reference(s)") {
		t.Fatalf("error = %q, want the full count", got.Error)
	}
}

func TestPolicyContextDigestsFollowWhatChanged(t *testing.T) {
	svc, _, _ := setupASAAdmin(t)
	before := svc.GetPolicyContext()
	if !before.Success || before.NodeRole != "signer" || before.RulesVersion != 1 {
		t.Fatalf("GetPolicyContext() = %+v", before)
	}
	var privateDev, usdc bool
	for _, n := range before.Networks {
		privateDev = privateDev || (n.Network == "private-dev" && n.GenesisHash == asaTestChain)
	}
	for _, a := range before.Assets {
		usdc = usdc || (a.AssetID == 31566704 && a.Origin == "builtin" && a.Network == "mainnet")
	}
	if !privateDev || !usdc {
		t.Fatalf("context lacks the custom network or the built-ins: %+v", before.Networks)
	}
	if want := policycontext.SnapshotSHA256(before.ContextSHA256, before.PolicySetSHA256); before.SnapshotSHA256 != want {
		t.Fatalf("snapshot %s, want %s", before.SnapshotSHA256, want)
	}

	// The ASA set moves the context, not the policy set.
	if added := confirmASA9(t, svc); !added.Success {
		t.Fatal(added)
	}
	afterSet := svc.GetPolicyContext()
	if afterSet.ContextSHA256 == before.ContextSHA256 || afterSet.PolicySetSHA256 != before.PolicySetSHA256 || afterSet.SnapshotSHA256 == before.SnapshotSHA256 {
		t.Fatalf("after an ASA add: %+v", afterSet)
	}
	// A policy apply moves the policy set, not the context.
	applyDefault(t, svc, `{"max_fee_microalgos": "3000"}`)
	afterPolicy := svc.GetPolicyContext()
	if afterPolicy.ContextSHA256 != afterSet.ContextSHA256 || afterPolicy.PolicySetSHA256 == afterSet.PolicySetSHA256 {
		t.Fatalf("after a policy apply: %+v", afterPolicy)
	}

	// A read against an old snapshot is refused; against the current one, served.
	if doc := svc.GetPolicyDocumentAt(adminproto.GetPolicyDocumentRequest{Key: policy.DefaultKey, ExpectedSnapshotSHA256: before.SnapshotSHA256}); doc.Success || doc.Code != "policy_snapshot_changed" {
		t.Fatalf("read against a stale snapshot = %+v", doc)
	}
	if doc := svc.GetPolicyDocumentAt(adminproto.GetPolicyDocumentRequest{Key: policy.DefaultKey, ExpectedSnapshotSHA256: afterPolicy.SnapshotSHA256}); !doc.Success {
		t.Fatalf("read against the current snapshot = %+v", doc)
	}
}

// The ASA set file is bounded at 1 MiB; a context carrying a set that large,
// plus the built-ins, still fits one admin frame.
func TestPolicyContextFitsOneAdminFrame(t *testing.T) {
	svc, ir, _ := setupASAAdmin(t)
	genesis, _ := asaset.ParseGenesisHash(asaTestChain)
	var entries []asaset.Entry
	for i := uint64(1); ; i++ {
		entries = append(entries, asaset.Entry{
			Identity: asaset.Identity{Genesis: genesis, AssetID: i}, Name: strings.Repeat("n", asaset.MaxNameBytes),
			UnitName: strings.Repeat("u", asaset.MaxUnitNameBytes), Decimals: 19, Creator: asaTestCreator,
			ConfirmedAt: time.Unix(1_700_000_000, 0), NetworkAtConfirmation: "private-dev",
		})
		if i%500 != 0 {
			continue
		}
		set, err := asaset.New(entries)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := set.Marshal()
		if len(data) > 1<<20 {
			entries = entries[:len(entries)-500]
			break
		}
	}
	set, err := asaset.New(entries)
	if err != nil {
		t.Fatal(err)
	}
	np, _ := ir.PolicyState()
	ir.SetVerifiedPolicyState(np, set, nil)
	view := svc.GetPolicyContext()
	if !view.Success || len(view.Assets) < len(entries) {
		t.Fatalf("GetPolicyContext() carried %d assets for %d entries", len(view.Assets), len(entries))
	}
	if size := encodedSize(t, adminserver.ProtocolPolicyContextMessage("ctx", view)); size > protocol.MaxAdminMessageBytes {
		t.Fatalf("a context with %d entries is %d bytes, over the %d-byte frame", len(entries), size, protocol.MaxAdminMessageBytes)
	} else {
		t.Logf("%d entries: %d bytes", len(entries), size)
	}
}
