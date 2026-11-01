// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/asasetstore"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/policyapply"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// The ASA set holds the assets the operator confirmed, beside the built-in
// table. Confirming an asset reads it from the node's own algod for the
// network, after checking that node serves the network's genesis hash; the
// operator confirms what it reported, and the node reads it again and adds it
// only if nothing changed. Adding and removing mint a generation under the
// store mutation lock, never holding it across network I/O, and reload the
// runtime from it, the way a policy apply does.

// ASAOperation is the operation an ASA set mint records.
const ASAOperation = "asa-set-update"

// maxBlockingReferences caps the references a refused removal reports, so
// the response fits one admin frame.
const maxBlockingReferences = 256

// asaLookupTimeout bounds one algod read.
const asaLookupTimeout = 15 * time.Second

// ASAChain is the node's view of its networks and their chains.
type ASAChain interface {
	// Networks is the node's genesis-hash mapping: the built-in networks
	// plus its configured custom ones.
	Networks() apconfig.GenesisHashNetworkResolver
	// ReadAsset reads an asset from the node serving genesisHash, after
	// checking that node's own genesis hash.
	ReadAsset(ctx context.Context, genesisHash []byte, assetID uint64) (models.AssetParams, error)
}

// ListASASet returns the node's effective ASA set: the built-ins and the
// operator's confirmations, each with the token that names its chain now.
func (s Service) ListASASet() adminproto.ListASASetResult {
	_, set := s.Runtime.PolicyState()
	if set == nil {
		return adminproto.ListASASetResult{Code: "policy_unavailable", Error: "policy is not loaded; unlock the signer"}
	}
	tokens := chainTokens(s.networks())
	var out []adminproto.ASAInfo
	builtins := map[asaset.Identity]bool{}
	for _, a := range asaset.Builtins() {
		builtins[a.Identity] = true
		out = append(out, adminproto.ASAInfo{
			Network: tokens[a.Genesis], GenesisHash: a.Genesis.String(), AssetID: a.AssetID,
			Name: a.Name, UnitName: a.UnitName, Decimals: a.Decimals, Origin: string(a.Origin),
		})
	}
	for _, e := range set.Entries() {
		out = append(out, asaInfo(e, tokens[e.Genesis], builtins[e.Identity]))
	}
	return adminproto.ListASASetResult{Assets: out}
}

// LookupASA reads an asset for the operator to confirm. Nothing is stored.
func (s Service) LookupASA(req adminproto.LookupASARequest) adminproto.LookupASAResult {
	if s.ASAChain == nil {
		return adminproto.LookupASAResult{Code: "asa_unavailable", Error: errASAUnavailable.Error()}
	}
	_, set := s.Runtime.PolicyState()
	if set == nil {
		return adminproto.LookupASAResult{Code: "policy_unavailable", Error: "policy is not loaded; unlock the signer"}
	}
	genesis, err := s.chainFor(req.Network)
	if err != nil {
		return adminproto.LookupASAResult{Code: "unknown_network", Error: err.Error()}
	}
	id := asaset.Identity{Genesis: genesis, AssetID: req.AssetID}
	if code, err := addableIdentity(id, set); err != nil {
		return adminproto.LookupASAResult{Code: code, Error: err.Error()}
	}
	obs, err := s.observe(req.Network, genesis, req.AssetID)
	if err != nil {
		return adminproto.LookupASAResult{Code: "lookup_failed", Error: err.Error()}
	}
	return adminproto.LookupASAResult{Success: true, Asset: obs}
}

// AddASA adds the asset the operator confirmed, after reading it again and
// finding every confirmed value unchanged.
func (s Service) AddASA(req adminproto.AddASARequest) adminproto.AddASAResult {
	if s.ASAChain == nil {
		return adminproto.AddASAResult{Code: "asa_unavailable", Error: errASAUnavailable.Error()}
	}
	confirmed := req.Confirmed
	genesis, err := s.chainFor(confirmed.Network)
	if err != nil {
		return adminproto.AddASAResult{Code: "unknown_network", Error: err.Error()}
	}
	if genesis.String() != confirmed.GenesisHash {
		return adminproto.AddASAResult{Code: "confirmation_stale", Error: fmt.Sprintf("network %q now names another chain than the one confirmed; look the asset up again", confirmed.Network)}
	}
	// The second read happens before the store lock: network I/O is never
	// done while holding it.
	current, err := s.observe(confirmed.Network, genesis, confirmed.AssetID)
	if err != nil {
		return adminproto.AddASAResult{Code: "lookup_failed", Error: err.Error()}
	}
	if current != confirmed {
		return adminproto.AddASAResult{Code: "confirmation_stale", Error: "the asset's parameters changed since they were confirmed; look it up and confirm again"}
	}
	entry := asaset.Entry{
		Identity:              asaset.Identity{Genesis: genesis, AssetID: confirmed.AssetID},
		Name:                  confirmed.Name,
		UnitName:              confirmed.UnitName,
		Decimals:              confirmed.Decimals,
		Creator:               confirmed.Creator,
		ConfirmedAt:           s.now(),
		NetworkAtConfirmation: confirmed.Network,
	}
	var generationID string
	var uncertain bool
	err = s.mutateASASet(&generationID, &uncertain, func(_ *crypto.Keyring, _ storepaths.GenPaths, set *asaset.Set) (*asaset.Set, error) {
		// The mapping and the set are checked again under the lock: a
		// concurrent change is a conflict, not a silent retry.
		again, err := s.chainFor(confirmed.Network)
		if err != nil || again != genesis {
			return nil, asaError{"confirmation_stale", fmt.Sprintf("network %q changed while the asset was being confirmed; look it up again", confirmed.Network)}
		}
		if code, err := addableIdentity(entry.Identity, set); err != nil {
			return nil, asaError{code, err.Error()}
		}
		return set.With(entry)
	})
	if err != nil {
		return adminproto.AddASAResult{Code: asaCode(err, "asa_add_failed"), Error: err.Error(), CommitUncertain: uncertain, GenerationID: generationID}
	}
	return adminproto.AddASAResult{Success: true, GenerationID: generationID, Asset: asaInfo(entry, confirmed.Network, false)}
}

// RemoveASA removes an operator entry, refusing while any stored document
// explicitly names the asset.
func (s Service) RemoveASA(req adminproto.RemoveASARequest) adminproto.RemoveASAResult {
	if s.ASAChain == nil {
		return adminproto.RemoveASAResult{Code: "asa_unavailable", Error: errASAUnavailable.Error()}
	}
	var genesis asaset.GenesisHash
	var err error
	switch {
	case req.GenesisHash != "":
		genesis, err = asaset.ParseGenesisHash(req.GenesisHash)
	default:
		genesis, err = s.chainFor(req.Network)
	}
	if err != nil {
		return adminproto.RemoveASAResult{Code: "unknown_network", Error: err.Error()}
	}
	id := asaset.Identity{Genesis: genesis, AssetID: req.AssetID}
	var generationID string
	var uncertain bool
	var blocking []adminproto.ASAReference
	var blockingOmitted int
	err = s.mutateASASet(&generationID, &uncertain, func(kr *crypto.Keyring, active storepaths.GenPaths, set *asaset.Set) (*asaset.Set, error) {
		next, found := set.Without(id)
		if !found {
			if builtinIdentity(id) {
				return nil, asaError{"asa_builtin", fmt.Sprintf("%s is built in and cannot be removed", id)}
			}
			return nil, asaError{"not_found", fmt.Sprintf("%s is not in this node's ASA set", id)}
		}
		// A confirmation a later release made built-in is shadowed: the
		// built-in entry is the one used, so removing the confirmation
		// leaves the effective table unchanged, and references to the
		// asset stay valid.
		if builtinIdentity(id) {
			return next, nil
		}
		current, err := policyruntime.Load(s.Runtime.NodeRole(), s.Deps.Config(), active, kr)
		if err != nil {
			return nil, fmt.Errorf("verify active policy: %w", err)
		}
		blocking, err = referencesTo(current, id, s.networks())
		if err != nil {
			return nil, err
		}
		if len(blocking) > 0 {
			total := len(blocking)
			if total > maxBlockingReferences {
				blockingOmitted = total - maxBlockingReferences
				blocking = blocking[:maxBlockingReferences]
			}
			for i := range blocking {
				blocking[i].Pointer = policyapply.TruncateText(blocking[i].Pointer, policyapply.MaxProblemTextBytes)
			}
			return nil, asaError{"asa_referenced", fmt.Sprintf("%s is named by %d policy reference(s); change those documents first", id, total)}
		}
		return next, nil
	})
	if err != nil {
		return adminproto.RemoveASAResult{Code: asaCode(err, "asa_remove_failed"), Error: err.Error(), Blocking: blocking, BlockingOmitted: blockingOmitted, CommitUncertain: uncertain, GenerationID: generationID}
	}
	return adminproto.RemoveASAResult{Success: true, GenerationID: generationID}
}

// mutateASASet, under the store mutation lock, loads the current set, lets
// change produce the next one, mints a generation carrying it, and reloads
// the runtime from that generation.
func (s Service) mutateASASet(generationID *string, uncertain *bool, change func(*crypto.Keyring, storepaths.GenPaths, *asaset.Set) (*asaset.Set, error)) error {
	ir := s.Runtime
	err := s.Deps.WithStoreMutation(func() error {
		if ir.IsRecovery() {
			return asaError{protocol.ResultCodeRecoveryBlocked, "the store is in recovery mode; reconcile, roll back, or restore it before changing the ASA set"}
		}
		err := ir.WithKeyring(func(kr *crypto.Keyring) error {
			active, err := genstore.ResolveStoreRootWithKeyring(s.Deps.KeyPaths(), kr)
			if err != nil {
				return fmt.Errorf("resolve active generation: %w", err)
			}
			set, err := asasetstore.Load(active, kr)
			if err != nil {
				return fmt.Errorf("verify active asa set: %w", err)
			}
			next, err := change(kr, active, set)
			if err != nil {
				return err
			}
			id, mintErr := s.mintASASet(active, next, kr)
			*generationID = id
			if mintErr != nil {
				visible, visibleErr := genstore.ResolveStoreRootWithKeyring(s.Deps.KeyPaths(), kr)
				if errors.Is(mintErr, genstore.ErrStoreRootCommitDurabilityUnknown) || (visibleErr == nil && visible.GenerationID() == id) {
					*uncertain = true
					return asaError{"asa_commit_uncertain", fmt.Sprintf("the ASA set committed as generation %s but durability is unconfirmed; signing is blocked pending reconciliation: %v", id, mintErr)}
				}
				*generationID = ""
				return fmt.Errorf("asa set change failed before commit: %w", mintErr)
			}
			return nil
		})
		if *uncertain {
			ir.SetRecovery()
			_, _ = ir.Reload()
			return err
		}
		if err != nil {
			return err
		}
		if _, err := ir.Reload(); err != nil {
			*uncertain = true
			ir.SetRecovery()
			return asaError{"asa_reload_failed", "the ASA set committed as generation " + *generationID + " but runtime reload failed; signing is blocked pending recovery: " + err.Error()}
		}
		return nil
	})
	if errors.Is(err, keystore.ErrStoreLocked) {
		return asaError{"identity_locked", "identity is locked; unlock the signer before changing the ASA set"}
	}
	return err
}

func (s Service) mintASASet(active storepaths.GenPaths, set *asaset.Set, kr *crypto.Keyring) (string, error) {
	now := s.now()
	generationID, err := genstore.NewGenerationID(now)
	if err != nil {
		return "", err
	}
	_, err = genstore.Mint(s.Deps.KeyPaths(), genstore.MintRequest{
		GenerationID: generationID,
		Parent:       active.GenerationID(),
		Operation:    ASAOperation,
		OperationID:  "asa-" + generationID,
		CreatedAt:    now,
		Integrity:    kr,
		Apply: func(staged storepaths.GenPaths) error {
			return asasetstore.Write(staged, set, kr, now)
		},
		ValidateCandidate: func(staged storepaths.GenPaths) error {
			return storevalidate.Candidate(storevalidate.Options{
				Paths: s.Deps.KeyPaths(), Candidate: staged, Keyring: kr,
				ExpectedRole: s.Runtime.NodeRole(), DataDir: s.Deps.DataDir(), Config: s.Deps.Config(),
			})
		},
	})
	return generationID, err
}

// observe reads an asset from the node's algod for network.
func (s Service) observe(network string, genesis asaset.GenesisHash, assetID uint64) (adminproto.ASAObservation, error) {
	if assetID == 0 {
		return adminproto.ASAObservation{}, errors.New("asset ID must be positive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), asaLookupTimeout)
	defer cancel()
	params, err := s.ASAChain.ReadAsset(ctx, genesis[:], assetID)
	if err != nil {
		return adminproto.ASAObservation{}, err
	}
	return adminproto.ASAObservation{
		Network: network, GenesisHash: genesis.String(), AssetID: assetID,
		Name: params.Name, UnitName: params.UnitName, Decimals: params.Decimals,
		Total: params.Total, DefaultFrozen: params.DefaultFrozen, URL: params.Url,
		Creator: params.Creator, Manager: params.Manager, Reserve: params.Reserve,
		Freeze: params.Freeze, Clawback: params.Clawback,
	}, nil
}

// chainFor resolves a network token to the chain it names on this node.
func (s Service) chainFor(network string) (asaset.GenesisHash, error) {
	for hash, token := range s.networks().Map() {
		if token == network {
			return asaset.ParseGenesisHash(hash)
		}
	}
	return asaset.GenesisHash{}, fmt.Errorf("network %q is not one this node knows", network)
}

var errASAUnavailable = errors.New("the ASA set cannot be changed on this node")

// networks is the node's genesis-hash mapping: the chain view's, or, without
// one, the mapping built from the node's config.
func (s Service) networks() apconfig.GenesisHashNetworkResolver {
	if s.ASAChain != nil {
		return s.ASAChain.Networks()
	}
	var custom map[string]string
	if s.Deps != nil && s.Deps.Config() != nil {
		custom = s.Deps.Config().GenesisHashNetworks
	}
	if r, err := apconfig.NewGenesisHashNetworkResolver(custom); err == nil {
		return r
	}
	return apconfig.DefaultGenesisHashNetworkResolver()
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// addableIdentity refuses a built-in asset and one already confirmed.
func addableIdentity(id asaset.Identity, set *asaset.Set) (string, error) {
	if builtinIdentity(id) {
		return "asa_builtin", fmt.Errorf("%s is built in; it needs no confirmation", id)
	}
	if _, ok := set.Lookup(id); ok {
		return "asa_already_confirmed", fmt.Errorf("%s is already in this node's ASA set", id)
	}
	return "", nil
}

func builtinIdentity(id asaset.Identity) bool {
	for _, a := range asaset.Builtins() {
		if a.Identity == id {
			return true
		}
	}
	return false
}

// referencesTo lists every explicit reference to id in the node's stored
// documents. A direct asa:<id> route term under several networks or "*" is
// expanded over the networks it applies to now, so a document that would
// fail admission today still blocks removal.
func referencesTo(np *policyruntime.NodePolicy, id asaset.Identity, networks apconfig.GenesisHashNetworkResolver) ([]adminproto.ASAReference, error) {
	byToken := map[string]asaset.GenesisHash{}
	for hash, token := range networks.Map() {
		genesis, err := asaset.ParseGenesisHash(hash)
		if err != nil {
			return nil, err
		}
		byToken[token] = genesis
	}
	names := func(network string) bool { return byToken[network] == id.Genesis }
	var out []adminproto.ASAReference
	for _, stored := range np.Documents {
		doc, err := policy.DecodePolicyV1(stored.Bytes, stored.Key, np.Role)
		if err != nil {
			return nil, fmt.Errorf("decode stored policy %s: %w", stored.Key, err)
		}
		refs := doc.References()
		seen := map[string]bool{}
		add := func(pointer string) {
			if !seen[pointer] {
				seen[pointer] = true
				out = append(out, adminproto.ASAReference{Document: stored.Key, Pointer: pointer})
			}
		}
		for _, a := range refs.Assets {
			if a.AssetID == id.AssetID && names(a.Network) {
				add(a.Pointer)
			}
		}
		for _, d := range refs.DirectRouteAssets {
			if d.AssetID != id.AssetID {
				continue
			}
			applies := d.Networks
			if d.NetworkWildcard {
				applies = nil
				for token := range byToken {
					applies = append(applies, token)
				}
			}
			for _, network := range applies {
				if names(network) {
					add(d.Pointer)
					break
				}
			}
		}
	}
	return out, nil
}

// chainTokens maps each chain to the token that names it now.
func chainTokens(networks apconfig.GenesisHashNetworkResolver) map[asaset.GenesisHash]string {
	out := map[asaset.GenesisHash]string{}
	for hash, token := range networks.Map() {
		if genesis, err := asaset.ParseGenesisHash(hash); err == nil {
			out[genesis] = token
		}
	}
	return out
}

func asaInfo(e asaset.Entry, network string, shadowed bool) adminproto.ASAInfo {
	return adminproto.ASAInfo{
		Network: network, GenesisHash: e.Genesis.String(), AssetID: e.AssetID,
		Name: e.Name, UnitName: e.UnitName, Decimals: e.Decimals, Origin: string(asaset.OriginOperator),
		Shadowed: shadowed, Creator: e.Creator, ConfirmedAt: e.ConfirmedAt.UTC().Format(time.RFC3339),
		NetworkAtConfirmation: e.NetworkAtConfirmation,
	}
}

// asaError is an ASA set failure with a protocol result code.
type asaError struct{ code, msg string }

func (e asaError) Error() string { return e.msg }

func asaCode(err error, fallback string) string {
	var ae asaError
	if errors.As(err, &ae) {
		return ae.code
	}
	return fallback
}
