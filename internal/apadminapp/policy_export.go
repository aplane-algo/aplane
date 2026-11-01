// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"errors"
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policycontext"
	"github.com/aplane-algo/aplane/internal/policyexport"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// WritePolicyExport writes an export of the documents a node returned, in
// the context view it sent with them (policyexport.Write).
func WritePolicyExport(dir string, docs []policyexport.Document, view adminproto.PolicyContextView, at time.Time) ([]string, error) {
	ctx, err := PolicyContextFromView(view)
	if err != nil {
		return nil, err
	}
	return policyexport.Write(dir, docs, ctx, view.PolicySetSHA256, view.SnapshotSHA256, at)
}

// PolicyContextFromView is the context a node described, checked against the
// digests it sent with it: a context whose contents do not produce its own
// digest, or a snapshot that is not the context's with its policy set, is
// refused rather than exported.
func PolicyContextFromView(view adminproto.PolicyContextView) (*policycontext.Context, error) {
	if !view.Success {
		return nil, fmt.Errorf("the node's policy context is unavailable: %s", view.Error)
	}
	networks := make(map[string]asaset.GenesisHash, len(view.Networks))
	for _, n := range view.Networks {
		genesis, err := asaset.ParseGenesisHash(n.GenesisHash)
		if err != nil {
			return nil, fmt.Errorf("network %q: %w", n.Network, err)
		}
		if _, dup := networks[n.Network]; dup {
			return nil, fmt.Errorf("network %q is listed twice", n.Network)
		}
		networks[n.Network] = genesis
	}
	assets := make([]asaset.Asset, 0, len(view.Assets))
	for _, a := range view.Assets {
		genesis, err := asaset.ParseGenesisHash(a.GenesisHash)
		if err != nil {
			return nil, fmt.Errorf("asset %d: %w", a.AssetID, err)
		}
		assets = append(assets, asaset.Asset{
			Identity: asaset.Identity{Genesis: genesis, AssetID: a.AssetID},
			Name:     a.Name, UnitName: a.UnitName, Decimals: a.Decimals, Origin: asaset.Origin(a.Origin),
		})
	}
	table, err := asaset.NewTable(assets)
	if err != nil {
		return nil, err
	}
	ctx, err := policycontext.FromParts(noderole.Role(view.NodeRole), networks, table, view.RulesVersion)
	if err != nil {
		return nil, err
	}
	if ctx.SHA256() != view.ContextSHA256 {
		return nil, errors.New("the node's policy context does not match its context_sha256")
	}
	if policycontext.SnapshotSHA256(view.ContextSHA256, view.PolicySetSHA256) != view.SnapshotSHA256 {
		return nil, errors.New("the node's snapshot_sha256 is not its context's with its policy set")
	}
	return ctx, nil
}

// PolicyContextViewFromMessage is the policy context a get_policy_context reply carries,
// the inverse of the server's projection onto the wire.
func PolicyContextViewFromMessage(msg protocol.PolicyContextMessage) adminproto.PolicyContextView {
	view := adminproto.PolicyContextView{
		Success: msg.Success, NodeRole: msg.NodeRole, RulesVersion: msg.RulesVersion,
		ContextSHA256: msg.ContextSHA256, PolicySetSHA256: msg.PolicySetSHA256, SnapshotSHA256: msg.SnapshotSHA256,
		Code: msg.Code, Error: msg.Error,
	}
	for _, n := range msg.Networks {
		view.Networks = append(view.Networks, adminproto.PolicyNetwork{Network: n.Network, GenesisHash: n.GenesisHash})
	}
	for _, a := range msg.Assets {
		view.Assets = append(view.Assets, adminproto.ASAInfo{
			Network: a.Network, GenesisHash: a.GenesisHash, AssetID: a.AssetID, Name: a.Name,
			UnitName: a.UnitName, Decimals: a.Decimals, Origin: a.Origin,
		})
	}
	return view
}
