// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policycontext"
)

// nodeContextView is what a signer node with the built-in networks and
// assets sends for the policy set setSHA256.
func nodeContextView(t *testing.T, setSHA256 string) adminproto.PolicyContextView {
	t.Helper()
	ctx, err := policycontext.New(noderole.RoleSigner, apconfig.DefaultGenesisHashNetworkResolver(), asaset.Empty())
	if err != nil {
		t.Fatal(err)
	}
	view := adminproto.PolicyContextView{
		Success: true, NodeRole: string(ctx.Role()), RulesVersion: ctx.RulesVersion(),
		ContextSHA256: ctx.SHA256(), PolicySetSHA256: setSHA256,
		SnapshotSHA256: policycontext.SnapshotSHA256(ctx.SHA256(), setSHA256),
	}
	for token, genesis := range ctx.Networks() {
		view.Networks = append(view.Networks, adminproto.PolicyNetwork{Network: token, GenesisHash: genesis.String()})
	}
	for _, a := range ctx.Assets().Assets() {
		view.Assets = append(view.Assets, adminproto.ASAInfo{
			GenesisHash: a.Genesis.String(), AssetID: a.AssetID, Name: a.Name, UnitName: a.UnitName, Decimals: a.Decimals, Origin: string(a.Origin),
		})
	}
	return view
}

func TestPolicyContextFromViewChecksTheNodesDigests(t *testing.T) {
	set := strings.Repeat("a", 64)
	view := nodeContextView(t, set)
	ctx, err := PolicyContextFromView(view)
	if err != nil || ctx.SHA256() != view.ContextSHA256 {
		t.Fatalf("PolicyContextFromView() = %v, %v", ctx, err)
	}

	decimals := nodeContextView(t, set)
	decimals.Assets[0].Decimals++
	stale := nodeContextView(t, set)
	stale.SnapshotSHA256 = strings.Repeat("0", 64)
	twice := nodeContextView(t, set)
	twice.Networks = append(twice.Networks, twice.Networks[0])
	for name, tc := range map[string]struct {
		view adminproto.PolicyContextView
		want string
	}{
		"an asset's decimals": {decimals, "context_sha256"},
		"a stale snapshot":    {stale, "snapshot_sha256"},
		"a network twice":     {twice, "listed twice"},
		"no context":          {adminproto.PolicyContextView{Error: "policy is not loaded"}, "unavailable"},
	} {
		if _, err := PolicyContextFromView(tc.view); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: PolicyContextFromView() error = %v, want one naming %q", name, err, tc.want)
		}
	}
}
