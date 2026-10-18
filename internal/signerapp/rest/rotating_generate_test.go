// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"context"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestRotatingKeyGenerationIsOptIn(t *testing.T) {
	ir := setupProductRuntime(t, true)
	// A configured custom network, as LocalNet is in a signer's config.
	const localnetGenesis = "mtfrXt6VMnEhUImpbE0uarG19rcO7L4Vx7TIPd8q8Ok="
	networks := func() map[string]string {
		return map[string]string{"localnet": localnetGenesis, "testnet": "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="}
	}
	svc := Service{Deps: Dependencies{
		KeyAdmin:             keyadmin.Service{Runtime: ir, NetworkGenesisHashes: networks},
		NetworkGenesisHashes: networks,
	}}
	ctx := context.Background()
	req := signerapi.AdminGenerateRequest{KeyType: rotatingkey.RotatingTripleHybridV1, Parameters: map[string]string{"network": "testnet"}}

	// Library key types are hidden and refused until enabled.
	if _, err := svc.AdminGenerate(ctx, ir, req); err == nil {
		t.Fatal("rotating key generated before the key type was enabled")
	}
	if err := keytypestate.Put(ir.KeyPaths(), keytypestate.Record{
		KeyType: rotatingkey.RotatingTripleHybridV1,
		Source:  keytypestate.SourceCompiled,
		State:   keytypestate.StateEnabled,
	}); err != nil {
		t.Fatal(err)
	}

	types, typesErr := svc.KeyTypes(ir)
	if typesErr != nil {
		t.Fatal(typesErr)
	}
	var info *signerapi.KeyTypeInfo
	for i := range types.KeyTypes {
		if types.KeyTypes[i].KeyType == rotatingkey.RotatingTripleHybridV1 {
			info = &types.KeyTypes[i]
		}
	}
	if info == nil {
		t.Fatal("enabled rotating key type missing from /keytypes")
	}
	if info.SigningFlow != signerapi.SigningFlowRotating1 || len(info.CreationParams) != 1 || info.CreationParams[0].Name != "network" {
		t.Fatalf("key type info = %+v", *info)
	}
	if got := info.CreationParams[0].Options; len(got) != 2 || got[0] != "localnet" || got[1] != "testnet" {
		t.Fatalf("network options = %v, want the configured networks", got)
	}
	if got := info.CreationParams[0].Default; got != "localnet" {
		t.Fatalf("network default = %q, want the only custom network", got)
	}

	for _, params := range []map[string]string{nil, {"network": "nowhere"}, {"network": "testnet", "extra": "1"}} {
		bad := req
		bad.Parameters = params
		if _, err := svc.AdminGenerate(ctx, ir, bad); err == nil {
			t.Fatalf("generation accepted parameters %v", params)
		}
	}

	// apadmin receives the keyadmin result, which carries the mnemonic; the
	// HTTP generate response never does.
	resp, genErr := svc.Deps.KeyAdmin.GenerateKey(ctx, req.KeyType, req.Parameters, nil)
	if genErr != nil {
		t.Fatal(genErr)
	}
	if words := strings.Fields(resp.Mnemonic); len(words) != 24 {
		t.Fatalf("mnemonic has %d words, want 24", len(words))
	}
	keysResp, keysErr := svc.Keys(ir)
	if keysErr != nil {
		t.Fatal(keysErr)
	}
	var row *signerapi.KeyInfo
	for i := range keysResp.Keys {
		if keysResp.Keys[i].Address == resp.Address {
			row = &keysResp.Keys[i]
		}
	}
	if row == nil || row.SigningFlow != signerapi.SigningFlowRotating1 || row.PublicKeyHex != "" || row.AuthorizationKind != "logic_sig" {
		t.Fatalf("inventory row = %+v", row)
	}

	// A configured network name resolves to its genesis hash.
	local, localErr := svc.Deps.KeyAdmin.GenerateKey(ctx, req.KeyType, map[string]string{"network": "localnet"}, nil)
	if localErr != nil {
		t.Fatalf("generate on configured network localnet: %v", localErr)
	}
	if local.Address == resp.Address {
		t.Fatal("two generations returned the same account")
	}
}

func TestDefaultRotatingNetwork(t *testing.T) {
	tests := []struct {
		networks []string
		want     string
	}{
		{[]string{"betanet", "localnet", "mainnet", "testnet"}, "localnet"},
		{[]string{"betanet", "mainnet", "testnet"}, "testnet"},
		{[]string{"betanet", "devnet", "localnet", "mainnet", "testnet"}, "testnet"},
		{[]string{"mainnet"}, ""},
		{nil, ""},
	}
	for _, tt := range tests {
		if got := defaultRotatingNetwork(tt.networks); got != tt.want {
			t.Errorf("defaultRotatingNetwork(%v) = %q, want %q", tt.networks, got, tt.want)
		}
	}
}
