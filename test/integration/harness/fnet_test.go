// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"strings"
	"testing"
)

func TestValidateFNetIntegrationIdentityAndConsensus(t *testing.T) {
	const endpoint = "https://fnet.example"
	if err := validateIntegrationNetwork(IntegrationNetworkFNet, endpoint,
		FNetGenesisID, FNetGenesisHash, FNetConsensus, FNetConsensus); err != nil {
		t.Fatalf("valid FNet profile rejected: %v", err)
	}

	tests := []struct {
		name             string
		genesisID        string
		genesisHash      string
		suggestedVersion string
		statusVersion    string
		want             string
	}{
		{name: "genesis id", genesisID: "other-v1", genesisHash: FNetGenesisHash, suggestedVersion: FNetConsensus, statusVersion: FNetConsensus, want: "requires genesis"},
		{name: "genesis hash", genesisID: FNetGenesisID, genesisHash: "wrong", suggestedVersion: FNetConsensus, statusVersion: FNetConsensus, want: "requires genesis"},
		{name: "suggested consensus", genesisID: FNetGenesisID, genesisHash: FNetGenesisHash, suggestedVersion: "future", statusVersion: FNetConsensus, want: "requires consensus"},
		{name: "status consensus", genesisID: FNetGenesisID, genesisHash: FNetGenesisHash, suggestedVersion: FNetConsensus, statusVersion: "future", want: "requires consensus"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIntegrationNetwork(IntegrationNetworkFNet, endpoint,
				tt.genesisID, tt.genesisHash, tt.suggestedVersion, tt.statusVersion)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateIntegrationNetwork() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestFNetEndpointUsesExplicitOverrides(t *testing.T) {
	t.Setenv("ALGOD_URL", "")
	t.Setenv("ALGOD_TOKEN", "")
	t.Setenv("APLANE_FNET_ALGOD_URL", "https://custom-fnet.example")
	t.Setenv("APLANE_FNET_ALGOD_TOKEN", "test-token")

	url, token, err := integrationAlgodEndpoint(IntegrationNetworkFNet)
	if err != nil {
		t.Fatalf("integrationAlgodEndpoint() error = %v", err)
	}
	if url != "https://custom-fnet.example" || token != "test-token" {
		t.Fatalf("integrationAlgodEndpoint() = %q, %q", url, token)
	}
}
