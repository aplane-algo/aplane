// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authorization

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
)

func TestCompleteAdminArgsPadsInteriorSlots(t *testing.T) {
	base := [][]byte{{0x01}}
	signature := []byte{0xaa, 0xbb}
	args, err := completeAdminArgs(base, 3, signature)
	if err != nil {
		t.Fatalf("completeAdminArgs() error = %v", err)
	}
	if len(args) != 4 || !bytes.Equal(args[0], base[0]) || len(args[1]) != 0 || len(args[2]) != 0 || !bytes.Equal(args[3], signature) {
		t.Fatalf("completeAdminArgs() = %#v", args)
	}
	signature[0] = 0
	if args[3][0] != 0xaa {
		t.Fatal("completeAdminArgs() retained the caller's signature buffer")
	}
}

func TestCompleteAdminArgsRejectsOccupiedAdminSlot(t *testing.T) {
	if _, err := completeAdminArgs([][]byte{{1}, {2}}, 1, []byte{3}); err == nil {
		t.Fatal("completeAdminArgs() accepted an occupied admin slot")
	}
}

func TestValidateNetworkContext(t *testing.T) {
	mainnetHash, err := base64.StdEncoding.DecodeString(config.AlgorandMainnetGenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	customHash := bytes.Repeat([]byte{0x42}, 32)
	tests := []struct {
		name        string
		network     string
		genesisHash []byte
		verified    bool
		wantError   string
	}{
		{name: "canonical built-in", network: config.NetworkMainnet, genesisHash: mainnetHash, verified: true},
		{name: "wrong built-in label", network: config.NetworkTestnet, genesisHash: mainnetHash, wantError: "canonical mainnet"},
		{name: "custom label on built-in hash", network: "production", genesisHash: mainnetHash, wantError: "canonical mainnet"},
		{name: "reserved label on custom hash", network: config.NetworkMainnet, genesisHash: customHash, wantError: "canonical genesis hash"},
		{name: "custom mapping unavailable offline", network: "localnet", genesisHash: customHash},
		{name: "invalid token", network: "Local Net", genesisHash: customHash, wantError: "network context is invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verified, err := validateNetworkContext(test.network, test.genesisHash)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("validateNetworkContext() error = %v, want containing %q", err, test.wantError)
				}
				return
			}
			if err != nil || verified != test.verified {
				t.Fatalf("validateNetworkContext() = (%v, %v), want (%v, nil)", verified, err, test.verified)
			}
		})
	}
}
