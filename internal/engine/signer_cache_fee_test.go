// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/protocol"

	"github.com/aplane-algo/aplane/internal/lsigresource"
)

func TestAuthorizationFeeReserveUsesConsensusResourceModel(t *testing.T) {
	const address = "ADDR"
	tests := []struct {
		name      string
		consensus protocol.ConsensusVersion
		want      uint64
	}{
		{name: "v41 combined bytes require five dummies", consensus: protocol.ConsensusV41, want: 5_000},
		{name: "v42 args require one dummy and all program bytes are priced", consensus: protocol.ConsensusV42, want: 1_251},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := newAccountMockTransport(t)
			transport.txParams.ConsensusVersion = string(test.consensus)
			engine := setupEngineWithMockAlgod(t, transport)
			engine.SignerCache.SetLogicSigResourceProfile(address, lsigresource.Profile{
				ProgramBytes: 4_500,
				Spend: &lsigresource.PathProfile{
					ArgumentBytes: 1_423,
					MaxOpcodeCost: 20_000,
				},
			})

			got, err := engine.AuthorizationFeeReserve(context.Background(), address)
			if err != nil {
				t.Fatalf("AuthorizationFeeReserve() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("AuthorizationFeeReserve() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestAuthorizationFeeReserveUsesNativeFalconContribution(t *testing.T) {
	const address = "ADDR"
	transport := newAccountMockTransport(t)
	transport.txParams.ConsensusVersion = string(protocol.ConsensusV42)
	engine := setupEngineWithMockAlgod(t, transport)
	engine.SignerCache.AddAddress(address, "falcon1024")

	got, err := engine.AuthorizationFeeReserve(context.Background(), address)
	if err != nil {
		t.Fatalf("AuthorizationFeeReserve() error = %v", err)
	}
	if got != 2_000 {
		t.Fatalf("AuthorizationFeeReserve() = %d, want 2000", got)
	}
}

func TestAuthorizationFeeReserveSkipsOrdinaryAccountWithoutAlgod(t *testing.T) {
	engine, err := NewEngine("test")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	got, err := engine.AuthorizationFeeReserve(context.Background(), "ADDR")
	if err != nil || got != 0 {
		t.Fatalf("AuthorizationFeeReserve() = %d, %v; want 0, nil", got, err)
	}
}
