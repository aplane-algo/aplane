// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	txsigning "github.com/aplane-algo/aplane/internal/signing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

type AlgodFactory func(serverURL, token string) (*algod.Client, error)

type Simulator struct {
	Config    func() serverconfig.ServerConfig
	MakeAlgod AlgodFactory
}

func (s Simulator) SimulateSignedGroup(ctx context.Context, signedTxns []types.SignedTxn) ([]string, string, bool, *ServiceError) {
	if len(signedTxns) == 0 {
		return nil, "", false, &ServiceError{Kind: ErrorBadRequest, Message: "no transactions to simulate"}
	}

	algodClient, err := s.AlgodForTransactionGroup(signedTxns)
	if err != nil {
		return nil, "", false, err
	}

	var output bytes.Buffer
	txIDs, simErr := txsigning.SimulateSignedTransactionsWithContext(ctx, signedTxns, algodClient, &output)
	if simErr != nil {
		if errors.Is(simErr, txsigning.ErrSimulationFailed) {
			return txIDs, output.String(), true, nil
		}
		return txIDs, output.String(), false, &ServiceError{Kind: ErrorUnavailable, Message: simErr.Error()}
	}
	return txIDs, output.String(), false, nil
}

func (s Simulator) AlgodForTransactionGroup(signedTxns []types.SignedTxn) (*algod.Client, *ServiceError) {
	cfg := s.serverConfig()
	resolver, err := apconfig.NewGenesisHashNetworkResolver(cfg.GenesisHashNetworks)
	if err != nil {
		return nil, &ServiceError{Kind: ErrorInternal, Message: fmt.Sprintf("invalid genesis hash network config: %v", err)}
	}

	genesisHash := signedTxns[0].Txn.GenesisHash
	for i, signedTxn := range signedTxns[1:] {
		if signedTxn.Txn.GenesisHash != genesisHash {
			return nil, &ServiceError{Kind: ErrorBadRequest, Message: fmt.Sprintf("transaction %d has different genesis hash - all transactions must target the same network", i+2)}
		}
	}

	network, ok := resolver.NetworkForGenesisHashBytes(genesisHash[:])
	if !ok {
		return nil, &ServiceError{Kind: ErrorBadRequest, Message: fmt.Sprintf("transaction group has unrecognized genesis hash %x", genesisHash[:])}
	}

	algodCfg, err := cfg.GetAlgodConfig(network)
	if err != nil {
		return nil, &ServiceError{Kind: ErrorUnavailable, Message: fmt.Sprintf("algod config for network %q is unavailable: %v", network, err)}
	}
	if algodCfg == nil || algodCfg.Server == "" {
		return nil, &ServiceError{Kind: ErrorUnavailable, Message: fmt.Sprintf("algod server for network %q is not configured", network)}
	}

	makeAlgod := s.MakeAlgod
	if makeAlgod == nil {
		makeAlgod = txsigning.CreateAlgodClient
	}
	algodClient, err := makeAlgod(algodCfg.Server, algodCfg.Token)
	if err != nil {
		return nil, &ServiceError{Kind: ErrorUnavailable, Message: fmt.Sprintf("failed to create algod client for network %q: %v", network, err)}
	}
	if algodClient == nil {
		return nil, &ServiceError{Kind: ErrorUnavailable, Message: fmt.Sprintf("algod client for network %q is not configured", network)}
	}
	return algodClient, nil
}

func (s Simulator) serverConfig() serverconfig.ServerConfig {
	if s.Config == nil {
		return serverconfig.DefaultServerConfig()
	}
	return s.Config()
}
