// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apboundedadminapp

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

type engineRuntime struct {
	engine *engine.Engine
}

func openRuntime(clientData, networkOverride string, stderr io.Writer, connectSigner bool) (*engineRuntime, error) {
	dataDir := config.GetClientDataDir(clientData)
	if dataDir == "" {
		return nil, fmt.Errorf("client data directory not specified: pass --client-data <path> or set APCLIENT_DATA")
	}
	configPath := config.GetConfigPath(dataDir)
	if _, err := os.Stat(configPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config file not found: %s", configPath)
		}
		return nil, fmt.Errorf("stat client config: %w", err)
	}
	if connectSigner {
		if err := config.CheckSupportedClientEndpointConfig(dataDir); err != nil {
			return nil, err
		}
	}
	cache.InitLogger()
	cfg, err := config.LoadConfig(dataDir)
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	network := networkOverride
	if network == "" {
		network = cfg.Network
	}
	if err := config.ValidateNetworkID(network); err != nil {
		return nil, fmt.Errorf("invalid network: %w", err)
	}
	if !cfg.IsNetworkAllowed(network) {
		return nil, fmt.Errorf("network %q is not allowed by configuration", network)
	}
	algodConfig, err := cfg.GetAlgodConfig(network)
	if err != nil {
		return nil, fmt.Errorf("network %q is not configured in config.yaml", network)
	}
	if algodConfig.Server == "" {
		return nil, fmt.Errorf("algod.%s.server is required in config.yaml", network)
	}

	eng, err := engine.NewInitializedEngine(network, &cfg, dataDir)
	if err != nil {
		return nil, err
	}
	if eng.AlgodClient == nil {
		return nil, fmt.Errorf("create algod client for network %q", network)
	}
	if !connectSigner {
		return &engineRuntime{engine: eng}, nil
	}

	registry := cfg.ClientEndpointsOrDefault()
	alias, endpoint, ok := registry.DefaultEndpoint()
	if !ok {
		return nil, fmt.Errorf("no default signer endpoint is configured in %s", config.ClientEndpointsFile)
	}
	host, sshPort, err := config.ClientEndpointSSHHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("default signer endpoint %q: %w", alias, err)
	}
	token, err := tokenfile.ReadToken(endpoint.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("read signer API token: %w", err)
	}
	if token == "" {
		return nil, fmt.Errorf("no signer API token found at %s", endpoint.TokenFile)
	}
	localPort := endpoint.LocalPort
	if localPort == 0 {
		localPort, err = connect.FindAvailableLocalPort()
		if err != nil {
			return nil, err
		}
	}
	signerPort := endpoint.SignerPort
	if signerPort == 0 {
		signerPort = config.DefaultRESTPort
	}

	eng.Connection.SetSignerProgressWriter(stderr)
	result, err := eng.ConnectWithTunnel(alias, host, sshPort, localPort, signerPort, token, endpoint.IdentityFile, endpoint.KnownHostsPath, nil, nil)
	if err != nil {
		_ = eng.Disconnect()
		return nil, fmt.Errorf("connect to signer endpoint %q: %w", alias, err)
	}
	if result == nil || !result.Connected {
		_ = eng.Disconnect()
		return nil, fmt.Errorf("signer endpoint %q did not establish a connection", alias)
	}
	if result.Locked {
		_ = eng.Disconnect()
		return nil, fmt.Errorf("signer endpoint %q is locked", alias)
	}
	return &engineRuntime{engine: eng}, nil
}

func (r *engineRuntime) ResolveSingle(raw string) (string, error) {
	return r.engine.NewAddressResolver().ResolveSingle(raw)
}

func (r *engineRuntime) RefreshAuthAddressWithContext(ctx context.Context, address string) (string, error) {
	return r.engine.RefreshAuthAddressWithContext(ctx, address)
}

func (r *engineRuntime) PrepareRekey(ctx context.Context, params engine.RekeyParams) (*engine.TransactionPrepResult, *engine.RekeyCheckResult, error) {
	return r.engine.PrepareRekey(ctx, params)
}

func (r *engineRuntime) PrepareExternalBoundedAdmin(ctx context.Context, prep *engine.TransactionPrepResult) (*engine.BoundedAdminPreparation, error) {
	return r.engine.PrepareExternalBoundedAdmin(ctx, prep)
}

func (r *engineRuntime) SubmitCompletedBoundedAdmin(ctx context.Context, prep *engine.BoundedAdminPreparation, signed [][]byte, txns []types.Transaction, wait bool) (*engine.SubmitResult, error) {
	return r.engine.SubmitCompletedBoundedAdmin(ctx, prep, signed, txns, wait)
}

func (r *engineRuntime) Close() error {
	return r.engine.Disconnect()
}
