// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// localnet-clean-test-keys deletes keys from the generated LocalNet integration
// signer fixture. It connects as the fixture's enrolled client, through the
// signer's SSH server, and does not touch algod/KMD accounts or production
// signer data directories.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerclient"
)

const (
	localnetNetwork       = "localnet"
	integrationNetworkEnv = "APLANE_INTEGRATION_NETWORK"
	defaultTestEnv        = "/tmp/aplane-test-env"
	defaultSignerData     = defaultTestEnv + "/apsigner"
	defaultClientData     = defaultTestEnv + "/apclient"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var opts options
	flag.BoolVar(&opts.yes, "yes", false, "delete keys; without -yes, only print a dry run")
	flag.StringVar(&opts.signerData, "signer-data", envDefault("APSIGNER_DATA", defaultSignerData), "generated integration signer data directory")
	flag.StringVar(&opts.clientData, "client-data", envDefault("APCLIENT_DATA", defaultClientData), "generated integration client data directory, whose default endpoint and enrolled key reach the signer")
	flag.Parse()

	resolved, err := resolveOptions(opts)
	if err != nil {
		return err
	}

	client, closeClient, err := connectFixtureClient(resolved)
	if err != nil {
		return err
	}
	defer closeClient()
	keys, err := client.GetKeys()
	if err != nil {
		return fmt.Errorf("list signer keys from %s: %w", resolved.endpointURL, err)
	}
	if keys.Locked {
		return fmt.Errorf("signer at %s is locked; unlock it before deleting test keys", resolved.endpointURL)
	}
	if len(keys.Keys) == 0 {
		fmt.Printf("No APlane signer test keys found at %s.\n", resolved.endpointURL)
		return nil
	}

	fmt.Printf("Found %d APlane signer test key(s) in %s:\n", len(keys.Keys), resolved.signerData)
	for _, key := range keys.Keys {
		fmt.Printf("  %s  %s\n", key.Address, key.KeyType)
	}
	if !opts.yes {
		fmt.Println("Dry run only. Re-run with -yes to delete these signer test keys.")
		return nil
	}

	var failed []error
	deleted := 0
	for _, key := range keys.Keys {
		resp, err := client.AdminDeleteKey(key.Address)
		if err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", key.Address, err))
			continue
		}
		if resp == nil || !resp.Success {
			failed = append(failed, fmt.Errorf("%s: signer returned unsuccessful delete response", key.Address))
			continue
		}
		deleted++
		fmt.Printf("Deleted %s\n", key.Address)
	}
	if len(failed) > 0 {
		for _, err := range failed {
			_, _ = fmt.Fprintf(os.Stderr, "delete failed: %v\n", err)
		}
		return fmt.Errorf("deleted %d key(s), %d deletion(s) failed", deleted, len(failed))
	}

	fmt.Printf("Deleted %d APlane signer test key(s).\n", deleted)
	return nil
}

type options struct {
	yes        bool
	signerData string
	clientData string
}

type resolvedOptions struct {
	signerData  string
	endpointURL string
	host        string
	sshPort     int
	endpoint    config.ClientEndpointConfig
}

// connectFixtureClient opens an SSH tunnel to the signer as the fixture's
// enrolled client and returns a REST client over it.
func connectFixtureClient(resolved resolvedOptions) (*signerclient.Client, func(), error) {
	localPort, err := connect.FindAvailableLocalPort()
	if err != nil {
		return nil, nil, err
	}
	state := connect.NewState()
	result, err := state.ConnectWithTunnel(
		resolved.endpointURL, resolved.host, resolved.sshPort, localPort,
		resolved.endpoint.IdentityFile, resolved.endpoint.KnownHostsPath,
		nil, nil, nil,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to signer %s as the fixture client: %w", resolved.endpointURL, err)
	}
	if result == nil || !result.Connected {
		_ = state.Disconnect(nil)
		return nil, nil, fmt.Errorf("signer %s did not establish a connection", resolved.endpointURL)
	}
	client := state.SignerClient
	if client == nil {
		_ = state.Disconnect(nil)
		return nil, nil, fmt.Errorf("signer %s connected without a REST client", resolved.endpointURL)
	}
	return client, func() { _ = state.Disconnect(nil) }, nil
}

func resolveOptions(opts options) (resolvedOptions, error) {
	if network := strings.TrimSpace(os.Getenv(integrationNetworkEnv)); network != localnetNetwork {
		return resolvedOptions{}, fmt.Errorf("refusing to clean keys unless %s=%s, got %q", integrationNetworkEnv, localnetNetwork, network)
	}

	signerData, err := filepath.Abs(strings.TrimSpace(opts.signerData))
	if err != nil {
		return resolvedOptions{}, fmt.Errorf("resolve signer data path: %w", err)
	}
	if signerData == "" || signerData == "." {
		return resolvedOptions{}, fmt.Errorf("signer data directory is empty")
	}
	if err := requirePathInside(signerData, defaultTestEnv); err != nil {
		return resolvedOptions{}, err
	}

	configPath := filepath.Join(signerData, "config.yaml")
	if _, err := os.Stat(configPath); err != nil {
		return resolvedOptions{}, fmt.Errorf("read signer fixture config %s: %w", configPath, err)
	}
	cfg, err := serverconfig.LoadServerConfig(signerData)
	if err != nil {
		return resolvedOptions{}, err
	}
	if !serverConfigLooksLocalnet(cfg) {
		return resolvedOptions{}, fmt.Errorf("refusing to clean keys because %s does not look like a localnet signer fixture", configPath)
	}

	clientData, err := filepath.Abs(strings.TrimSpace(opts.clientData))
	if err != nil {
		return resolvedOptions{}, fmt.Errorf("resolve client data path: %w", err)
	}
	if err := requirePathInside(clientData, defaultTestEnv); err != nil {
		return resolvedOptions{}, err
	}
	clientCfg, err := config.LoadConfig(clientData)
	if err != nil {
		return resolvedOptions{}, fmt.Errorf("load fixture client config: %w", err)
	}
	alias, endpoint, ok := clientCfg.ClientEndpointsOrDefault().DefaultEndpoint()
	if !ok {
		return resolvedOptions{}, fmt.Errorf("fixture client %s has no default signer endpoint", clientData)
	}
	host, sshPort, err := config.ClientEndpointSSHHostPort(endpoint)
	if err != nil {
		return resolvedOptions{}, fmt.Errorf("fixture client endpoint %q: %w", alias, err)
	}

	return resolvedOptions{
		signerData:  signerData,
		endpointURL: endpoint.URL,
		host:        host,
		sshPort:     sshPort,
		endpoint:    endpoint,
	}, nil
}

func requirePathInside(path, parent string) error {
	parentAbs, err := filepath.Abs(parent)
	if err != nil {
		return fmt.Errorf("resolve fixture root %s: %w", parent, err)
	}
	rel, err := filepath.Rel(parentAbs, path)
	if err != nil {
		return fmt.Errorf("compare %s with fixture root %s: %w", path, parentAbs, err)
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return fmt.Errorf("refusing signer data outside generated fixture root %s: %s", parentAbs, path)
	}
	return nil
}

func serverConfigLooksLocalnet(cfg serverconfig.ServerConfig) bool {
	if cfg.TEALCompileNetwork == localnetNetwork {
		return true
	}
	if cfg.Algod != nil {
		if _, ok := cfg.Algod[localnetNetwork]; ok {
			return true
		}
	}
	if cfg.Networks != nil {
		if _, ok := cfg.Networks[localnetNetwork]; ok {
			return true
		}
	}
	for _, network := range cfg.GenesisHashNetworks {
		if network == localnetNetwork {
			return true
		}
	}
	return false
}

func envDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}
