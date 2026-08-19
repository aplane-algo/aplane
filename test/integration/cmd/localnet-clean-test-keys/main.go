// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// localnet-clean-test-keys deletes keys from the generated LocalNet integration
// signer fixture. It does not touch algod/KMD accounts or production signer
// data directories.
package main

import (
	"flag"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/signerclient"
)

const (
	localnetNetwork       = "localnet"
	integrationNetworkEnv = "APLANE_INTEGRATION_NETWORK"
	defaultTestEnv        = "/tmp/aplane-test-env"
	defaultSignerData     = defaultTestEnv + "/apsigner"
	defaultIdentity       = "default"
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
	flag.StringVar(&opts.identity, "identity", defaultIdentity, "identity whose token file should be used")
	flag.StringVar(&opts.baseURL, "base-url", "", "signer REST URL; defaults to http://localhost:<signer_port> from signer config")
	flag.StringVar(&opts.tokenFile, "token-file", "", "API token file; defaults to <signer-data>/identities/default/aplane.token")
	flag.Parse()

	resolved, err := resolveOptions(opts)
	if err != nil {
		return err
	}

	client := signerclient.NewSignerClientWithToken(resolved.baseURL, resolved.token)
	keys, err := client.GetKeys()
	if err != nil {
		return fmt.Errorf("list signer keys from %s: %w", resolved.baseURL, err)
	}
	if keys.Locked {
		return fmt.Errorf("signer at %s is locked; unlock it before deleting test keys", resolved.baseURL)
	}
	if len(keys.Keys) == 0 {
		fmt.Printf("No APlane signer test keys found at %s.\n", resolved.baseURL)
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
	identity   string
	baseURL    string
	tokenFile  string
}

type resolvedOptions struct {
	signerData string
	baseURL    string
	token      string
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

	baseURL := strings.TrimRight(strings.TrimSpace(opts.baseURL), "/")
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://localhost:%d", cfg.Endpoint.SignerPort)
	}

	tokenFile := strings.TrimSpace(opts.tokenFile)
	if tokenFile == "" {
		identity := strings.TrimSpace(opts.identity)
		if identity == "" {
			return resolvedOptions{}, fmt.Errorf("identity must not be empty")
		}
		tokenFile = filepath.Join(signerData, "identities", identity, "aplane.token")
	}
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return resolvedOptions{}, fmt.Errorf("read token file %s: %w", tokenFile, err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return resolvedOptions{}, fmt.Errorf("token file %s is empty", tokenFile)
	}

	return resolvedOptions{
		signerData: signerData,
		baseURL:    baseURL,
		token:      token,
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
