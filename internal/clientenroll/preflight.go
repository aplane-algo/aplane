// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientenroll

import (
	"crypto/ed25519"
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

// Options customize enrollment preflight messages for the calling surface.
type Options struct {
	Product              string
	MissingSSHHint       string
	MissingTokenHint     string
	MissingKnownHostHint string
}

// Prereqs describes an enrolled client configuration ready for signer-facing use.
type Prereqs struct {
	DataDir string
	Config  config.Config
	Token   string
}

// LoadEnrolledClient validates that the client is already enrolled for a
// non-interactive, signer-facing surface. It requires a default signer endpoint
// or legacy ssh config, a client token, and a trusted known_hosts entry.
func LoadEnrolledClient(dataDir string, opts Options) (*Prereqs, error) {
	if err := config.CheckNoLegacyClientEndpointConfig(dataDir); err != nil {
		return nil, err
	}
	cfg, err := config.LoadConfig(dataDir)
	if err != nil {
		return nil, fmt.Errorf("invalid client configuration for %s: %w", opts.Product, err)
	}
	registry := cfg.ClientEndpointsOrDefault(dataDir)
	_, endpoint, ok := registry.DefaultEndpoint()
	if !ok {
		return nil, fmt.Errorf("%s requires a default signer endpoint in %s/endpoints.yaml; %s", opts.Product, dataDir, opts.MissingSSHHint)
	}
	host, sshPort, err := config.ClientEndpointSSHHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("%s default signer endpoint is invalid: %w", opts.Product, err)
	}
	cfg.SSH = &config.SSHClientConfig{
		Host:           host,
		Port:           sshPort,
		IdentityFile:   endpoint.IdentityFile,
		KnownHostsPath: endpoint.KnownHostsPath,
	}

	tokenPath := endpoint.TokenFile
	if tokenPath == "" {
		tokenPath, _ = tokenfile.GetApshellTokenPathForDataDir(dataDir)
	}
	token, err := tokenfile.ReadToken(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load token from %s: %w", tokenPath, err)
	}
	if token == "" {
		return nil, fmt.Errorf("%s requires an enrolled client token at %s; %s", opts.Product, tokenPath, opts.MissingTokenHint)
	}

	if err := requireKnownHost(cfg, opts); err != nil {
		return nil, err
	}

	return &Prereqs{
		DataDir: dataDir,
		Config:  cfg,
		Token:   token,
	}, nil
}

func requireKnownHost(cfg config.Config, opts Options) error {
	knownHostsPath := cfg.SSH.KnownHostsPath
	callback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s requires the signer host to be trusted in %s; %s", opts.Product, knownHostsPath, opts.MissingKnownHostHint)
		}
		return fmt.Errorf("failed to load known_hosts %s: %w", knownHostsPath, err)
	}

	dummyKey, err := dummyHostPublicKey()
	if err != nil {
		return fmt.Errorf("failed to prepare known_hosts check: %w", err)
	}

	address := net.JoinHostPort(cfg.SSH.Host, strconv.Itoa(cfg.SSH.Port))
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: cfg.SSH.Port}
	err = callback(address, remote, dummyKey)
	if err == nil {
		return fmt.Errorf("%s known_hosts entry for %s matches an invalid placeholder key; remove it from %s and trust the real signer host key", opts.Product, address, knownHostsPath)
	}
	if keyErr, ok := err.(*knownhosts.KeyError); ok {
		if len(keyErr.Want) > 0 {
			return nil
		}
		return fmt.Errorf("%s requires the signer host %s to be trusted in %s; %s", opts.Product, address, knownHostsPath, opts.MissingKnownHostHint)
	}
	return fmt.Errorf("failed to validate known_hosts %s for %s: %w", knownHostsPath, address, err)
}

func dummyHostPublicKey() (ssh.PublicKey, error) {
	return ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
}
