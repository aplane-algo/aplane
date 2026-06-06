// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"crypto/ed25519"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/aplane-algo/aplane/internal/config"
	tui "github.com/aplane-algo/aplane/internal/signertui"
	"github.com/aplane-algo/aplane/internal/theme"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

type remoteAdminConfig struct {
	dataDir   string
	config    config.Config
	token     string
	connector tui.SSHAdminConnector
}

func formatRemoteConnectError(err error, interactive bool) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "unknown SSH host ") {
		return fmt.Errorf("%w\nhint: remote apadmin requires a trusted signer host; run standalone 'apshell request-token' or 'apshell connect' first to save the host key to known_hosts", err)
	}
	return err
}

func loadRemoteAdminConfig(clientDataDirFlag string, _ bool) (*remoteAdminConfig, error) {
	clientDataDir := config.GetClientDataDir(clientDataDirFlag)
	if clientDataDir == "" {
		return nil, fmt.Errorf("client data directory not specified: pass --client-data <path> or set APCLIENT_DATA")
	}

	cfg, err := config.LoadConfig(clientDataDir)
	if err != nil {
		return nil, fmt.Errorf("invalid remote client configuration: %w", err)
	}
	registry := cfg.ClientEndpointsOrDefault(clientDataDir)
	_, endpoint, ok := registry.DefaultEndpoint()
	if !ok {
		return nil, fmt.Errorf("remote mode requires a default signer endpoint in %s/endpoints.yaml", clientDataDir)
	}
	host, sshPort, err := config.ClientEndpointSSHHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("remote mode default signer endpoint is invalid: %w", err)
	}
	cfg.SSH = &config.SSHClientConfig{
		Host:           host,
		Port:           sshPort,
		IdentityFile:   endpoint.IdentityFile,
		KnownHostsPath: endpoint.KnownHostsPath,
	}
	theme.Init(cfg.Theme)

	tokenPath := endpoint.TokenFile
	if tokenPath == "" {
		tokenPath, _ = tokenfile.GetApshellTokenPathForDataDir(clientDataDir)
	}
	token, err := tokenfile.ReadToken(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load token from %s: %w", tokenPath, err)
	}
	if token == "" {
		return nil, fmt.Errorf("no token configured for remote mode; copy aplane.token to %s or enroll via apshell", tokenPath)
	}
	if err := requireRemoteKnownHost(cfg); err != nil {
		return nil, err
	}

	connector := tui.SSHAdminConnector{
		Host:           cfg.SSH.Host,
		Port:           cfg.SSH.Port,
		Token:          token,
		IdentityFile:   cfg.SSH.IdentityFile,
		KnownHostsPath: cfg.SSH.KnownHostsPath,
	}

	return &remoteAdminConfig{
		dataDir:   clientDataDir,
		config:    cfg,
		token:     token,
		connector: connector,
	}, nil
}

func requireRemoteKnownHost(cfg config.Config) error {
	knownHostsPath := cfg.SSH.KnownHostsPath
	callback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("remote apadmin requires the signer host to be trusted in %s; run standalone apshell request-token or connect first", knownHostsPath)
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
		return fmt.Errorf("remote apadmin known_hosts entry for %s matches an invalid placeholder key; remove it from %s and trust the real signer host key", address, knownHostsPath)
	}
	if keyErr, ok := err.(*knownhosts.KeyError); ok {
		if len(keyErr.Want) > 0 {
			return nil
		}
		return fmt.Errorf("remote apadmin requires the signer host %s to be trusted in %s; run standalone apshell request-token or connect first", address, knownHostsPath)
	}
	return fmt.Errorf("failed to validate known_hosts %s for %s: %w", knownHostsPath, address, err)
}

func dummyHostPublicKey() (ssh.PublicKey, error) {
	return ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
}
