// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// SentryTunnelConfig describes a one-shot SSH tunnel used for sentry
// component signing. It does not mutate the primary signer connection.
type SentryTunnelConfig struct {
	Host           string
	SSHPort        int
	LocalPort      int
	SignerPort     int
	Token          string
	IdentityFile   string
	KnownHostsPath string
	ProgressOut    io.Writer
}

// FindAvailableLocalPort returns an unused loopback TCP port for a transient
// sentry tunnel.
func FindAvailableLocalPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("failed to reserve local port: %w", err)
	}
	defer func() { _ = listener.Close() }()
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || addr.Port <= 0 {
		return 0, fmt.Errorf("failed to determine reserved local port")
	}
	return addr.Port, nil
}

// ConnectSentryWithTunnel opens a transient tunnel to a remote sentry
// signer and returns an authenticated HTTP client plus a cleanup callback.
func ConnectSentryWithTunnel(ctx context.Context, cfg SentryTunnelConfig) (*signerclient.Client, func(), error) {
	if cfg.Token == "" {
		return nil, nil, fmt.Errorf("no API token configured")
	}
	if cfg.LocalPort == 0 {
		port, err := FindAvailableLocalPort()
		if err != nil {
			return nil, nil, err
		}
		cfg.LocalPort = port
	}

	tunnel := sshtunnel.NewClient(cfg.Host, cfg.SSHPort, cfg.LocalPort, cfg.SignerPort, cfg.IdentityFile, cfg.KnownHostsPath)
	tunnel.SetAPIToken(cfg.Token)
	if err := tunnel.ConnectWithKey(ctx); err != nil {
		return nil, nil, fmt.Errorf("SSH auth failed: %w", err)
	}
	if err := tunnel.StartPortForwarding(ctx); err != nil {
		_ = tunnel.Close()
		return nil, nil, fmt.Errorf("failed to start port forwarding: %w", err)
	}

	client := signerclient.NewSignerClientWithToken(fmt.Sprintf("http://localhost:%d", cfg.LocalPort), cfg.Token)
	client.ProgressOut = cfg.ProgressOut
	return client, func() { _ = tunnel.Close() }, nil
}
