// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// SSH trust errors are re-exported at the engine transport boundary so
// guarded orchestration can classify tunnel failures without depending on the
// SSH implementation package directly.
var (
	ErrSSHHostKeyMismatch = sshtunnel.ErrHostKeyMismatch
	ErrSSHUnknownHostKey  = sshtunnel.ErrUnknownHostKey
	ErrSSHKnownHostsFile  = sshtunnel.ErrKnownHostsFile
)

// HostKeyApproval is the interactive trust callback accepted by explicit SSH
// setup operations. The alias keeps higher client layers on the connect
// boundary rather than the SSH implementation package.
type HostKeyApproval = sshtunnel.HostKeyApprovalHandler

// SentrySSHConfig describes a one-shot SSH connection used for sentry
// component signing. It does not mutate the primary signer connection.
type SentrySSHConfig struct {
	Host            string
	SSHPort         int
	SignerPort      int
	Token           string
	IdentityFile    string
	KnownHostsPath  string
	ProgressOut     io.Writer
	HostKeyApproval sshtunnel.HostKeyApprovalHandler
}

const sentrySSHHTTPAuthority = "sentry.aplane.invalid:80"

type sentrySSHDialer interface {
	DialSignerAPI(context.Context) (net.Conn, error)
}

// ConnectSentryWithSSH opens an authenticated SSH connection to a remote
// sentry and returns an HTTP client that opens direct SSH channels to its REST
// API, plus a cleanup callback.
func ConnectSentryWithSSH(ctx context.Context, cfg SentrySSHConfig) (*signerclient.Client, func(), error) {
	if cfg.Token == "" {
		return nil, nil, fmt.Errorf("no API token configured")
	}

	// The caller's context bounds connection setup, but a successful SSH link is
	// owned by the returned cleanup callback. Discovery callers intentionally
	// cancel their short per-endpoint probe context after /keys; binding the
	// retained connection to that context would make the subsequent component call
	// fail on an already-canceled connection.
	sshCtx, cancelSSH, detachSetup := newSentrySSHLifetime(ctx)
	sshConnection := sshtunnel.NewClient(cfg.Host, cfg.SSHPort, 0, cfg.SignerPort, cfg.IdentityFile, cfg.KnownHostsPath)
	if cfg.HostKeyApproval != nil {
		sshConnection.SetHostKeyApprovalHandler(cfg.HostKeyApproval)
	}
	sshConnection.SetAPIToken(cfg.Token)
	if err := sshConnection.ConnectWithKey(sshCtx); err != nil {
		_ = detachSetup()
		cancelSSH()
		return nil, nil, fmt.Errorf("SSH auth failed: %w", err)
	}
	if err := detachSetup(); err != nil {
		cancelSSH()
		_ = sshConnection.Close()
		return nil, nil, fmt.Errorf("SSH setup canceled: %w", err)
	}

	transport := newSentrySSHHTTPTransport(sshConnection)
	client := signerclient.NewSignerClientWithToken("http://"+sentrySSHHTTPAuthority, cfg.Token)
	client.Client = &http.Client{Transport: transport}
	client.ProgressOut = cfg.ProgressOut
	var closeOnce sync.Once
	return client, func() {
		closeOnce.Do(func() {
			transport.CloseIdleConnections()
			_ = sshConnection.Close()
			cancelSSH()
		})
	}, nil
}

func newSentrySSHHTTPTransport(dialer sentrySSHDialer) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = false
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" || addr != sentrySSHHTTPAuthority {
			return nil, fmt.Errorf("unexpected sentry HTTP dial target %s %s", network, addr)
		}
		return dialer.DialSignerAPI(ctx)
	}
	return transport
}

func newSentrySSHLifetime(setupCtx context.Context) (context.Context, context.CancelFunc, func() error) {
	lifetimeCtx, cancel := context.WithCancel(context.Background())
	stopSetupCancellation := context.AfterFunc(setupCtx, cancel)
	detach := func() error {
		if stopSetupCancellation() {
			if err := setupCtx.Err(); err != nil {
				cancel()
				return err
			}
			return nil
		}
		if err := setupCtx.Err(); err != nil {
			return err
		}
		return context.Canceled
	}
	return lifetimeCtx, cancel, detach
}
