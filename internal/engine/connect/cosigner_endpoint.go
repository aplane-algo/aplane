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
	"time"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// SSH trust errors are re-exported at the engine transport boundary so
// cosigned orchestration can classify tunnel failures without depending on the
// SSH implementation package directly.
var (
	ErrSSHHostKeyMismatch = sshtunnel.ErrHostKeyMismatch
	ErrSSHUnknownHostKey  = sshtunnel.ErrUnknownHostKey
	ErrSSHKnownHostsFile  = sshtunnel.ErrKnownHostsFile
	ErrSSHKeyNotEnrolled  = sshtunnel.ErrKeyNotEnrolled
)

// HostKeyApproval is the interactive trust callback accepted by explicit SSH
// setup operations. The alias keeps higher client layers on the connect
// boundary rather than the SSH implementation package.
type HostKeyApproval = sshtunnel.HostKeyApprovalHandler

// IdentityCreatedHandler is told when connecting generates a new SSH identity key.
// The alias keeps higher client layers on the connect boundary, as above.
type IdentityCreatedHandler = func(sshtunnel.IdentityCreated)

// CosignerSSHConfig describes a one-shot SSH connection used for cosigner
// component signing. It does not mutate the primary signer connection.
type CosignerSSHConfig struct {
	Host            string
	SSHPort         int
	IdentityFile    string
	KnownHostsPath  string
	ProgressOut     io.Writer
	HostKeyApproval sshtunnel.HostKeyApprovalHandler
	IdentityCreated IdentityCreatedHandler
}

const cosignerSSHHTTPAuthority = "cosigner.aplane.invalid:80"

// sshAPIDialer opens a channel to a node's REST API over an SSH connection.
type sshAPIDialer interface {
	DialSignerAPI(context.Context) (net.Conn, error)
}

// ConnectCosignerWithSSH opens an authenticated SSH connection to a remote
// cosigner and returns an HTTP client that opens direct SSH channels to its REST
// API, plus a cleanup callback.
func ConnectCosignerWithSSH(ctx context.Context, cfg CosignerSSHConfig) (*signerclient.Client, func(), error) {
	// The caller's context bounds connection setup, but a successful SSH link is
	// owned by the returned cleanup callback. Discovery callers intentionally
	// cancel their short per-endpoint probe context after /keys; binding the
	// retained connection to that context would make the subsequent component call
	// fail on an already-canceled connection.
	sshCtx, cancelSSH, detachSetup := newSSHLifetime(ctx)
	sshConnection := sshtunnel.NewClient(cfg.Host, cfg.SSHPort, cfg.IdentityFile, cfg.KnownHostsPath)
	if cfg.HostKeyApproval != nil {
		sshConnection.SetHostKeyApprovalHandler(cfg.HostKeyApproval)
	}
	sshConnection.SetIdentityCreatedCallback(cfg.IdentityCreated)
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

	transport := newSSHHTTPTransport(sshConnection, cosignerSSHHTTPAuthority)
	client := signerclient.NewSignerClient("http://" + cosignerSSHHTTPAuthority)
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

// sshHTTPIdleTimeout closes an idle connection before the node's HTTP server
// does (its IdleTimeout is 120 seconds), as http.DefaultTransport's 90 seconds
// did. A request sent on a connection the server is closing fails, and a POST
// is not retried.
const sshHTTPIdleTimeout = 90 * time.Second

// newSSHHTTPTransport carries every HTTP connection to authority over an SSH
// channel to the node's REST API, and refuses to dial anything else.
func newSSHHTTPTransport(dialer sshAPIDialer, authority string) *http.Transport {
	return &http.Transport{
		ForceAttemptHTTP2: false,
		IdleConnTimeout:   sshHTTPIdleTimeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp" || addr != authority {
				return nil, fmt.Errorf("unexpected node HTTP dial target %s %s", network, addr)
			}
			return dialer.DialSignerAPI(ctx)
		},
	}
}

// newSSHLifetime returns the lifetime of an SSH connection set up under
// setupCtx: it ends with setupCtx until detach is called, and after that
// only with cancel. detach reports setupCtx's error if it ended first.
func newSSHLifetime(setupCtx context.Context) (context.Context, context.CancelFunc, func() error) {
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
