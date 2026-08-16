// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/sshtunnel"

	gossh "golang.org/x/crypto/ssh"
)

type sshRuntime struct {
	server     *sshtunnel.Server
	ctx        context.Context
	cancel     context.CancelFunc
	listenAddr string
}

func startSSHRuntime(server *Signer, listenAddress string, port int, hostKeyPath, authorizedKeysPath string, auditLog *AuditLogger) (*sshRuntime, error) {
	sshCtx, sshCancel := context.WithCancel(context.Background())
	provisioning := server.sshProvisioningService()

	listenAddress = strings.TrimSpace(listenAddress)
	if listenAddress == "" {
		listenAddress = apconfig.DefaultSSHListenAddress
	}
	listenAddr := net.JoinHostPort(listenAddress, strconv.Itoa(port))
	cfg := server.ConfigSnapshot()
	targetAddr := httpBindAddr(cfg.Endpoint.SignerPort)
	sshServer, err := sshtunnel.NewServer(listenAddr, targetAddr, hostKeyPath, authorizedKeysPath, "")
	if err != nil {
		sshCancel()
		return nil, err
	}

	productRuntime := server.productIdentityRuntime()
	if loadErr := productRuntime.LoadAuthorizedKeys(); loadErr != nil {
		logWarnf("failed to load product authorized keys: %v", loadErr)
	}

	sshServer.SetProductHooks(sshtunnel.ProductHooks{
		ComputeTokenMACs: func(serverInput, clientInput []byte) ([]byte, []byte, uint64, bool) {
			ta, ok := productRuntime.Authenticator().(*auth.TokenAuthenticator)
			if !ok {
				return nil, nil, 0, false
			}
			return ta.ComputeHMACPair(serverInput, clientInput)
		},
		CheckKey: func(key gossh.PublicKey) bool {
			return productRuntime.HasAuthorizedKey(key)
		},
		EnrollKey: func(key gossh.PublicKey) error {
			return productRuntime.EnrollAuthorizedKey(key)
		},
	})

	if auditLog != nil {
		sshServer.SetSessionCallback(func(remoteAddr string, connected bool) {
			if connected {
				auditLog.LogSessionConnected(auth.CurrentProductIdentityID(), remoteAddr, auth.CurrentProductIdentityID())
			} else {
				auditLog.LogSessionDisconnected(auth.CurrentProductIdentityID(), remoteAddr, auth.CurrentProductIdentityID())
			}
		})
	}

	sshServer.SetAdminChannelCallback(func(channel gossh.Channel, remoteAddr string) {
		logInfof("apadmin client connected via SSH from %s", remoteAddr)
		server.ipcServer.acceptAdminSession(adminproto.NewStreamAdminConn(channel, remoteAddr), "ssh", "ssh-passphrase")
	})
	sshServer.SetTokenProvisioningHooks(sshtunnel.TokenProvisioningHooks{
		ApproveContext: func(ctx context.Context, sshFingerprint, remoteAddr string) (bool, error) {
			return provisioning.ApproveContext(ctx, auth.CurrentProductIdentityID(), sshFingerprint, remoteAddr)
		},
		Issue: func() (string, error) {
			return provisioning.Issue(auth.CurrentProductIdentityID())
		},
		AuditProvisioned: func(sshFingerprint, remoteAddr string) {
			provisioning.AuditProvisioned(auth.CurrentProductIdentityID(), sshFingerprint, remoteAddr)
		},
		OperatorConnected: func() bool {
			return server.hasClientForIdentity(auth.CurrentProductIdentityID())
		},
	})

	if err := sshServer.Start(sshCtx); err != nil {
		sshCancel()
		return nil, err
	}

	logInfof("SSH server started on %s (public key authentication)", listenAddr)
	logInfof("host key fingerprint: %s", sshServer.GetHostKeyFingerprint())

	return &sshRuntime{
		server:     sshServer,
		ctx:        sshCtx,
		cancel:     sshCancel,
		listenAddr: listenAddr,
	}, nil
}

func (fs *Signer) setSSHRuntime(rt *sshRuntime) {
	fs.sshRuntimeMu.Lock()
	defer fs.sshRuntimeMu.Unlock()
	fs.sshRuntime = rt
	if rt == nil {
		fs.sshServer = nil
		return
	}
	fs.sshServer = rt.server
}

func (fs *Signer) currentSSHServer() *sshtunnel.Server {
	fs.sshRuntimeMu.RLock()
	defer fs.sshRuntimeMu.RUnlock()
	return fs.sshServer
}

func (fs *Signer) stopSSHRuntime() error {
	fs.sshRuntimeMu.Lock()
	rt := fs.sshRuntime
	fs.sshRuntime = nil
	fs.sshServer = nil
	fs.sshRuntimeMu.Unlock()

	// Stop waits for listener/connection shutdown and may run code paths that
	// consult the current SSH server. Keep it outside sshRuntimeMu so future
	// live-restart paths cannot deadlock through currentSSHServer.
	return stopSSHRuntimeInstance(rt)
}

func stopSSHRuntimeInstance(rt *sshRuntime) error {
	if rt == nil {
		return nil
	}
	if rt.cancel != nil {
		rt.cancel()
	}
	if rt.server != nil {
		return rt.server.Stop()
	}
	return nil
}
