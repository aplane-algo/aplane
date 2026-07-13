// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"fmt"
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

	for _, rt := range server.registry.All() {
		if loadErr := rt.LoadAuthorizedKeys(); loadErr != nil {
			logWarnf("failed to load identity authorized keys for %s: %v", rt.ID(), loadErr)
		}
	}

	sshServer.SetIdentityHooks(sshtunnel.IdentityHooks{
		ComputeTokenMACs: func(identityID string, serverInput, clientInput []byte) ([]byte, []byte, uint64, bool) {
			rt := server.registry.Get(identityID)
			if rt == nil || rt.IsDecommissioned() {
				return nil, nil, 0, false
			}
			ta, ok := rt.Authenticator().(*auth.TokenAuthenticator)
			if !ok {
				return nil, nil, 0, false
			}
			return ta.ComputeHMACPair(serverInput, clientInput)
		},
		CheckKey: func(identityID string, key gossh.PublicKey) bool {
			rt := server.registry.Get(identityID)
			if rt == nil || rt.IsDecommissioned() {
				return false
			}
			return rt.HasAuthorizedKey(key)
		},
		EnrollKey: func(identityID string, key gossh.PublicKey) error {
			enrollIR := server.registry.Get(identityID)
			if enrollIR == nil {
				return fmt.Errorf("identity not found: %s", identityID)
			}
			if enrollIR.IsDecommissioned() {
				return fmt.Errorf("identity decommissioned: %s", identityID)
			}
			return enrollIR.EnrollAuthorizedKey(key)
		},
	})

	if auditLog != nil {
		sshServer.SetSessionCallback(func(remoteAddr, identityID string, connected bool) {
			if connected {
				auditLog.LogSessionConnected(identityID, remoteAddr, identityID)
			} else {
				auditLog.LogSessionDisconnected(identityID, remoteAddr, identityID)
			}
		})
	}

	sshServer.SetAdminChannelCallback(func(channel gossh.Channel, remoteAddr, identityID string) {
		if identityID == "" {
			logInfof("apadmin client connected via SSH from %s", remoteAddr)
		} else {
			logInfof("apadmin client connected via SSH from %s for identity %q", remoteAddr, identityID)
		}
		server.ipcServer.acceptAdminSession(adminproto.NewStreamAdminConn(channel, remoteAddr), "ssh", "ssh-passphrase", identityID)
	})
	sshServer.SetTokenProvisioningHooks(sshtunnel.TokenProvisioningHooks{
		ApproveContext: func(ctx context.Context, identityID, sshFingerprint, remoteAddr string) (bool, error) {
			return provisioning.ApproveContext(ctx, identityID, sshFingerprint, remoteAddr)
		},
		Issue: func(identityID string) (string, error) {
			return provisioning.Issue(identityID)
		},
		AuditProvisioned: func(identityID, sshFingerprint, remoteAddr string) {
			provisioning.AuditProvisioned(identityID, sshFingerprint, remoteAddr)
		},
		OperatorConnected: func(identityID string) bool {
			return server.hasClientForIdentity(identityID)
		},
		IdentityProvisioning: func(identityID string) bool {
			rt := server.registry.Get(identityID)
			return rt != nil && !rt.IsDecommissioned()
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
