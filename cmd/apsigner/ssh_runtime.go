// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

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
	"github.com/aplane-algo/aplane/internal/tokenfile"

	gossh "golang.org/x/crypto/ssh"
)

type sshRuntime struct {
	server     *sshtunnel.Server
	ctx        context.Context
	cancel     context.CancelFunc
	listenAddr string
}

func startSSHRuntime(server *Signer, listenAddress string, port int, hostKeyPath, authorizedKeysPath, tokenRoot, identityID string, auditLog *AuditLogger) (*sshRuntime, error) {
	sshCtx, sshCancel := context.WithCancel(context.Background())
	provisioning := server.sshProvisioningService()

	listenAddress = strings.TrimSpace(listenAddress)
	if listenAddress == "" {
		listenAddress = apconfig.DefaultSSHListenAddress
	}
	listenAddr := net.JoinHostPort(listenAddress, strconv.Itoa(port))
	cfg := server.ConfigSnapshot()
	targetAddr := httpBindAddr(cfg.SignerPort)
	productToken, err := tokenfile.LoadAPlaneToken(tokenRoot, identityID)
	if err != nil {
		sshCancel()
		return nil, fmt.Errorf("failed to load product identity API token: %w", err)
	}

	sshServer, err := sshtunnel.NewServer(listenAddr, targetAddr, hostKeyPath, authorizedKeysPath, productToken)
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
		ValidateToken: func(token string) (string, uint64, bool) {
			var matchedID string
			var matchedGeneration uint64
			matchCount := 0
			for _, rt := range server.registry.All() {
				if rt == nil || rt.IsDecommissioned() {
					continue
				}
				a := rt.Authenticator()
				if ta, ok := a.(*auth.TokenAuthenticator); ok {
					generation, valid := ta.ValidateTokenGeneration(token)
					if !valid {
						continue
					}
					matchCount++
					if matchCount == 1 {
						matchedID = rt.ID()
						matchedGeneration = generation
					}
				}
			}
			if matchCount != 1 {
				return "", 0, false
			}
			return matchedID, matchedGeneration, true
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
		server.ipcServer.acceptAdminSession(adminproto.NewStreamAdminConn(channel, remoteAddr, &server.ipcServer.writeMu), "ssh", "ssh-passphrase", identityID)
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
	defer fs.sshRuntimeMu.Unlock()
	rt := fs.sshRuntime
	fs.sshRuntime = nil
	fs.sshServer = nil
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

// RestartSSHListener restarts the SSH listener with a new bind address. The
// old listener is restored if the new bind fails and restoration is possible.
func (fs *Signer) RestartSSHListener(listenAddress string) error {
	listenAddress = strings.TrimSpace(listenAddress)
	if err := apconfig.ValidateSSHListenAddress(listenAddress); err != nil {
		return err
	}

	fs.sshRuntimeMu.Lock()
	defer fs.sshRuntimeMu.Unlock()

	oldRuntime := fs.sshRuntime
	oldCfg := fs.ConfigSnapshot()
	if oldRuntime != nil && oldCfg.SSH.ListenAddress == listenAddress {
		return nil
	}

	if err := stopSSHRuntimeInstance(oldRuntime); err != nil {
		return fmt.Errorf("failed to stop current SSH listener: %w", err)
	}
	fs.sshRuntime = nil
	fs.sshServer = nil

	newRuntime, err := fs.startSSHRuntimeForListenAddress(listenAddress)
	if err != nil {
		if oldRuntime != nil {
			restoreRuntime, restoreErr := fs.startSSHRuntimeForListenAddress(oldCfg.SSH.ListenAddress)
			if restoreErr == nil {
				fs.sshRuntime = restoreRuntime
				fs.sshServer = restoreRuntime.server
			} else {
				return fmt.Errorf("failed to start SSH listener on %s: %w; failed to restore previous listener on %s: %v", listenAddress, err, oldCfg.SSH.ListenAddress, restoreErr)
			}
		}
		return fmt.Errorf("failed to start SSH listener on %s: %w", listenAddress, err)
	}

	fs.sshRuntime = newRuntime
	fs.sshServer = newRuntime.server
	return nil
}

func (fs *Signer) startSSHRuntimeForListenAddress(listenAddress string) (*sshRuntime, error) {
	cfg := fs.ConfigSnapshot()
	cfg.SSH.ListenAddress = listenAddress
	return startSSHRuntime(
		fs,
		cfg.SSH.ListenAddress,
		cfg.SSH.Port,
		cfg.SSH.HostKeyPath,
		cfg.SSH.AuthorizedKeysPath,
		fs.keyPaths.Root(),
		auth.CurrentProductIdentityID(),
		fs.auditLog,
	)
}
