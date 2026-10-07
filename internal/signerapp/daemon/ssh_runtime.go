// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

type sshRuntime struct {
	server     *sshtunnel.Server
	stopper    sshRuntimeStopper
	ctx        context.Context
	cancel     context.CancelFunc
	listenAddr string
}

type sshRuntimeStopper interface {
	StopContext(context.Context) error
}

// sshSessionCallback audits each client session and announces an enrolled
// key's connection coming or going, since the Enrolled Clients list shows
// which keys are connected. Enrollment-request connections are audited but
// not announced: the request itself is, when it is queued.
func (fs *Signer) sshSessionCallback(auditLog *AuditLogger) sshtunnel.SessionCallback {
	return func(event sshtunnel.SessionEvent) {
		if auditLog != nil {
			if event.Connected {
				auditLog.LogSessionConnected(event.RemoteAddr, "ssh")
			} else {
				auditLog.LogSessionDisconnected(event.RemoteAddr, "ssh")
			}
		}
		if !event.EnrolledKey {
			return
		}
		reason := protocol.EnrollmentChangeDisconnected
		if event.Connected {
			reason = protocol.EnrollmentChangeConnected
		}
		fs.notifyEnrollmentChanged(reason, event.Fingerprint)
	}
}

func startSSHRuntime(server *Signer, listenAddress string, port int, hostKeyPath string, auditLog *AuditLogger) (*sshRuntime, error) {
	sshCtx, sshCancel := context.WithCancel(context.Background())
	enrollmentSvc := server.enrollmentService()

	listenAddress = strings.TrimSpace(listenAddress)
	if listenAddress == "" {
		listenAddress = apconfig.DefaultSSHListenAddress
	}
	listenAddr := net.JoinHostPort(listenAddress, strconv.Itoa(port))
	sshServer, err := sshtunnel.NewServer(listenAddr, hostKeyPath)
	if err != nil {
		sshCancel()
		return nil, err
	}

	productRuntime := server.productRuntime()
	// A registry the daemon cannot read completely refuses to serve rather
	// than serving with partial authority; the same goes for the queue of
	// requests waiting on the operator, which the daemon alone writes.
	if err := productRuntime.LoadAuthorizedKeys(); err != nil {
		sshCancel()
		return nil, fmt.Errorf("enrolled client registry: %w", err)
	}
	if err := productRuntime.LoadEnrollmentQueue(); err != nil {
		sshCancel()
		return nil, fmt.Errorf("enrollment queue: %w", err)
	}

	sshServer.SetProductHooks(sshtunnel.ProductHooks{
		CheckKey:  productRuntime.HasAuthorizedKey,
		EnrollKey: productRuntime.EnrollAuthorizedKey,
	})
	if server.apiListener != nil {
		sshServer.SetAPIHandoff(server.apiListener.Handoff)
	}

	sshServer.SetSessionCallback(server.sshSessionCallback(auditLog))

	sshServer.SetEnrollmentHooks(sshtunnel.EnrollmentHooks{Request: enrollmentSvc.Request})

	if err := sshServer.Start(sshCtx); err != nil {
		sshCancel()
		return nil, err
	}

	logInfof("SSH server started on %s (enrolled-key authentication)", listenAddr)
	logInfof("host key fingerprint: %s", sshServer.GetHostKeyFingerprint())

	return &sshRuntime{
		server:     sshServer,
		stopper:    sshServer,
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

func (fs *Signer) stopSSHRuntime(ctx context.Context) error {
	fs.sshRuntimeMu.Lock()
	rt := fs.sshRuntime
	fs.sshRuntime = nil
	fs.sshServer = nil
	fs.sshRuntimeMu.Unlock()

	// Stop waits for listener/connection shutdown and may run code paths that
	// consult the current SSH server. Keep it outside sshRuntimeMu so future
	// live-restart paths cannot deadlock through currentSSHServer.
	return stopSSHRuntimeInstance(ctx, rt)
}

func stopSSHRuntimeInstance(ctx context.Context, rt *sshRuntime) error {
	if rt == nil {
		return nil
	}
	if rt.cancel != nil {
		rt.cancel()
	}
	if rt.stopper != nil {
		return rt.stopper.StopContext(ctx)
	}
	// Preserve safe teardown for zero-value and older runtime holders that do
	// not have the stopper seam populated.
	if rt.server != nil {
		return rt.server.StopContext(ctx)
	}
	return nil
}
