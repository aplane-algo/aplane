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
	server  *sshtunnel.Server
	stopper sshRuntimeStopper
	cancel  context.CancelFunc
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
				auditLog.LogSSHSessionConnected(event.RemoteAddr, event.Fingerprint, event.EnrolledKey)
			} else {
				auditLog.LogSSHSessionDisconnected(event.RemoteAddr, event.Fingerprint, event.EnrolledKey)
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
		server:  sshServer,
		stopper: sshServer,
		cancel:  sshCancel,
	}, nil
}

func (fs *Signer) setSSHRuntime(rt *sshRuntime) {
	fs.sshRuntimeMu.Lock()
	defer fs.sshRuntimeMu.Unlock()
	fs.sshRuntime = rt
}

func (fs *Signer) currentSSHServer() *sshtunnel.Server {
	fs.sshRuntimeMu.RLock()
	defer fs.sshRuntimeMu.RUnlock()
	if fs.sshRuntime == nil {
		return nil
	}
	return fs.sshRuntime.server
}

func (fs *Signer) stopSSHRuntime(ctx context.Context) error {
	fs.sshRuntimeMu.Lock()
	rt := fs.sshRuntime
	fs.sshRuntime = nil
	fs.sshRuntimeMu.Unlock()

	// Stop waits for listener/connection shutdown and may run code paths that
	// consult the current SSH server, so it runs outside sshRuntimeMu, where
	// it cannot deadlock through currentSSHServer.
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
	return nil
}
