// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"net"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

func newIPCServerWithActiveConn(conn net.Conn) *IPCServer {
	server := &IPCServer{
		manager: adminserver.NewSessionManager(),
	}
	session := adminserver.NewSession(adminproto.NewUnixAdminConn(conn, nil), adminserver.SessionDeps{})
	_ = server.manager.RegisterPending(session)
	server.manager.PromoteToActive(session)
	return server
}

func newBoundTestSession(server *IPCServer, conn net.Conn, ir *identity.Runtime) *adminserver.Session {
	session := adminserver.NewSession(adminproto.NewUnixAdminConn(conn, nil), server.signer.adminSessionDeps())
	remoteAddr := "test-ipc"
	if addr := conn.RemoteAddr(); addr != nil {
		remoteAddr = addr.String()
	}
	session.SetTransportInfo(adminserver.TransportIPC, remoteAddr)
	session.Bind(auth.NewDefaultIdentity("test"), ir)
	return session
}
