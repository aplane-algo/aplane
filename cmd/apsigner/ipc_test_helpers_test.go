// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"net"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

func newIPCServerWithActiveConn(conn net.Conn) *IPCServer {
	server := &IPCServer{
		manager: adminproto.NewSessionManager(),
	}
	session := adminproto.NewSession(adminproto.NewUnixAdminConn(conn, nil, &server.writeMu), adminproto.SessionDeps{})
	_ = server.manager.RegisterPending(auth.CurrentProductIdentityID(), session)
	server.manager.PromoteToActive(auth.CurrentProductIdentityID(), session)
	return server
}

func newBoundTestSession(server *IPCServer, conn net.Conn, ir *identity.Runtime) *adminproto.Session {
	session := adminproto.NewSession(adminproto.NewUnixAdminConn(conn, nil, &server.writeMu), server.signer.adminSessionDeps())
	remoteAddr := "test-ipc"
	if addr := conn.RemoteAddr(); addr != nil {
		remoteAddr = addr.String()
	}
	session.SetTransportInfo(adminproto.TransportIPC, remoteAddr)
	session.Bind(auth.NewDefaultIdentity("test"), ir)
	return session
}
