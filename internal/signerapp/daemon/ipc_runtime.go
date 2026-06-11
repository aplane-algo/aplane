// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

func startIPCServer(server *Signer, socketPath string) error {
	server.ipcServer = NewIPCServer(socketPath, server)
	server.hub = server.ipcServer
	if err := server.ipcServer.Start(); err != nil {
		return err
	}
	logInfof("admin interface ready on IPC socket %s", socketPath)
	return nil
}
