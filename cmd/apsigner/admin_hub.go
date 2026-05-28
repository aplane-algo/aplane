// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "github.com/aplane-algo/aplane/internal/adminproto"

// adminHub returns the process-root admin facade used by non-transport code.
// During the initial extraction this falls back to the existing IPC server.
func (fs *Signer) adminHub() adminproto.AdminHub {
	if fs == nil {
		return nil
	}
	if fs.hub != nil {
		return fs.hub
	}
	if fs.ipcServer != nil {
		return fs.ipcServer
	}
	return nil
}
