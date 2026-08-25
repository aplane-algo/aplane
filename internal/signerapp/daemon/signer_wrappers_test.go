// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"net"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

// Product-mode Signer/IPCServer wrappers kept only for test convenience.

// These Signer-level wrappers exist for test convenience and legacy
// call sites. They route through productRuntime() which is the
// only process-boundary use of the fixed product runtime in the runtime path.

func (fs *Signer) getState() SignerState {
	return fs.productRuntime().GetState()
}

func (fs *Signer) isUnlocked() bool {
	return fs.getState() == SignerStateUnlocked
}

func (fs *Signer) setUnlocked() {
	fs.productRuntime().SetUnlocked()
}

func (fs *Signer) lock() {
	fs.productRuntime().Lock()
}

// hasClient is a product-mode test helper.
func (fs *Signer) hasClient() bool {
	return fs.hasAdminClient()
}

func (fs *Signer) pendingSignCount() int {
	return fs.productRuntime().PendingSignCount()
}

func (fs *Signer) failAllPendingApprovals(reason string) {
	fs.productRuntime().FailAllPendingApprovals(reason)
}

func (fs *Signer) newApprovalServiceForRuntime(ir *productruntime.Runtime) *signersigning.ApprovalService {
	return fs.newApprovalServiceWithAudit(ir, fs.auditLog)
}

// offerDisplacement sends a client_exists message to the new connection and waits
// for a displace_confirm response. If confirmed, it displaces the old client.
// Returns the bufio.Reader (to avoid data loss from buffering) and true on success.
func (s *IPCServer) offerDisplacement(newConn net.Conn) bool {
	return s.offerDisplacementSession(s.activeSession(), adminproto.NewUnixAdminConn(newConn, nil))
}

// handleClient handles a single IPC client connection.
func (s *IPCServer) handleClient(conn net.Conn) {
	s.acceptAdminSession(adminproto.NewUnixAdminConn(conn, nil), "ipc", "ipc-passphrase")
}
