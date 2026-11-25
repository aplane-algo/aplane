// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/ipcbind"
)

// IPCServer handles Unix socket connections for local IPC.
type IPCServer struct {
	listener net.Listener
	signer   *Signer
	path     string
	manager  *adminserver.SessionManager

	preAuthTimeout time.Duration // 0 means preAuthLoginTimeout; settable in tests

	// stopped is closed by Stop, so acceptLoop ends a backoff wait at once.
	// A server built without NewIPCServer has none and waits it out.
	stopped  chan struct{}
	stopOnce sync.Once
}

const existingIPCProbeTimeout = 300 * time.Millisecond

// NewIPCServer creates a new IPC server.
func NewIPCServer(path string, signer *Signer) *IPCServer {
	return &IPCServer{
		path:    path,
		signer:  signer,
		manager: adminserver.NewSessionManager(),
		stopped: make(chan struct{}),
	}
}

// Start begins listening on the Unix socket.
func (s *IPCServer) Start() error {
	resolvedPath, err := ipcbind.ResolveBindPath(s.path)
	if err != nil {
		return err
	}
	s.path = resolvedPath

	// ResolveBindPath has already proven that the canonical parent and any
	// configured alias chain are current-UID/root controlled and not writable
	// by group or other users. removeStaleIPCSocket relies on that invariant for
	// the final pathname operation after its stable-inode recheck.
	if err := removeStaleIPCSocket(s.path); err != nil {
		return err
	}

	listener, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("failed to listen on IPC socket: %w", err)
	}

	// Set socket permissions (owner + group can access, for apadmin users in the service group)
	if err := os.Chmod(s.path, 0660); err != nil {
		_ = listener.Close() // Best-effort cleanup
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	s.listener = listener
	go s.acceptLoop()
	return nil
}

// removeStaleIPCSocket refuses to unlink a reachable listener. A closed Unix
// listener leaves a socket inode that returns ECONNREFUSED; only that stable,
// rechecked inode is eligible for removal.
func removeStaleIPCSocket(path string) error {
	before, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing IPC socket: %w", err)
	}

	conn, dialErr := net.DialTimeout("unix", path, existingIPCProbeTimeout)
	if dialErr == nil {
		_ = conn.Close()
		return fmt.Errorf("refusing to replace live IPC socket: %s", path)
	}
	if errors.Is(dialErr, syscall.ENOENT) {
		return nil
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		return fmt.Errorf("cannot prove existing IPC socket is stale: %w", dialErr)
	}

	after, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reinspect stale IPC socket: %w", err)
	}
	if !os.SameFile(before, after) {
		return fmt.Errorf("refusing to remove IPC socket that changed during stale check: %s", path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove stale IPC socket: %w", err)
	}
	return nil
}

// Stop closes the IPC server.
func (s *IPCServer) Stop() {
	s.stopOnce.Do(func() {
		if s.stopped != nil {
			close(s.stopped)
		}
	})
	if s.listener != nil {
		_ = s.listener.Close() // Best-effort cleanup
	}
	if active := s.activeSession(); active != nil {
		_ = active.Close()
	}
	// Clean up socket file
	_ = os.Remove(s.path) // Best-effort cleanup
}

// The wait before the next Accept after one fails doubles from the initial
// value up to the maximum, and resets once an Accept succeeds.
const (
	initialIPCAcceptBackoff = 25 * time.Millisecond
	maxIPCAcceptBackoff     = time.Second
)

// acceptLoop accepts incoming IPC connections until Stop closes the listener.
// Any other Accept error (EMFILE or ENFILE when the process runs out of
// descriptors) is retried after a capped backoff: ending the loop would
// leave the daemon running with no way for apadmin to connect, unlock or
// approve until it restarts.
func (s *IPCServer) acceptLoop() {
	var backoff time.Duration
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if backoff == 0 {
				logWarnf("IPC accept failed, retrying: %v", err)
			}
			backoff = nextIPCAcceptBackoff(backoff)
			select {
			case <-s.stopped:
				return
			case <-time.After(backoff):
			}
			continue
		}
		if backoff != 0 {
			logInfof("IPC accept recovered")
			backoff = 0
		}

		logInfof("apadmin client connected via IPC")
		go s.acceptAdminSession(adminproto.NewUnixAdminConn(conn))
	}
}

func nextIPCAcceptBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return initialIPCAcceptBackoff
	}
	return min(current*2, maxIPCAcceptBackoff)
}

// displacementTimeout is the maximum time to wait for a displacement confirmation.
const displacementTimeout = 30 * time.Second

// preAuthLoginTimeout bounds how long one connection may hold the single
// pre-auth slot. It runs from accept, through any displacement prompt, to a
// verified passphrase; wrong passphrases do not extend it. Without it, an
// apadmin left at its login screen blocks every other apadmin indefinitely.
const preAuthLoginTimeout = 2 * time.Minute

// readDeadlineConn is implemented by admin connections whose reads can be
// bounded.
type readDeadlineConn interface {
	SetReadDeadline(time.Time) error
}

func (s *IPCServer) loginTimeout() time.Duration {
	if s.preAuthTimeout > 0 {
		return s.preAuthTimeout
	}
	return preAuthLoginTimeout
}

func setPreAuthReadDeadline(conn adminproto.AdminConn, deadline time.Time) {
	if d, ok := conn.(readDeadlineConn); ok {
		_ = d.SetReadDeadline(deadline)
	}
}

// offerDisplacementSession asks newConn whether to displace the active
// session; callers offer only while one is active.
func (s *IPCServer) offerDisplacementSession(newConn adminproto.AdminConn) bool {
	confirmed := adminserver.OfferDisplacement(newConn, displacementTimeout)
	if confirmed {
		logWarnf("existing apadmin client accepted displacement by new connection")
	}
	return confirmed
}

func (s *IPCServer) acceptAdminSession(adminConn adminproto.AdminConn) {
	setPreAuthReadDeadline(adminConn, time.Now().Add(s.loginTimeout()))
	session := adminserver.NewSession(adminConn, s.signer.adminSessionDeps(), adminserver.OriginLocal)

	var active *adminserver.Session
	var displacementConfirmedFor *adminserver.Session
	ok := s.sessionManager().RegisterPreAuthPending(session)
	active = s.activeSession()
	if !ok {
		errMsg := protocol.ErrorMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeError},
			Error:       "another apadmin client is currently authenticating",
		}
		_ = adminserver.WriteJSONMessage(adminConn, errMsg)
		_ = session.Close()
		return
	}
	if active != nil {
		if !s.offerDisplacementSession(adminConn) {
			s.clearPendingSession(session)
			_ = session.Close()
			return
		}
		displacementConfirmedFor = active
	}
	s.handleRegisteredClient(session, displacementConfirmedFor)
}

func (s *IPCServer) handleRegisteredClient(session *adminserver.Session, displacementConfirmedFor *adminserver.Session) {
	// If auth unlocks an identity for this session, either the session becomes
	// the active owner or cleanup must leave the identity locked (when
	// lock_on_disconnect is set) with no pending approvals stranded.
	cleanupRuntime := false
	adminConn := session.Conn()

	defer func() {
		s.clearPendingSession(session)
		boundIR := session.BoundRuntime()
		wasActiveClient := s.sessionManager().ClearActive(session)
		_ = session.Close() // Best-effort cleanup

		// Run owner cleanup whenever this authenticated session exits and no
		// active owner remains. Displaced clients skip cleanup because the
		// replacement is already active before they are notified and closed.
		if cleanupRuntime && boundIR != nil && (wasActiveClient || !s.sessionManager().HasClient()) {
			// Route disconnect cleanup through the bound identity
			if wasActiveClient && s.signer != nil {
				s.signer.auditLog.LogSessionDisconnectedContext(session.SessionContext())
			}
			boundIR.FailAllPendingApprovals(signerapproval.SignRequestCancelReasonApproverDisconnected)

			// Lock behavior is driven by the live product runtime config,
			// which should already reflect any stored overrides.
			if boundIR.Config().LockOnDisconnect() {
				boundIR.Lock()
				logWarnf("apadmin client disconnected - signer locked")
			} else {
				logWarnf("apadmin disconnected - signer remains unlocked")
			}
		}
	}()

	// Authenticate the client before allowing normal operations. A fresh store
	// can also handle one local initialize request before passphrase auth exists.
	switch session.AuthenticateOutcome() {
	case adminserver.AuthOutcomeAuthenticated:
		cleanupRuntime = !session.AuthenticatedOnly()
		setPreAuthReadDeadline(adminConn, time.Time{})
	case adminserver.AuthOutcomeTimedOut:
		logWarnf("IPC client did not log in within %s; connection closed", s.loginTimeout())
		return
	default:
		logWarnf("IPC client authentication failed")
		return
	}
	logInfof("IPC client authenticated")

	// Now register as the active client (after auth succeeds)
	// This ensures NotifyKeysChanged won't send messages during auth
	boundIR := session.BoundRuntime()
	if boundIR == nil {
		return
	}
	if session.AuthenticatedOnly() {
		// auth_only sessions are bounded, server-enforced public-read observers.
		// They never occupy or replace the active owner slot, receive approval
		// notifications, fail pending approvals, or run lock-on-disconnect cleanup.
		s.clearPendingSession(session)
		s.serveAdminMessages(session, adminConn)
		return
	}
	active, ok := s.sessionManager().BindPreAuthPending(session)
	if !ok {
		logWarnf("IPC client could not bind the pending product session")
		return
	}
	if active != nil && active != session && active != displacementConfirmedFor {
		if !s.offerDisplacementSession(adminConn) {
			s.sessionManager().ClearPending(session)
			return
		}
	}
	replaced := s.sessionManager().PromoteToActive(session)
	if replaced != nil && replaced != session {
		if replacedIR := replaced.BoundRuntime(); replacedIR != nil {
			replacedIR.FailAllPendingApprovals(signerapproval.SignRequestCancelReasonApproverDisplaced)
		}
		adminserver.DisplaceSession(replaced)
	}

	if s.signer != nil {
		s.signer.auditLog.LogSessionConnectedContext(session.SessionContext())
	}

	// Send initial status after successful authentication
	_ = session.SendStatus()
	// After the status, the operator who now owns the session sees every
	// enrollment request still waiting, oldest first.
	if s.signer != nil {
		s.signer.notifyPendingEnrollments()
	}

	s.serveAdminMessages(session, adminConn)
}

func (s *IPCServer) serveAdminMessages(session *adminserver.Session, adminConn adminproto.AdminConn) {
	for {
		line, err := adminConn.ReadMessage()
		if err != nil {
			return
		}
		session.Dispatch(line)
		// The frame may carry a passphrase or a recovery phrase. Handlers
		// decode what they need into their own buffers, so it is not needed
		// once the message is handled.
		protocol.SensitiveBytes(line).Zero()
	}
}

// HasClient returns true if an admin client is connected.
func (s *IPCServer) HasClient() bool {
	return s.sessionManager().HasClient()
}

// SendSignRequest sends a signing request to the IPC client.
func (s *IPCServer) SendSignRequest(req *signerapproval.SignRequest) bool {
	active := s.activeSession()
	if active == nil {
		return false
	}
	return active.WriteJSON(adminserver.ProtocolSignRequestMessage(*req)) == nil
}

// SendSignRequestCanceled tells the IPC client that a previously delivered
// signing request is no longer actionable.
func (s *IPCServer) SendSignRequestCanceled(msg *signerapproval.SignRequestCanceled) bool {
	active := s.activeSession()
	if active == nil || msg == nil {
		return false
	}
	return active.WriteJSON(adminserver.ProtocolSignRequestCanceledMessage(*msg)) == nil
}

// SendClientEnrollmentRequest tells the IPC client that an enrollment
// request is waiting for the operator.
func (s *IPCServer) SendClientEnrollmentRequest(req *signerapproval.ClientEnrollmentRequest) bool {
	active := s.activeSession()
	if active == nil {
		return false
	}
	return active.WriteJSON(adminserver.ProtocolClientEnrollmentRequestMessage(*req)) == nil
}

// NotifyLocked sends a signer_locked notification to the connected IPC client.
// This allows apadmin to transition to the unlock screen when the signer locks.
func (s *IPCServer) NotifyLocked(notification adminproto.SignerLockedNotification) {
	msg := adminserver.ProtocolSignerLockedMessage(notification)
	active := s.activeSession()
	if active == nil {
		return
	}
	_ = active.WriteJSON(msg) // Best-effort notification
}

// NotifyStatus pushes the current signer state to the connected IPC client.
// Used when the runtime state changes without a client request that already
// reports it — e.g. leaving recovery mode after the marker rescan comes back
// clean.
func (s *IPCServer) NotifyStatus(state string, keyCount int, warnings []string) {
	active := s.activeSession()
	if active == nil {
		return
	}
	_ = active.WriteJSON(adminserver.ProtocolStatusMessage(state, keyCount, warnings)) // Best-effort notification
}

// NotifyKeysChanged sends a keys_changed notification to the connected IPC client.
// This allows apadmin to refresh its key list when keys are added/removed.
func (s *IPCServer) NotifyKeysChanged(notification adminproto.KeysChangedNotification) {
	msg := adminserver.ProtocolKeysChangedMessage(notification)
	active := s.activeSession()
	if active == nil {
		return
	}
	_ = active.WriteJSON(msg) // Best-effort notification
}

// NotifyEnrollmentChanged sends an enrollment_changed notification to the
// connected IPC client so a screen showing the enrollment queue or the
// client registry can re-fetch it, whatever session or path made the change.
func (s *IPCServer) NotifyEnrollmentChanged(notification adminproto.EnrollmentChangedNotification) {
	active := s.activeSession()
	if active == nil {
		return
	}
	_ = active.WriteJSON(adminserver.ProtocolEnrollmentChangedMessage(notification)) // Best-effort notification
}

func (s *IPCServer) sessionManager() *adminserver.SessionManager {
	if s.manager == nil {
		s.manager = adminserver.NewSessionManager()
	}
	return s.manager
}

func (s *IPCServer) activeSession() *adminserver.Session {
	return s.sessionManager().ActiveSession()
}

func (s *IPCServer) clearPendingSession(session *adminserver.Session) {
	s.sessionManager().ClearPreAuthPending(session)
	s.sessionManager().ClearPending(session)
}
