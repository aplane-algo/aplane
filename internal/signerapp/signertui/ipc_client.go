// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/transport"
	tea "github.com/charmbracelet/bubbletea"
)

// ReconnectingMsg is sent when attempting to reconnect
type ReconnectingMsg struct {
	Delay time.Duration
}

type queuedMsg struct {
	sessionID uint64
	msg       tea.Msg
}

// IPCClient manages the IPC connection to aplane
type IPCClient struct {
	conn      io.ReadWriteCloser
	stream    *transport.StreamClient
	connector AdminConnector

	// Mutex for connection state
	mu        sync.Mutex
	connected bool

	// Channel for incoming messages to forward to TUI
	msgChan chan queuedMsg
	// sendMu is held shared by emit for its whole enqueue and exclusively by
	// discardStaleQueued, so a drain sees a queue no producer can add to.
	sendMu sync.RWMutex

	// Done channel for shutdown
	done chan struct{}

	// Session token increments whenever a new connection lifecycle starts.
	sessionID uint64

	// Displacement state
	// serverEnded is set when the signer ended the session on purpose
	// (displacement or a login timeout); reconnecting would undo that.
	serverEnded bool

	// Reconnection state. reconnectDelay and maxDelay are set at construction
	// (tests shorten them) and never change.
	reconnecting   bool
	reconnectDelay time.Duration
	maxDelay       time.Duration

	// notificationLoss is shared with the client this one replaces, if any.
	notificationLoss *notificationLoss
}

// NewAdminClient creates a new admin client for an arbitrary transport.
func NewAdminClient(connector AdminConnector) *IPCClient {
	return &IPCClient{
		connector:      connector,
		msgChan:        make(chan queuedMsg, 10),
		done:           make(chan struct{}),
		reconnectDelay: 1 * time.Second,
		maxDelay:       30 * time.Second,

		notificationLoss: newNotificationLoss(),
	}
}

// Connect establishes the IPC connection
func (c *IPCClient) Connect() error {
	c.mu.Lock()

	if c.connected {
		c.mu.Unlock()
		return nil
	}

	// A new session begins only once the dial succeeds. A failed attempt
	// leaves the session as it was, so a reconnect loop for it goes on
	// retrying rather than finding its session superseded by nothing.
	conn, err := c.connector.Connect()
	if err != nil {
		c.mu.Unlock()
		return err
	}
	c.done = make(chan struct{})
	c.sessionID++
	sessionID := c.sessionID

	c.conn = conn
	c.stream = transport.NewStreamClient(conn)
	stream := c.stream
	c.connected = true
	c.serverEnded = false
	done := c.done
	c.mu.Unlock()

	c.notificationLoss.track(stream)

	// Start message reader goroutine
	go c.forwardMessages(sessionID, done, stream.Notifications(), stream.LifecycleEvents())

	return nil
}

// Disconnect closes the IPC connection
func (c *IPCClient) Disconnect() {
	c.mu.Lock()
	if !c.connected && c.done == nil {
		c.mu.Unlock()
		c.discardStaleQueued()
		return
	}

	done := c.done
	conn := c.conn
	stream := c.stream
	c.done = nil
	c.conn = nil
	c.stream = nil
	c.connected = false
	c.serverEnded = false
	c.reconnecting = false
	c.sessionID++
	c.mu.Unlock()

	if done != nil {
		select {
		case <-done:
		default:
			close(done)
		}
	}
	if stream != nil {
		_ = stream.Close()
	} else if conn != nil {
		_ = conn.Close()
	}
	c.discardStaleQueued()
}

// zeroSensitiveMsg clears recovery material carried by a message that will
// never reach the model.
func zeroSensitiveMsg(msg tea.Msg) {
	if result, ok := msg.(nativeMnemonicResultMsg); ok {
		result.Mnemonic.Zero()
	}
}

// discardStaleQueued drops, and clears, queued messages from ended sessions.
// No listener may ever consume them (listeners also exit on done), so without
// this a recovery phrase queued just before a disconnect would stay resident.
// It waits for in-flight emits, which unblock once their session's done is
// closed, so none can enqueue a stale message behind the drain. Messages of
// the current session are put back in order.
func (c *IPCClient) discardStaleQueued() {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.mu.Lock()
	current := c.sessionID
	c.mu.Unlock()
	var keep []queuedMsg
drain:
	for {
		select {
		case queued := <-c.msgChan:
			if queued.sessionID < current {
				zeroSensitiveMsg(queued.msg)
				continue
			}
			keep = append(keep, queued)
		default:
			break drain
		}
	}
	for _, queued := range keep {
		select {
		case c.msgChan <- queued:
		default:
			// Unreachable: the drain freed at least this much room and
			// emits are excluded. Never block teardown on it.
			zeroSensitiveMsg(queued.msg)
		}
	}
}

// SendAuth sends an authentication request. It zeroes its copy of the
// passphrase once sent; the caller zeroes its own.
func (c *IPCClient) SendAuth(passphrase []byte) error {
	protocolVersion := CurrentAdminProtocolVersion()
	msg := AuthMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeAuth,
			ID:   fmt.Sprintf("auth-%d", time.Now().UnixNano()),
		},
		Passphrase:      SensitiveBytes(cloneBytes(passphrase)),
		ProtocolVersion: &protocolVersion,
	}
	defer msg.Passphrase.Zero()
	return c.sendMessage(msg)
}

// SendUnlock sends an unlock request. It zeroes its copy of the passphrase
// once sent; the caller zeroes its own.
func (c *IPCClient) SendUnlock(passphrase []byte) error {
	msg := UnlockMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeUnlock,
			ID:   fmt.Sprintf("unlock-%d", time.Now().UnixNano()),
		},
		Passphrase: SensitiveBytes(cloneBytes(passphrase)),
	}
	defer msg.Passphrase.Zero()
	return c.sendMessage(msg)
}

// SendLockIdentity requests an explicit lock of the bound identity.
func (c *IPCClient) SendLockIdentity(reason string) error {
	msg := LockIdentityMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeLockIdentity,
			ID:   fmt.Sprintf("lock-%d", time.Now().UnixNano()),
		},
		Reason: reason,
	}
	return c.sendMessage(msg)
}

// SendSignResponse sends a signing approval/rejection
func (c *IPCClient) SendSignResponse(requestID string, approved bool, reason string) error {
	msg := SignResponseMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeSignResponse,
			ID:   requestID,
		},
		Approved: approved,
		Reason:   reason,
	}
	return c.sendMessage(msg)
}

// SendApproveEnrollment enrolls the key of a waiting enrollment request.
func (c *IPCClient) SendApproveEnrollment(fingerprint, label string) error {
	return c.sendMessage(ApproveEnrollmentMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeApproveEnrollment,
			ID:   fmt.Sprintf("approve-%d", time.Now().UnixNano()),
		},
		Fingerprint: fingerprint,
		Label:       label,
	})
}

// SendRejectEnrollment drops a waiting enrollment request.
func (c *IPCClient) SendRejectEnrollment(fingerprint string) error {
	return c.sendMessage(RejectEnrollmentMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeRejectEnrollment,
			ID:   fmt.Sprintf("reject-%d", time.Now().UnixNano()),
		},
		Fingerprint: fingerprint,
	})
}

// SendListPendingEnrollments asks for the waiting enrollment requests.
func (c *IPCClient) SendListPendingEnrollments(id string) error {
	return c.sendMessage(ListPendingEnrollmentsMessage{BaseMessage: BaseMessage{
		Type: MsgTypeListPendingEnrollments,
		ID:   id,
	}})
}

// SendImportClientKey pre-enrolls an OpenSSH public-key line.
func (c *IPCClient) SendImportClientKey(publicKey, label string) error {
	return c.sendMessage(ImportClientKeyMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeImportClientKey,
			ID:   fmt.Sprintf("import-client-%d", time.Now().UnixNano()),
		},
		PublicKey: publicKey,
		Label:     label,
	})
}

// sendMessage sends a message over IPC
func (c *IPCClient) sendMessage(msg interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected || c.stream == nil {
		return fmt.Errorf("not connected")
	}
	return c.stream.WriteJSON(msg)
}

func (c *IPCClient) SendAndReceive(msg interface{}, timeout time.Duration) ([]byte, error) {
	c.mu.Lock()
	stream := c.stream
	connected := c.connected
	c.mu.Unlock()
	if !connected || stream == nil {
		return nil, fmt.Errorf("not connected")
	}
	return stream.SendAndReceive(msg, timeout)
}

func (c *IPCClient) emit(sessionID uint64, msg tea.Msg) bool {
	c.sendMu.RLock()
	defer c.sendMu.RUnlock()
	c.mu.Lock()
	currentSession := c.sessionID
	done := c.done
	c.mu.Unlock()

	if currentSession > sessionID || done == nil {
		zeroSensitiveMsg(msg)
		return false
	}

	// Select on the session's done channel so a forwarder blocked on a full,
	// undrained msgChan (e.g. the TUI went away) unblocks on teardown instead
	// of leaking.
	select {
	case <-done:
		zeroSensitiveMsg(msg)
		return false
	case c.msgChan <- queuedMsg{sessionID: sessionID, msg: msg}:
		return true
	}
}

// reportNotificationLoss sends the running total of lost notifications, if any.
func (c *IPCClient) reportNotificationLoss(sessionID uint64) {
	if total := c.notificationLoss.total(); total > 0 {
		c.emit(sessionID, NotificationsLostMsg{Total: total})
	}
}

// emitUndecodable reports a signer message the TUI cannot decode. Dropping it
// would leave a screen waiting for a result that never arrives.
func (c *IPCClient) emitUndecodable(sessionID uint64, notification transport.Notification, err error) {
	c.emit(sessionID, ErrorMsg{
		ID:    notification.Base.ID,
		Error: fmt.Errorf("cannot decode %s message from signer: %w", notification.Base.Type, err),
	})
}

// forwardMessages receives dispatcher notifications/lifecycle events and
// forwards them to the TUI while preserving reconnect/displacement semantics.
func (c *IPCClient) forwardMessages(sessionID uint64, done <-chan struct{}, notifications <-chan transport.Notification, lifecycle <-chan transport.LifecycleEvent) {
	defer func() {
		// A loss can land just before the connection ends, and no later signal
		// reaches this loop.
		c.reportNotificationLoss(sessionID)

		c.mu.Lock()
		if c.sessionID != sessionID {
			c.mu.Unlock()
			return
		}
		c.connected = false
		c.conn = nil
		c.stream = nil
		serverEnded := c.serverEnded
		c.mu.Unlock()

		if serverEnded {
			// The TUI was already told why (DisplacedMsg or a login-timeout
			// AuthResultMsg); don't auto-reconnect.
			return
		}

		go c.reconnect(sessionID, done)
	}()

	// Losses from before this connection may not have reached the model.
	c.reportNotificationLoss(sessionID)

	for {
		select {
		case <-done:
			return
		case <-c.notificationLoss.changed:
			c.reportNotificationLoss(sessionID)
		case event, ok := <-lifecycle:
			if !ok {
				return
			}
			if event.Type != transport.LifecycleConnectionLost &&
				event.Type != transport.LifecycleProtocolError &&
				event.Type != transport.LifecycleReaderStopped {
				continue
			}
			// The transport's single reader queues every notification before
			// it reports the end of the connection, but on separate channels.
			// Deliver what is already queued first: a login_timeout or
			// displacement there must suppress the reconnect below.
			if c.drainNotifications(sessionID, notifications) {
				return
			}
			switch event.Type {
			case transport.LifecycleConnectionLost:
				if event.Err != nil && !errors.Is(event.Err, io.EOF) {
					c.emit(sessionID, ErrorMsg{Error: event.Err})
				}
			case transport.LifecycleProtocolError:
				c.emit(sessionID, ErrorMsg{Error: fmt.Errorf("protocol error: %w", event.Err)})
			}
			return
		case notification, ok := <-notifications:
			if !ok {
				return
			}
			if c.forwardNotification(sessionID, notification) {
				return
			}
		}
	}
}

// drainNotifications forwards notifications already queued without waiting
// for more. It reports whether one of them ended the session.
func (c *IPCClient) drainNotifications(sessionID uint64, notifications <-chan transport.Notification) bool {
	for {
		select {
		case notification, ok := <-notifications:
			if !ok {
				return false
			}
			if c.forwardNotification(sessionID, notification) {
				return true
			}
		default:
			return false
		}
	}
}

// forwardNotification turns one signer notification into a TUI message. It
// reports whether the notification ended the session (displacement), after
// which nothing more is read.
func (c *IPCClient) forwardNotification(sessionID uint64, notification transport.Notification) bool {
	if notification.Base.Type == protocol.MsgTypeExportResult {
		defer protocol.SensitiveBytes(notification.Raw).Zero()
	}

	if notification.Base.Type == MsgTypeDisplaced {
		// Displacement ends the session without a reconnect.
		var displaced DisplacedMessage
		if err := json.Unmarshal(notification.Raw, &displaced); err != nil {
			c.emitUndecodable(sessionID, notification, err)
			return false
		}
		c.mu.Lock()
		c.serverEnded = true
		c.mu.Unlock()
		c.emit(sessionID, DisplacedMsg{Reason: displaced.Reason})
		return true
	}
	decode, ok := signerMessageDecoders[notification.Base.Type]
	if !ok {
		return false
	}
	msg, err := decode(notification.Raw)
	if err != nil {
		c.emitUndecodable(sessionID, notification, err)
		return false
	}
	if isLoginTimeout(msg) {
		// The signer closes the connection next. Reconnecting would take the
		// single pre-auth slot right back.
		c.mu.Lock()
		c.serverEnded = true
		c.mu.Unlock()
	}
	c.emit(sessionID, msg)
	return false
}

func isLoginTimeout(msg tea.Msg) bool {
	result, ok := msg.(AuthResultMsg)
	return ok && !result.Success && result.Code == protocol.ErrCodeLoginTimeout
}

// signerMessageDecoders turns each signer message type into the TUI message
// the update loop handles. A type with no entry is ignored.
var signerMessageDecoders = map[string]func(raw []byte) (tea.Msg, error){
	// Server requires authentication before any other operations.
	MsgTypeAuthRequired: noBody(AuthRequiredMsg{}),
	// Server locked: transition to the unlock screen.
	MsgTypeSignerLocked: noBody(SignerStatusMsg{State: "locked"}),
	MsgTypeClientExists: noBody(ClientExistsMsg{}),
	MsgTypeAuthResult: decodeAs(func(authResult AuthResultMessage) tea.Msg {
		return AuthResultMsg{
			Success: authResult.Success,
			Code:    authResult.Code,
			Error:   authResult.Error,
		}
	}),
	MsgTypeStatus: decodeAs(func(status StatusMessage) tea.Msg {
		return SignerStatusMsg{
			State:    status.State,
			KeyCount: status.KeyCount,
			Warnings: status.Warnings,
		}
	}),
	MsgTypeUnlockResult: decodeAs(func(result UnlockResultMessage) tea.Msg {
		return UnlockResultMsg{
			Success:  result.Success,
			KeyCount: result.KeyCount,
			Code:     result.Code,
			Error:    result.Error,
		}
	}),
	MsgTypeLockIdentityResult: decodeAs(func(result LockIdentityResultMessage) tea.Msg {
		return LockIdentityResultMsg{
			Success: result.Success,
			Error:   result.Error,
		}
	}),
	MsgTypeSignRequest: decodeAs(func(req SignRequestMessage) tea.Msg {
		req = req.TerminalSafe()
		return SignRequestReceivedMsg{
			Request: PendingSignRequest{
				ID:          req.ID,
				Address:     req.Address,
				TxnSender:   req.TxnSender,
				Description: req.Description,
				Timestamp:   time.Unix(req.Timestamp, 0),
				FirstValid:  req.FirstValid,
				LastValid:   req.LastValid,
				Violations:  req.Violations,
				Review:      req.Review,
			},
		}
	}),
	MsgTypeSignRequestCanceled: decodeAs(func(canceled SignRequestCanceledMessage) tea.Msg {
		return SignRequestCanceledMsg{
			ID:     canceled.ID,
			Reason: canceled.Reason,
		}
	}),
	MsgTypeError: decodeAs(func(errMsg ErrorMessage) tea.Msg {
		return ErrorMsg{ID: errMsg.ID, Error: fmt.Errorf("%s", errMsg.Error)}
	}),
	MsgTypeKeysList: decodeAs(func(keysList KeysListMessage) tea.Msg {
		keys := make([]KeyInfo, 0, len(keysList.Keys))
		for _, k := range keysList.Keys {
			keys = append(keys, KeyInfo{
				Address:                  k.Address,
				KeyType:                  k.KeyType,
				TemplateProvenanceStatus: k.TemplateProvenanceStatus,
				TemplateProvenanceNote:   k.TemplateProvenanceNote,
			})
		}
		return KeysListMsg{Keys: keys}
	}),
	protocol.MsgTypeExportResult: decodeAs(func(result protocol.ExportResultMessage) tea.Msg { return nativeMnemonicResultMsg(result) }),
	MsgTypeGenerateResult: decodeAs(func(genResult GenerateResultMessage) tea.Msg {
		return GenerateResultMsg{
			ID:       genResult.ID,
			Success:  genResult.Success,
			Address:  genResult.Address,
			KeyType:  genResult.KeyType,
			Warnings: genResult.Warnings,
			Error:    genResult.Error,
		}
	}),
	MsgTypePrepareGenerateResult: decodeAs(func(result PrepareGenerateResultMessage) tea.Msg {
		return PrepareGenerateResultMsg{Result: result}
	}),
	MsgTypeBackupResult: decodeAs(func(backupResult BackupResultMessage) tea.Msg {
		return BackupResultMsg{
			ID:          backupResult.ID,
			Success:     backupResult.Success,
			ArchivePath: backupResult.ArchivePath,
			Warning:     backupResult.Warning,
			Error:       backupResult.Error,
		}
	}),
	MsgTypeBackupsList: decodeAs(func(backupsList BackupsListMessage) tea.Msg {
		return BackupsListMsg{
			Backups: backupsList.Backups,
			Error:   backupsList.Error,
		}
	}),
	MsgTypeRestorePreview: decodeAs(func(preview RestorePreviewMessage) tea.Msg {
		return RestorePreviewMsg{
			ID:               preview.ID,
			ArchivePath:      preview.ArchivePath,
			ArchiveCreatedAt: preview.ArchiveCreatedAt,
			Keys:             preview.Keys,
			Errors:           preview.Errors,
			Error:            preview.Error,
		}
	}),
	MsgTypeRestoreBackupResult: decodeAs(func(restored RestoreBackupResultMessage) tea.Msg {
		return RestoreBackupResultMsg{Result: restored}
	}),
	MsgTypeRollbackRestoreResult: decodeAs(func(result RollbackRestoreResultMessage) tea.Msg {
		return RollbackRestoreResultMsg{Result: result}
	}),
	MsgTypeReconcileStoreResult: decodeAs(func(result ReconcileStoreResultMessage) tea.Msg {
		return ReconcileStoreResultMsg{Result: result}
	}),
	MsgTypeDeleteResult: decodeAs(func(delResult DeleteResultMessage) tea.Msg {
		return DeleteResultMsg{
			ID:      delResult.ID,
			Success: delResult.Success,
			Error:   delResult.Error,
		}
	}),
	MsgTypeEnrolledKeysList: decodeAs(func(list EnrolledKeysListMessage) tea.Msg {
		return EnrolledKeysListMsg{Keys: list.Keys}
	}),
	MsgTypePendingEnrollmentsList: decodeAs(func(list PendingEnrollmentsListMessage) tea.Msg {
		return PendingEnrollmentsListMsg{Requests: list.Requests}
	}),
	MsgTypeApproveEnrollmentResult: decodeAs(func(result ApproveEnrollmentResultMessage) tea.Msg {
		return ApproveEnrollmentResultMsg{Success: result.Success, Error: result.Error, Fingerprint: result.Fingerprint, Label: result.Label}
	}),
	MsgTypeRejectEnrollmentResult: decodeAs(func(result RejectEnrollmentResultMessage) tea.Msg {
		return RejectEnrollmentResultMsg{Success: result.Success, Error: result.Error, Fingerprint: result.Fingerprint}
	}),
	MsgTypeImportClientKeyResult: decodeAs(func(result ImportClientKeyResultMessage) tea.Msg {
		return ImportClientKeyResultMsg{Success: result.Success, Error: result.Error, Fingerprint: result.Fingerprint, Label: result.Label, Added: result.Added}
	}),
	MsgTypeRevokeEnrolledKeyResult: decodeAs(func(result RevokeEnrolledKeyResultMessage) tea.Msg {
		return RevokeEnrolledKeyResultMsg{
			Success:           result.Success,
			Error:             result.Error,
			ClosedConnections: result.ClosedConnections,
		}
	}),
	MsgTypeRevokeAllEnrolledKeysResult: decodeAs(func(result RevokeAllEnrolledKeysResultMessage) tea.Msg {
		return RevokeAllEnrolledKeysResultMsg{
			Success:           result.Success,
			Error:             result.Error,
			RevokedCount:      result.RevokedCount,
			ClosedConnections: result.ClosedConnections,
		}
	}),
	MsgTypeImportResult: decodeAs(func(impResult ImportResultMessage) tea.Msg {
		return ImportResultMsg{
			ID:      impResult.ID,
			Success: impResult.Success,
			Address: impResult.Address,
			KeyType: impResult.KeyType,
			Error:   impResult.Error,
		}
	}),
	MsgTypeKeyDetails: decodeAs(func(detailsResult KeyDetailsMessage) tea.Msg {
		return KeyDetailsMsg{
			Success:                  detailsResult.Success,
			Address:                  detailsResult.Address,
			KeyType:                  detailsResult.KeyType,
			PublicKeyHex:             detailsResult.PublicKeyHex,
			Parameters:               detailsResult.Parameters,
			DisplayTEAL:              detailsResult.DisplayTEAL,
			TemplateProvenanceStatus: detailsResult.TemplateProvenanceStatus,
			TemplateProvenanceNote:   detailsResult.TemplateProvenanceNote,
			PolicyLabel:              detailsResult.PolicyLabel,
			MnemonicExportable:       detailsResult.MnemonicExportable,
			Error:                    detailsResult.Error,
		}
	}),
	MsgTypeLibraryTemplates: decodeAs(func(library LibraryTemplatesMessage) tea.Msg {
		return LibraryTemplatesMsg{
			Templates: library.Templates,
			Error:     library.Error,
		}
	}),
	MsgTypeInstallLibraryTemplateResult: decodeAs(func(result InstallLibraryTemplateResultMessage) tea.Msg {
		return InstallLibraryTemplateResultMsg{
			ID:            result.ID,
			Success:       result.Success,
			KeyType:       result.KeyType,
			TemplateType:  result.TemplateType,
			AlreadyExists: result.AlreadyExists,
			Error:         result.Error,
		}
	}),
	MsgTypeShowLibraryTemplateResult: decodeAs(func(result ShowLibraryTemplateResultMessage) tea.Msg {
		return ShowLibraryTemplateResultMsg{
			Success:       result.Success,
			KeyType:       result.KeyType,
			TemplateType:  result.TemplateType,
			SourcePath:    result.SourcePath,
			SourceSHA256:  result.SourceSHA256,
			SourceModTime: result.SourceModTime,
			TemplateYAML:  result.TemplateYAML,
			Error:         result.Error,
		}
	}),
	MsgTypeShowInstalledTemplateResult: decodeAs(func(result ShowInstalledTemplateResultMessage) tea.Msg {
		return ShowLibraryTemplateResultMsg{
			Success:      result.Success,
			KeyType:      result.KeyType,
			TemplateType: result.TemplateType,
			TemplateYAML: result.TemplateYAML,
			Error:        result.Error,
		}
	}),
	MsgTypeActivateKeyTypeResult: decodeAs(func(result ActivateKeyTypeResultMessage) tea.Msg {
		return ActivateKeyTypeResultMsg{
			ID:            result.ID,
			Success:       result.Success,
			KeyType:       result.KeyType,
			AlreadyExists: result.AlreadyExists,
			Error:         result.Error,
		}
	}),
	MsgTypeDeactivateKeyTypeResult: decodeAs(func(result DeactivateKeyTypeResultMessage) tea.Msg {
		return DeactivateKeyTypeResultMsg{
			ID:      result.ID,
			Success: result.Success,
			KeyType: result.KeyType,
			Removed: result.Removed,
			Error:   result.Error,
		}
	}),
	MsgTypeKeyTypes: decodeAs(func(keyTypes KeyTypesMessage) tea.Msg {
		return KeyTypesMsg{
			KeyTypes: keyTypes.KeyTypes,
			Error:    keyTypes.Error,
		}
	}),
	MsgTypeCosignerReferencesList: decodeAs(func(references CosignerReferencesListMessage) tea.Msg {
		return CosignerReferencesMsg{
			References: references.References,
			Error:      references.Error,
		}
	}),
	MsgTypeImportCosignerReferenceResult: decodeAs(func(result ImportCosignerReferenceResultMessage) tea.Msg {
		return CosignerImportResultMsg{
			ID:        result.ID,
			Success:   result.Success,
			Reference: result.Reference,
			Error:     result.Error,
		}
	}),
	MsgTypeRemoveCosignerReferenceResult: decodeAs(func(result RemoveCosignerReferenceResultMessage) tea.Msg {
		return CosignerRemoveResultMsg{
			ID:      result.ID,
			Success: result.Success,
			Name:    result.Name,
			Removed: result.Removed,
			Error:   result.Error,
		}
	}),
	MsgTypeExportCosignerPublicResult: decodeAs(func(result ExportCosignerPublicResultMessage) tea.Msg {
		return CosignerExportResultMsg{
			ID:           result.ID,
			Success:      result.Success,
			WitnessKeyID: result.WitnessKeyID,
			EnvelopeJSON: result.EnvelopeJSON,
			Error:        result.Error,
		}
	}),
	MsgTypeKeysChanged: decodeAs(func(keysChanged KeysChangedMessage) tea.Msg {
		return KeysChangedMsg{
			KeyCount: keysChanged.KeyCount,
		}
	}),
	MsgTypeEnrollmentChanged: decodeAs(func(changed EnrollmentChangedMessage) tea.Msg {
		return EnrollmentChangedMsg{Reason: changed.Reason, Fingerprint: changed.Fingerprint}
	}),
	MsgTypeClientEnrollmentRequest: decodeAs(func(req ClientEnrollmentRequestMessage) tea.Msg {
		return ClientEnrollmentRequestReceivedMsg{
			Request: PendingEnrollmentRequest{
				ID:             req.ID,
				SSHFingerprint: req.SSHFingerprint,
				Label:          req.Label,
				RemoteAddr:     req.RemoteAddr,
				Timestamp:      time.Unix(req.Timestamp, 0),
			},
		}
	}),
	MsgTypePolicy: decodeAs(func(policyMsg PolicyMessage) tea.Msg {
		return PolicyLoadedMsg{Policy: policyMsg}
	}),
	MsgTypePolicyContext: decodeAs(func(contextMsg PolicyContextMessage) tea.Msg {
		return PolicyContextLoadedMsg{Context: contextMsg}
	}),
	MsgTypePolicyDocument: decodeAs(func(documentMsg PolicyDocumentMessage) tea.Msg {
		return PolicyDocumentLoadedMsg{Document: documentMsg}
	}),
	MsgTypeCheckPolicyResult: decodeAs(func(result CheckPolicyResultMessage) tea.Msg {
		return PolicyCheckResultMsg{Result: result}
	}),
	MsgTypeApplyPolicyResult: decodeAs(func(result ApplyPolicyResultMessage) tea.Msg {
		return PolicyApplyResultMsg{Result: result}
	}),
	MsgTypeAdminSettings: decodeAs(func(settings AdminSettingsMessage) tea.Msg {
		return AdminSettingsMsg{
			Settings: AdminSettings{
				UserAutoApprove:      settings.UserAutoApprove,
				RequireContained:     settings.RequireContained,
				RequireCosigner:      settings.RequireCosigner,
				LockOnDisconnect:     settings.LockOnDisconnect,
				PassphraseTimeout:    settings.PassphraseTimeout,
				PassphraseMethod:     settings.PassphraseMethod,
				NodeRole:             settings.NodeRole,
				SSHEnabled:           settings.SSHEnabled,
				SSHListenAddress:     settings.SSHListenAddress,
				SSHPort:              settings.SSHPort,
				SSHFingerprint:       settings.SSHFingerprint,
				SSHClients:           settings.SSHClients,
				SignerPort:           settings.SignerPort,
				TEALCompileNet:       settings.TEALCompileNet,
				EndpointAdvertiseURL: settings.EndpointAdvertiseURL,
				EndpointDisplayURL:   settings.EndpointDisplayURL,
				Theme:                settings.Theme,
				UnsavedSettings:      settings.UnsavedSettings,
			},
		}
	}),
	MsgTypeUpdateAdminSettingResult: decodeAs(func(result UpdateAdminSettingResultMessage) tea.Msg {
		return AdminSettingUpdatedMsg{
			Success: result.Success,
			Key:     result.Key,
			Value:   result.Value,
			Code:    result.Code,
			Error:   result.Error,
		}
	}),
}

// decodeAs decodes a message body as wire type T and converts it.
func decodeAs[T any](convert func(T) tea.Msg) func([]byte) (tea.Msg, error) {
	return func(raw []byte) (tea.Msg, error) {
		var wire T
		if err := json.Unmarshal(raw, &wire); err != nil {
			// A decode can fail after filling some fields, such as a recovery
			// phrase before a malformed later field; zero what it filled.
			protocol.ZeroSensitive(&wire)
			return nil, err
		}
		return convert(wire), nil
	}
}

// noBody maps a message whose body carries nothing the TUI reads.
func noBody(msg tea.Msg) func([]byte) (tea.Msg, error) {
	return func([]byte) (tea.Msg, error) { return msg, nil }
}

// reconnect attempts to reconnect with exponential backoff
func (c *IPCClient) reconnect(sessionID uint64, done <-chan struct{}) {
	c.mu.Lock()
	if c.reconnecting || c.sessionID != sessionID {
		c.mu.Unlock()
		return
	}
	c.reconnecting = true
	delay, maxDelay := c.reconnectDelay, c.maxDelay
	c.mu.Unlock()

	for {
		c.emit(sessionID, ReconnectingMsg{Delay: delay})

		select {
		case <-done:
			c.mu.Lock()
			if c.sessionID == sessionID {
				c.reconnecting = false
			}
			c.mu.Unlock()
			return
		default:
		}

		// Wait before attempting reconnection
		time.Sleep(delay)

		// Check if we're still supposed to reconnect
		c.mu.Lock()
		if c.sessionID != sessionID || c.connected {
			c.reconnecting = false
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		// Attempt connection
		err := c.Connect()
		if err == nil {
			c.mu.Lock()
			c.reconnecting = false
			newSessionID := c.sessionID
			c.mu.Unlock()

			c.emit(newSessionID, ConnectedMsg{})
			return
		}

		delay = min(delay*2, maxDelay)
	}
}

// listenerMsg carries one message the listener took from the client's queue.
// Model.Update handles the message it carries and only then starts the next
// wait, so exactly one wait is in flight and the model handles messages in
// the order the signer sent them.
type listenerMsg struct{ msg tea.Msg }

// Unwrap returns the signer message msg carries when it came through the
// signer TUI's listener, and msg itself otherwise. A host model that reads
// signer messages, as apconsole reads the admin settings, looks through the
// wrapper with Unwrap and still forwards msg itself, so the signer model
// starts its next wait.
func Unwrap(msg tea.Msg) tea.Msg {
	if delivered, ok := msg.(listenerMsg); ok {
		return delivered.msg
	}
	return msg
}

// ListenForMessages returns a tea.Cmd that waits for the next queued message
// and delivers it as a listenerMsg, or nothing once the session's done
// channel closes. On a client already disconnected (done is nil) there is
// nothing to wait for: a wait there would block for good.
func (c *IPCClient) ListenForMessages() tea.Cmd {
	return func() tea.Msg {
		for {
			c.mu.Lock()
			done := c.done
			currentSession := c.sessionID
			c.mu.Unlock()
			if done == nil {
				return nil
			}

			select {
			case queued := <-c.msgChan:
				if queued.sessionID < currentSession {
					zeroSensitiveMsg(queued.msg)
					continue
				}
				return listenerMsg{msg: queued.msg}
			case <-done:
				return nil
			}
		}
	}
}

// ConnectCmd returns a tea.Cmd that connects to the server via IPC
func ConnectCmd(connector AdminConnector) tea.Cmd {
	return func() tea.Msg {
		client := NewAdminClient(connector)

		if err := client.Connect(); err != nil {
			return DisconnectedMsg{Error: err}
		}
		return ConnectedMsg{Client: client}
	}
}

// ipcCmd wraps an IPC client method call into a tea.Cmd that reports a send
// failure as sendFailedMsg.
func ipcCmd(client *IPCClient, fn func(*IPCClient) error) tea.Cmd {
	return operationCmd(client, "", fn)
}

// operationCmd is ipcCmd for a request a screen waits on: a send failure
// carries the request's ID so it fails that request.
func operationCmd(client *IPCClient, id string, fn func(*IPCClient) error) tea.Cmd {
	return func() tea.Msg {
		if client == nil {
			return sendFailedMsg{ID: id, Error: fmt.Errorf("not connected")}
		}
		if err := fn(client); err != nil {
			return sendFailedMsg{ID: id, Error: err}
		}
		return nil
	}
}

// sendAuthCmd returns a tea.Cmd that sends an authentication request. The
// command keeps its own copy of the passphrase and zeroes it once it has run.
func (m Model) sendAuthCmd(passphrase []byte) tea.Cmd {
	return secretCmd(passphrase, func(p []byte) tea.Cmd {
		return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendAuth(p) })
	})
}

// sendUnlockCmd returns a tea.Cmd that sends an unlock request. The command
// keeps its own copy of the passphrase and zeroes it once it has run.
func (m Model) sendUnlockCmd(passphrase []byte) tea.Cmd {
	return secretCmd(passphrase, func(p []byte) tea.Cmd {
		return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendUnlock(p) })
	})
}

// secretCmd gives build a copy of secret to send and returns a command that
// runs the send and then zeroes the copy, so the caller can zero its own
// buffer at once. Every command that sends a secret is built through it: the
// copy belongs to the returned command, not to the send closure inside it, so
// it is zeroed even when that closure never runs, as when no client is
// connected.
func secretCmd(secret []byte, build func([]byte) tea.Cmd) tea.Cmd {
	owned := newSecretCopy(secret)
	send := build(owned)
	return func() tea.Msg {
		defer zeroBytes(owned)
		return send()
	}
}

// newSecretCopy makes the copy a secretCmd owns. Tests replace it to watch
// that copy.
var newSecretCopy = cloneBytes

// sendSignResponseCmd returns a tea.Cmd that sends a sign response
func (m Model) sendSignResponseCmd(requestID string, approved bool) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error {
		reason := ""
		if !approved {
			reason = "rejected by user"
		}
		return c.SendSignResponse(requestID, approved, reason)
	})
}

// sendClientEnrollmentResponseCmd returns a tea.Cmd that sends a client enrollment response
func (m Model) sendApproveEnrollmentCmd(fingerprint, label string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendApproveEnrollment(fingerprint, label) })
}

func (m Model) sendRejectEnrollmentCmd(fingerprint string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendRejectEnrollment(fingerprint) })
}

func (m Model) sendListPendingEnrollmentsCmd(id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendListPendingEnrollments(id) })
}

func (m Model) sendImportClientKeyCmd(publicKey, label string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendImportClientKey(publicKey, label) })
}

// listen starts the listener wait. Only Update calls it: after ConnectCmd's
// ConnectedMsg, and after handling each message the listener delivered. With
// no client there is nothing to wait on.
func (m Model) listen() tea.Cmd {
	if m.adminClient == nil {
		return nil
	}
	return m.adminClient.ListenForMessages()
}

// listenAgain starts the next wait after a message from the listener, unless
// that message ended the session (a displacement, a login timeout): nothing
// more comes on it, and the next connection starts listening afresh.
func (m Model) listenAgain() tea.Cmd {
	if m.connectionState == ConnectionDisconnected {
		return nil
	}
	return m.listen()
}

// SendDisplaceConfirm sends a displacement confirmation to the server
func (c *IPCClient) SendDisplaceConfirm() error {
	msg := DisplaceConfirmMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeDisplaceConfirm,
		},
	}
	return c.sendMessage(msg)
}

// SendDisplaceConfirmCmd returns a tea.Cmd that sends a displace confirm message
func (m Model) sendDisplaceConfirmCmd() tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendDisplaceConfirm() })
}

// SendListKeys sends a request to list all keys
func (c *IPCClient) SendListKeys() error {
	msg := ListKeysMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeListKeys,
			ID:   fmt.Sprintf("list-%d", time.Now().UnixNano()),
		},
	}
	return c.sendMessage(msg)
}

// SendBackup requests signer-managed creation of a backup archive. It zeroes
// its copy of the passphrase once sent; the caller zeroes its own.
func (c *IPCClient) SendBackup(exportPassphrase []byte, id string) error {
	msg := BackupMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeBackup,
			ID:   id,
		},
		ExportPassphrase: SensitiveBytes(cloneBytes(exportPassphrase)),
	}
	defer msg.ExportPassphrase.Zero()
	return c.sendMessage(msg)
}

// SendListBackups requests signer-managed backup archives for the active identity.
func (c *IPCClient) SendListBackups() error {
	msg := ListBackupsMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeListBackups,
			ID:   fmt.Sprintf("list-backups-%d", time.Now().UnixNano()),
		},
	}
	return c.sendMessage(msg)
}

// SendPreviewRestore requests a decrypted preview for a signer-managed backup archive.
func (c *IPCClient) SendPreviewRestore(archivePath string, exportPassphrase []byte, id string) error {
	passphrase := SensitiveBytes(append([]byte(nil), exportPassphrase...))
	defer passphrase.Zero()

	msg := PreviewRestoreMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypePreviewRestore,
			ID:   id,
		},
		ArchivePath:      archivePath,
		ExportPassphrase: passphrase,
	}
	return c.sendMessage(msg)
}

func (c *IPCClient) SendRestoreBackup(
	archivePath string,
	addresses []string,
	exportPassphrase []byte,
	replaceExisting bool,
	id string,
) error {
	passphrase := SensitiveBytes(append([]byte(nil), exportPassphrase...))
	defer passphrase.Zero()
	return c.sendMessage(RestoreBackupMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeRestoreBackup,
			ID:   id,
		},
		ArchivePath:      archivePath,
		Addresses:        append([]string(nil), addresses...),
		ExportPassphrase: passphrase,
		ReplaceExisting:  replaceExisting,
	})
}

func (c *IPCClient) SendRollbackRestore(id string) error {
	return c.sendMessage(RollbackRestoreMessage{BaseMessage: BaseMessage{
		Type: MsgTypeRollbackRestore,
		ID:   id,
	}})
}

func (c *IPCClient) SendReconcileStore(id string) error {
	return c.sendMessage(ReconcileStoreMessage{BaseMessage: BaseMessage{
		Type: MsgTypeReconcileStore,
		ID:   id,
	}})
}

// SendGenerateKey sends a request to generate a new key. params holds the
// creation parameters of a parameterized key type, such as a generic LogicSig,
// and is nil for any other.
func (c *IPCClient) SendGenerateKey(keyType string, params map[string]string, id string) error {
	msg := GenerateKeyMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeGenerateKey,
			ID:   id,
		},
		KeyType:    keyType,
		Parameters: params,
	}
	return c.sendMessage(msg)
}

// SendDeleteKey sends a request to delete a key
func (c *IPCClient) SendDeleteKey(address string, id string) error {
	msg := DeleteKeyMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeDeleteKey,
			ID:   id,
		},
		Address: address,
	}
	return c.sendMessage(msg)
}

// SendListKeysCmd returns a tea.Cmd that sends a list keys request
func (m Model) sendListKeysCmd() tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendListKeys() })
}

// sendGenerateKeyCmd returns a tea.Cmd that sends a generate key request.
func (m Model) sendGenerateKeyCmd(keyType string, params map[string]string, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendGenerateKey(keyType, params, id) })
}

// sendBackupCmd returns a tea.Cmd that requests a backup. The command keeps
// its own copy of the passphrase and zeroes it once it has run.
func (m Model) sendBackupCmd(exportPassphrase []byte, id string) tea.Cmd {
	return secretCmd(exportPassphrase, func(p []byte) tea.Cmd {
		return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendBackup(p, id) })
	})
}

func (m Model) sendListBackupsCmd() tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendListBackups() })
}

// sendPreviewRestoreCmd returns a tea.Cmd that requests a restore preview. The
// command keeps its own copy of the passphrase and zeroes it once it has run.
func (m Model) sendPreviewRestoreCmd(archivePath string, exportPassphrase []byte, id string) tea.Cmd {
	return secretCmd(exportPassphrase, func(p []byte) tea.Cmd {
		return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendPreviewRestore(archivePath, p, id) })
	})
}

// sendRestoreBackupCmd returns a tea.Cmd that requests a restore. The command
// keeps its own copy of the passphrase and zeroes it once it has run.
func (m Model) sendRestoreBackupCmd(
	archivePath string,
	addresses []string,
	exportPassphrase []byte,
	replaceExisting bool,
	id string,
) tea.Cmd {
	selectedAddresses := append([]string(nil), addresses...)
	return secretCmd(exportPassphrase, func(p []byte) tea.Cmd {
		return operationCmd(m.adminClient, id, func(c *IPCClient) error {
			return c.SendRestoreBackup(archivePath, selectedAddresses, p, replaceExisting, id)
		})
	})
}

func (m Model) sendRollbackRestoreCmd(id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendRollbackRestore(id) })
}

func (m Model) sendReconcileStoreCmd(id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendReconcileStore(id) })
}

// SendPrepareGenerateKey asks what a generation request would create.
func (c *IPCClient) SendPrepareGenerateKey(keyType string, params map[string]string, id string) error {
	return c.sendMessage(PrepareGenerateKeyMessage{
		BaseMessage: BaseMessage{Type: MsgTypePrepareGenerateKey, ID: id},
		KeyType:     keyType,
		Parameters:  params,
	})
}

func (m Model) sendPrepareGenerateKeyCmd(keyType string, params map[string]string, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendPrepareGenerateKey(keyType, params, id) })
}

// SendReviewedGenerateKey generates the account an operator reviewed.
func (c *IPCClient) SendReviewedGenerateKey(review PrepareGenerateResultMessage, id string) error {
	return c.sendMessage(reviewedGenerateMessage(review, id))
}

// reviewedGenerateMessage carries the resolved values, not the original request.
func reviewedGenerateMessage(review PrepareGenerateResultMessage, id string) GenerateKeyMessage {
	return GenerateKeyMessage{
		BaseMessage:            BaseMessage{Type: MsgTypeGenerateKey, ID: id},
		KeyType:                review.KeyType,
		Parameters:             review.Parameters,
		ExpectedFingerprint:    review.ReviewFingerprint,
		ExpectedBoundaryDigest: review.BoundaryDigest,
	}
}

func (m Model) sendReviewedGenerateKeyCmd(review PrepareGenerateResultMessage, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendReviewedGenerateKey(review, id) })
}

// SendDeleteKeyCmd returns a tea.Cmd that sends a delete key request
func (m Model) sendDeleteKeyCmd(address, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendDeleteKey(address, id) })
}

// SendListEnrolledKeys asks for the enrolled client keys.
func (c *IPCClient) SendListEnrolledKeys(id string) error {
	return c.sendMessage(ListEnrolledKeysMessage{BaseMessage: BaseMessage{
		Type: MsgTypeListEnrolledKeys,
		ID:   id,
	}})
}

// SendRevokeEnrolledKey revokes one enrolled client key.
func (c *IPCClient) SendRevokeEnrolledKey(fingerprint string) error {
	return c.sendMessage(RevokeEnrolledKeyMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeRevokeEnrolledKey,
			ID:   fmt.Sprintf("revoke-%d", time.Now().UnixNano()),
		},
		Fingerprint: fingerprint,
	})
}

// SendRevokeAllEnrolledKeys revokes every enrolled client key.
func (c *IPCClient) SendRevokeAllEnrolledKeys() error {
	return c.sendMessage(RevokeAllEnrolledKeysMessage{BaseMessage: BaseMessage{
		Type: MsgTypeRevokeAllEnrolledKeys,
		ID:   fmt.Sprintf("revoke-all-%d", time.Now().UnixNano()),
	}})
}

func (m Model) sendListEnrolledKeysCmd(id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendListEnrolledKeys(id) })
}

func (m Model) sendRevokeEnrolledKeyCmd(fingerprint string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendRevokeEnrolledKey(fingerprint) })
}

func (m Model) sendRevokeAllEnrolledKeysCmd() tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendRevokeAllEnrolledKeys() })
}

// SendImportKeyWithParams sends a request to import a key; params is nil for a
// key type that takes none.
func (c *IPCClient) SendImportKeyWithParams(keyType, mnemonic string, params map[string]string, id string) error {
	msg := ImportKeyMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeImportKey,
			ID:   id,
		},
		KeyType:    keyType,
		Mnemonic:   SensitiveBytes(mnemonic),
		Parameters: params,
	}
	defer msg.Mnemonic.Zero()
	return c.sendMessage(msg)
}

// sendImportKeyCmd returns a tea.Cmd that sends an import request for a key
// type that takes no parameters.
func (m Model) sendImportKeyCmd(keyType, mnemonic, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendImportKeyWithParams(keyType, mnemonic, nil, id) })
}

// SendImportKeyWithParamsCmd returns a tea.Cmd that sends an import key request with parameters.
func (m Model) sendImportKeyWithParamsCmd(keyType, mnemonic string, params map[string]string, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendImportKeyWithParams(keyType, mnemonic, params, id) })
}

// SendGetAdminSettings sends a request to get the current admin settings
func (c *IPCClient) SendGetAdminSettings() error {
	msg := GetAdminSettingsMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeGetAdminSettings,
			ID:   fmt.Sprintf("admin-%d", time.Now().UnixNano()),
		},
	}
	return c.sendMessage(msg)
}

// SendUpdateAdminSetting sends a request to update a single admin setting
func (c *IPCClient) SendUpdateAdminSetting(key, value string) error {
	msg := UpdateAdminSettingMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeUpdateAdminSetting,
			ID:   fmt.Sprintf("admin-set-%d", time.Now().UnixNano()),
		},
		Key:   key,
		Value: value,
	}
	return c.sendMessage(msg)
}

// SendGetAdminSettingsCmd returns a tea.Cmd that requests admin settings
func (m Model) sendGetAdminSettingsCmd() tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendGetAdminSettings() })
}

// SendUpdateAdminSettingCmd returns a tea.Cmd that updates an admin setting
func (m Model) sendUpdateAdminSettingCmd(key, value string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendUpdateAdminSetting(key, value) })
}

// SendGetKeyDetails sends a request to get detailed information about a key
func (c *IPCClient) SendGetKeyDetails(address string) error {
	msg := GetKeyDetailsMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeGetKeyDetails,
			ID:   fmt.Sprintf("details-%d", time.Now().UnixNano()),
		},
		Address: address,
	}
	return c.sendMessage(msg)
}

// SendGetKeyDetailsCmd returns a tea.Cmd that sends a get key details request
func (m Model) sendGetKeyDetailsCmd(address string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendGetKeyDetails(address) })
}

func (c *IPCClient) SendListLibraryTemplates() error {
	msg := ListLibraryTemplatesMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeListLibraryTemplates,
			ID:   fmt.Sprintf("tmpl-list-%d", time.Now().UnixNano()),
		},
	}
	return c.sendMessage(msg)
}

func (m Model) sendListLibraryTemplatesCmd() tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendListLibraryTemplates() })
}

func (c *IPCClient) SendInstallLibraryTemplate(keyType, templateType string, id string) error {
	msg := InstallLibraryTemplateMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeInstallLibraryTemplate,
			ID:   id,
		},
		KeyType:      keyType,
		TemplateType: templateType,
	}
	return c.sendMessage(msg)
}

func (m Model) sendInstallLibraryTemplateCmd(keyType, templateType, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendInstallLibraryTemplate(keyType, templateType, id) })
}

func (c *IPCClient) SendShowLibraryTemplate(keyType, templateType, id string) error {
	msg := ShowLibraryTemplateMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeShowLibraryTemplate,
			ID:   id,
		},
		KeyType:      keyType,
		TemplateType: templateType,
	}
	return c.sendMessage(msg)
}

func (c *IPCClient) SendShowInstalledTemplate(keyType, id string) error {
	msg := ShowInstalledTemplateMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeShowInstalledTemplate,
			ID:   id,
		},
		KeyType: keyType,
	}
	return c.sendMessage(msg)
}

func (m Model) sendShowInstalledTemplateCmd(keyType, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendShowInstalledTemplate(keyType, id) })
}

func (m Model) sendShowLibraryTemplateCmd(keyType, templateType, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendShowLibraryTemplate(keyType, templateType, id) })
}

func (c *IPCClient) SendActivateKeyType(keyType string, id string) error {
	msg := ActivateKeyTypeMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeActivateKeyType,
			ID:   id,
		},
		KeyType: keyType,
	}
	return c.sendMessage(msg)
}

func (m Model) sendActivateKeyTypeCmd(keyType, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendActivateKeyType(keyType, id) })
}

func (c *IPCClient) SendDeactivateKeyType(keyType string, id string) error {
	msg := DeactivateKeyTypeMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeDeactivateKeyType,
			ID:   id,
		},
		KeyType: keyType,
	}
	return c.sendMessage(msg)
}

func (m Model) sendDeactivateKeyTypeCmd(keyType, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendDeactivateKeyType(keyType, id) })
}

func (c *IPCClient) SendListKeyTypes() error {
	msg := ListKeyTypesMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeListKeyTypes,
			ID:   fmt.Sprintf("keytypes-%d", time.Now().UnixNano()),
		},
	}
	return c.sendMessage(msg)
}

func (m Model) sendListKeyTypesCmd() tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendListKeyTypes() })
}

func (c *IPCClient) SendListCosignerReferences() error {
	msg := ListCosignerReferencesMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeListCosignerReferences,
			ID:   fmt.Sprintf("cosigner-references-%d", time.Now().UnixNano()),
		},
	}
	return c.sendMessage(msg)
}

func (m Model) sendListCosignerReferencesCmd() tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendListCosignerReferences() })
}

func (c *IPCClient) SendImportCosignerReference(name, envelopeJSON, id string) error {
	msg := ImportCosignerReferenceMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeImportCosignerReference,
			ID:   id,
		},
		Name:         name,
		EnvelopeJSON: envelopeJSON,
	}
	return c.sendMessage(msg)
}

func (m Model) sendImportCosignerReferenceCmd(name, envelopeJSON, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error {
		return c.SendImportCosignerReference(name, envelopeJSON, id)
	})
}

func (c *IPCClient) SendRemoveCosignerReference(name, id string) error {
	msg := RemoveCosignerReferenceMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeRemoveCosignerReference,
			ID:   id,
		},
		Name: name,
	}
	return c.sendMessage(msg)
}

func (m Model) sendRemoveCosignerReferenceCmd(name, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error {
		return c.SendRemoveCosignerReference(name, id)
	})
}

func (c *IPCClient) SendExportCosignerPublic(witnessKeyID, id string) error {
	msg := ExportCosignerPublicMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeExportCosignerPublic,
			ID:   id,
		},
		WitnessKeyID: witnessKeyID,
	}
	return c.sendMessage(msg)
}

func (m Model) sendExportCosignerPublicCmd(witnessKeyID, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error {
		return c.SendExportCosignerPublic(witnessKeyID, id)
	})
}

// ReconnectCmd returns a tea.Cmd that forces a reconnection attempt
func (m Model) reconnectCmd() tea.Cmd {
	return func() tea.Msg {
		// Close existing client if any
		if m.adminClient != nil {
			m.adminClient.Disconnect()
		}

		// Create new client and connect
		client := NewAdminClient(m.connector)
		if m.adminClient != nil {
			client.notificationLoss = m.adminClient.notificationLoss
		}

		if err := client.Connect(); err != nil {
			return DisconnectedMsg{Error: err}
		}
		return ConnectedMsg{Client: client}
	}
}

func (m Model) disconnectAdminClient() {
	if m.adminClient != nil {
		m.adminClient.Disconnect()
	}
}
