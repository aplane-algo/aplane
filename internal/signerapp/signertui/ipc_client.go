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

	// Done channel for shutdown
	done chan struct{}

	// Session token increments whenever a new connection lifecycle starts.
	sessionID uint64

	// Displacement state
	displaced bool // True when displaced by another client (suppress reconnect)

	// Reconnection state
	reconnecting   bool
	reconnectDelay time.Duration
	maxDelay       time.Duration
}

// NewAdminClient creates a new admin client for an arbitrary transport.
func NewAdminClient(connector AdminConnector) *IPCClient {
	return &IPCClient{
		connector:      connector,
		msgChan:        make(chan queuedMsg, 10),
		done:           make(chan struct{}),
		reconnectDelay: 1 * time.Second,
		maxDelay:       30 * time.Second,
	}
}

// Connect establishes the IPC connection
func (c *IPCClient) Connect() error {
	c.mu.Lock()

	if c.connected {
		c.mu.Unlock()
		return nil
	}

	c.done = make(chan struct{})
	c.sessionID++
	sessionID := c.sessionID

	conn, err := c.connector.Connect()
	if err != nil {
		c.done = nil
		c.mu.Unlock()
		return err
	}

	c.conn = conn
	c.stream = transport.NewStreamClient(conn)
	c.connected = true
	c.displaced = false
	done := c.done
	c.mu.Unlock()

	// Start message reader goroutine
	go c.forwardMessages(sessionID, done, c.stream.Notifications(), c.stream.LifecycleEvents())

	return nil
}

// Disconnect closes the IPC connection
func (c *IPCClient) Disconnect() {
	c.mu.Lock()
	if !c.connected && c.done == nil {
		c.mu.Unlock()
		return
	}

	done := c.done
	conn := c.conn
	stream := c.stream
	c.done = nil
	c.conn = nil
	c.stream = nil
	c.connected = false
	c.displaced = false
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
}

// SendAuth sends an authentication request
func (c *IPCClient) SendAuth(passphrase string) error {
	protocolVersion := CurrentAdminProtocolVersion()
	msg := AuthMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeAuth,
			ID:   fmt.Sprintf("auth-%d", time.Now().UnixNano()),
		},
		Passphrase:      SensitiveBytes([]byte(passphrase)),
		ProtocolVersion: &protocolVersion,
	}
	return c.sendMessage(msg)
}

// SendUnlock sends an unlock request
func (c *IPCClient) SendUnlock(passphrase string) error {
	msg := UnlockMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeUnlock,
			ID:   fmt.Sprintf("unlock-%d", time.Now().UnixNano()),
		},
		Passphrase: SensitiveBytes([]byte(passphrase)),
	}
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

// SendTokenProvisioningResponse sends a token provisioning approval/rejection
func (c *IPCClient) SendTokenProvisioningResponse(requestID string, approved bool, reason string) error {
	msg := TokenProvisioningResponseMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeTokenProvisioningResponse,
			ID:   requestID,
		},
		Approved: approved,
		Reason:   reason,
	}
	return c.sendMessage(msg)
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
	c.mu.Lock()
	currentSession := c.sessionID
	done := c.done
	c.mu.Unlock()

	if currentSession > sessionID || done == nil {
		return false
	}

	// Select on the session's done channel so a forwarder blocked on a full,
	// undrained msgChan (e.g. the TUI went away) unblocks on teardown instead
	// of leaking.
	select {
	case <-done:
		return false
	case c.msgChan <- queuedMsg{sessionID: sessionID, msg: msg}:
		return true
	}
}

// forwardMessages receives dispatcher notifications/lifecycle events and
// forwards them to the TUI while preserving reconnect/displacement semantics.
func (c *IPCClient) forwardMessages(sessionID uint64, done <-chan struct{}, notifications <-chan transport.Notification, lifecycle <-chan transport.LifecycleEvent) {
	defer func() {
		c.mu.Lock()
		if c.sessionID != sessionID {
			c.mu.Unlock()
			return
		}
		c.connected = false
		c.conn = nil
		c.stream = nil
		displaced := c.displaced
		c.mu.Unlock()

		if displaced {
			// DisplacedMsg was already sent; don't send a redundant DisconnectedMsg
			// and don't auto-reconnect
			return
		}

		go c.reconnect(sessionID, done)
	}()

	for {
		select {
		case <-done:
			return
		case event, ok := <-lifecycle:
			if !ok {
				return
			}
			switch event.Type {
			case transport.LifecycleConnectionLost:
				if event.Err != nil && !errors.Is(event.Err, io.EOF) {
					c.emit(sessionID, ErrorMsg{Error: event.Err})
				}
				return
			case transport.LifecycleProtocolError:
				c.emit(sessionID, ErrorMsg{Error: fmt.Errorf("protocol error: %w", event.Err)})
				return
			case transport.LifecycleReaderStopped:
				return
			default:
				continue
			}
		case notification, ok := <-notifications:
			if !ok {
				return
			}
			line := notification.Raw
			switch notification.Base.Type {
			case MsgTypeAuthRequired:
				// Server requires authentication before any other operations
				c.emit(sessionID, AuthRequiredMsg{})

			case MsgTypeAuthResult:
				var authResult AuthResultMessage
				if err := json.Unmarshal(line, &authResult); err != nil {
					continue
				}
				c.emit(sessionID, AuthResultMsg{
					Success: authResult.Success,
					Code:    authResult.Code,
					Error:   authResult.Error,
				})

			case MsgTypeStatus:
				var status StatusMessage
				if err := json.Unmarshal(line, &status); err != nil {
					continue
				}
				c.emit(sessionID, SignerStatusMsg{
					State:    status.State,
					KeyCount: status.KeyCount,
				})

			case MsgTypeUnlockResult:
				var result UnlockResultMessage
				if err := json.Unmarshal(line, &result); err != nil {
					continue
				}
				c.emit(sessionID, UnlockResultMsg{
					Success:  result.Success,
					KeyCount: result.KeyCount,
					Code:     result.Code,
					Error:    result.Error,
				})

			case MsgTypeLockIdentityResult:
				var result LockIdentityResultMessage
				if err := json.Unmarshal(line, &result); err != nil {
					continue
				}
				c.emit(sessionID, LockIdentityResultMsg{
					Success: result.Success,
					Error:   result.Error,
				})

			case MsgTypeSignRequest:
				var req SignRequestMessage
				if err := json.Unmarshal(line, &req); err != nil {
					continue
				}
				c.emit(sessionID, SignRequestReceivedMsg{
					Request: PendingSignRequest{
						ID:          req.ID,
						Address:     req.Address,
						TxnSender:   req.TxnSender,
						Description: req.Description,
						Timestamp:   time.Unix(req.Timestamp, 0),
						FirstValid:  req.FirstValid,
						LastValid:   req.LastValid,
						Violations:  req.Violations,
					},
				})

			case MsgTypeSignRequestCanceled:
				var canceled SignRequestCanceledMessage
				if err := json.Unmarshal(line, &canceled); err != nil {
					continue
				}
				c.emit(sessionID, SignRequestCanceledMsg{
					ID:     canceled.ID,
					Reason: canceled.Reason,
				})

			case MsgTypeError:
				var errMsg ErrorMessage
				if err := json.Unmarshal(line, &errMsg); err != nil {
					continue
				}
				c.emit(sessionID, ErrorMsg{Error: fmt.Errorf("%s", errMsg.Error)})

			case MsgTypeKeysList:
				var keysList KeysListMessage
				if err := json.Unmarshal(line, &keysList); err != nil {
					continue
				}
				keys := make([]KeyInfo, 0, len(keysList.Keys))
				for _, k := range keysList.Keys {
					keys = append(keys, KeyInfo{
						Address:                  k.Address,
						KeyType:                  k.KeyType,
						TemplateProvenanceStatus: k.TemplateProvenanceStatus,
						TemplateProvenanceNote:   k.TemplateProvenanceNote,
					})
				}
				c.emit(sessionID, KeysListMsg{Keys: keys})

			case MsgTypeGenerateResult:
				var genResult GenerateResultMessage
				if err := json.Unmarshal(line, &genResult); err != nil {
					continue
				}
				c.emit(sessionID, GenerateResultMsg{
					Success: genResult.Success,
					Address: genResult.Address,
					KeyType: genResult.KeyType,
					Error:   genResult.Error,
				})

			case MsgTypeBackupResult:
				var backupResult BackupResultMessage
				if err := json.Unmarshal(line, &backupResult); err != nil {
					continue
				}
				c.emit(sessionID, BackupResultMsg{
					Success:     backupResult.Success,
					ArchivePath: backupResult.ArchivePath,
					SkippedKeys: backupResult.SkippedKeys,
					Error:       backupResult.Error,
				})

			case MsgTypeBackupsList:
				var backupsList BackupsListMessage
				if err := json.Unmarshal(line, &backupsList); err != nil {
					continue
				}
				c.emit(sessionID, BackupsListMsg{
					Backups: backupsList.Backups,
					Error:   backupsList.Error,
				})

			case MsgTypeRestorePreview:
				var preview RestorePreviewMessage
				if err := json.Unmarshal(line, &preview); err != nil {
					continue
				}
				c.emit(sessionID, RestorePreviewMsg{
					ArchivePath: preview.ArchivePath,
					Keys:        preview.Keys,
					Errors:      preview.Errors,
					Error:       preview.Error,
				})

			case MsgTypeRecoverBackupResult:
				var recovered RecoverBackupResultMessage
				if err := json.Unmarshal(line, &recovered); err != nil {
					continue
				}
				c.emit(sessionID, RecoverBackupResultMsg{
					Success:   recovered.Success,
					RestoreID: recovered.RestoreID,
					Error:     recovered.Error,
				})

			case MsgTypeReviewRecoveredResult:
				var review ReviewRecoveredResultMessage
				if err := json.Unmarshal(line, &review); err != nil {
					continue
				}
				c.emit(sessionID, ReviewRecoveredResultMsg{Result: review})

			case MsgTypeActivateRecoveredResult:
				var activated ActivateRecoveredResultMessage
				if err := json.Unmarshal(line, &activated); err != nil {
					continue
				}
				c.emit(sessionID, ActivateRecoveredResultMsg{Result: activated})

			case MsgTypeDeleteResult:
				var delResult DeleteResultMessage
				if err := json.Unmarshal(line, &delResult); err != nil {
					continue
				}
				c.emit(sessionID, DeleteResultMsg{
					Success: delResult.Success,
					Error:   delResult.Error,
				})

			case MsgTypeRevokeTokenResult:
				var revokeResult RevokeTokenResultMessage
				if err := json.Unmarshal(line, &revokeResult); err != nil {
					continue
				}
				c.emit(sessionID, RevokeTokenResultMsg{
					Success: revokeResult.Success,
					Error:   revokeResult.Error,
				})

			case MsgTypeImportResult:
				var impResult ImportResultMessage
				if err := json.Unmarshal(line, &impResult); err != nil {
					continue
				}
				c.emit(sessionID, ImportResultMsg{
					Success: impResult.Success,
					Address: impResult.Address,
					KeyType: impResult.KeyType,
					Error:   impResult.Error,
				})

			case MsgTypeKeyDetails:
				var detailsResult KeyDetailsMessage
				if err := json.Unmarshal(line, &detailsResult); err != nil {
					continue
				}
				c.emit(sessionID, KeyDetailsMsg{
					Success:                  detailsResult.Success,
					Address:                  detailsResult.Address,
					KeyType:                  detailsResult.KeyType,
					PublicKeyHex:             detailsResult.PublicKeyHex,
					Parameters:               detailsResult.Parameters,
					DisplayTEAL:              detailsResult.DisplayTEAL,
					TemplateProvenanceStatus: detailsResult.TemplateProvenanceStatus,
					TemplateProvenanceNote:   detailsResult.TemplateProvenanceNote,
					Error:                    detailsResult.Error,
				})

			case MsgTypeLibraryTemplates:
				var library LibraryTemplatesMessage
				if err := json.Unmarshal(line, &library); err != nil {
					continue
				}
				c.emit(sessionID, LibraryTemplatesMsg{
					Templates: library.Templates,
					Error:     library.Error,
				})

			case MsgTypeInstallLibraryTemplateResult:
				var result InstallLibraryTemplateResultMessage
				if err := json.Unmarshal(line, &result); err != nil {
					continue
				}
				c.emit(sessionID, InstallLibraryTemplateResultMsg{
					Success:       result.Success,
					KeyType:       result.KeyType,
					TemplateType:  result.TemplateType,
					AlreadyExists: result.AlreadyExists,
					Error:         result.Error,
				})

			case MsgTypeShowLibraryTemplateResult:
				var result ShowLibraryTemplateResultMessage
				if err := json.Unmarshal(line, &result); err != nil {
					continue
				}
				c.emit(sessionID, ShowLibraryTemplateResultMsg{
					Success:       result.Success,
					KeyType:       result.KeyType,
					TemplateType:  result.TemplateType,
					SourcePath:    result.SourcePath,
					SourceSHA256:  result.SourceSHA256,
					SourceModTime: result.SourceModTime,
					TemplateYAML:  result.TemplateYAML,
					Error:         result.Error,
				})

			case MsgTypeActivateKeyTypeResult:
				var result ActivateKeyTypeResultMessage
				if err := json.Unmarshal(line, &result); err != nil {
					continue
				}
				c.emit(sessionID, ActivateKeyTypeResultMsg{
					Success:       result.Success,
					KeyType:       result.KeyType,
					AlreadyExists: result.AlreadyExists,
					Error:         result.Error,
				})

			case MsgTypeDeactivateKeyTypeResult:
				var result DeactivateKeyTypeResultMessage
				if err := json.Unmarshal(line, &result); err != nil {
					continue
				}
				c.emit(sessionID, DeactivateKeyTypeResultMsg{
					Success: result.Success,
					KeyType: result.KeyType,
					Removed: result.Removed,
					Error:   result.Error,
				})

			case MsgTypeKeyTypes:
				var keyTypes KeyTypesMessage
				if err := json.Unmarshal(line, &keyTypes); err != nil {
					continue
				}
				c.emit(sessionID, KeyTypesMsg{
					KeyTypes: keyTypes.KeyTypes,
					Error:    keyTypes.Error,
				})

			case MsgTypeKeysChanged:
				var keysChanged KeysChangedMessage
				if err := json.Unmarshal(line, &keysChanged); err != nil {
					continue
				}
				c.emit(sessionID, KeysChangedMsg{
					KeyCount: keysChanged.KeyCount,
				})

			case MsgTypeSignerLocked:
				// Server locked - transition to unlock screen.
				c.emit(sessionID, SignerStatusMsg{
					State:    "locked",
					KeyCount: 0,
				})

			case MsgTypeRecoveredList:
				var list RecoveredListMessage
				if err := json.Unmarshal(line, &list); err != nil {
					continue
				}
				c.emit(sessionID, RecoveredListMsg{
					Batches: list.Batches,
					Code:    list.Code,
					Error:   list.Error,
				})

			case MsgTypePurgeRecoveredResult:
				var result PurgeRecoveredResultMessage
				if err := json.Unmarshal(line, &result); err != nil {
					continue
				}
				c.emit(sessionID, PurgeRecoveredResultMsg{Result: result})

			case MsgTypeTokenProvisioningRequest:
				var req TokenProvisioningRequestMessage
				if err := json.Unmarshal(line, &req); err != nil {
					continue
				}
				c.emit(sessionID, TokenProvisioningRequestReceivedMsg{
					Request: PendingTokenRequest{
						ID:             req.ID,
						IdentityID:     req.IdentityID,
						SSHFingerprint: req.SSHFingerprint,
						RemoteAddr:     req.RemoteAddr,
						Timestamp:      time.Unix(req.Timestamp, 0),
					},
				})

			case MsgTypeAdminSettings:
				var settings AdminSettingsMessage
				if err := json.Unmarshal(line, &settings); err != nil {
					continue
				}
				c.emit(sessionID, AdminSettingsMsg{
					Settings: AdminSettings{
						UserAutoApprove:      settings.UserAutoApprove,
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
					},
				})

			case MsgTypeUpdateAdminSettingResult:
				var result UpdateAdminSettingResultMessage
				if err := json.Unmarshal(line, &result); err != nil {
					continue
				}
				c.emit(sessionID, AdminSettingUpdatedMsg{
					Success: result.Success,
					Key:     result.Key,
					Value:   result.Value,
					Error:   result.Error,
				})

			case MsgTypeClientExists:
				c.emit(sessionID, ClientExistsMsg{})

			case MsgTypeDisplaced:
				var displaced DisplacedMessage
				if err := json.Unmarshal(line, &displaced); err != nil {
					continue
				}
				c.mu.Lock()
				c.displaced = true
				c.mu.Unlock()
				c.emit(sessionID, DisplacedMsg{Reason: displaced.Reason})
				return
			}
		}
	}
}

// reconnect attempts to reconnect with exponential backoff
func (c *IPCClient) reconnect(sessionID uint64, done <-chan struct{}) {
	c.mu.Lock()
	if c.reconnecting || c.sessionID != sessionID {
		c.mu.Unlock()
		return
	}
	c.reconnecting = true
	delay := c.reconnectDelay
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
			// Success - reset delay and exit
			c.mu.Lock()
			c.reconnecting = false
			c.reconnectDelay = 1 * time.Second
			newSessionID := c.sessionID
			c.mu.Unlock()

			c.emit(newSessionID, ConnectedMsg{})
			return
		}

		// Failed - increase delay with exponential backoff
		c.mu.Lock()
		delay = delay * 2
		if delay > c.maxDelay {
			delay = c.maxDelay
		}
		c.mu.Unlock()

	}
}

// ListenForMessages returns a tea.Cmd that listens for IPC messages
func (c *IPCClient) ListenForMessages() tea.Cmd {
	return func() tea.Msg {
		for {
			c.mu.Lock()
			done := c.done
			currentSession := c.sessionID
			c.mu.Unlock()

			select {
			case queued := <-c.msgChan:
				if queued.sessionID < currentSession {
					continue
				}
				return queued.msg
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

// ipcCmd wraps an IPC client method call into a tea.Cmd with nil-check and error handling.
func ipcCmd(client *IPCClient, fn func(*IPCClient) error) tea.Cmd {
	return func() tea.Msg {
		if client == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}
		if err := fn(client); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
}

// SendAuthCmd returns a tea.Cmd that sends an authentication request
func (m Model) sendAuthCmd(passphrase string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendAuth(passphrase) })
}

// SendUnlockCmd returns a tea.Cmd that sends an unlock request
func (m Model) sendUnlockCmd(passphrase string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendUnlock(passphrase) })
}

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

// sendTokenProvisioningResponseCmd returns a tea.Cmd that sends a token provisioning response
func (m Model) sendTokenProvisioningResponseCmd(requestID string, approved bool) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error {
		reason := ""
		if !approved {
			reason = "rejected by user"
		}
		return c.SendTokenProvisioningResponse(requestID, approved, reason)
	})
}

// WaitForMessageCmd returns a tea.Cmd that waits for the next message
func (m Model) waitForMessageCmd() tea.Cmd {
	return func() tea.Msg {
		if m.adminClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}
		return m.adminClient.ListenForMessages()()
	}
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

// SendGenerateKey sends a request to generate a new key
func (c *IPCClient) SendGenerateKey(keyType, name string) error {
	msg := GenerateKeyMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeGenerateKey,
			ID:   fmt.Sprintf("gen-%d", time.Now().UnixNano()),
		},
		KeyType: keyType,
		Name:    name,
	}
	return c.sendMessage(msg)
}

// SendBackup requests signer-managed creation of a backup archive.
func (c *IPCClient) SendBackup(exportPassphrase string) error {
	msg := BackupMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeBackup,
			ID:   fmt.Sprintf("backup-%d", time.Now().UnixNano()),
		},
		ExportPassphrase: SensitiveBytes([]byte(exportPassphrase)),
	}
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
func (c *IPCClient) SendPreviewRestore(archivePath string, exportPassphrase []byte) error {
	passphrase := SensitiveBytes(append([]byte(nil), exportPassphrase...))
	defer passphrase.Zero()

	msg := PreviewRestoreMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypePreviewRestore,
			ID:   fmt.Sprintf("preview-restore-%d", time.Now().UnixNano()),
		},
		ArchivePath:      archivePath,
		ExportPassphrase: passphrase,
	}
	return c.sendMessage(msg)
}

// SendRecoverBackup publishes selected archive entries as one inactive batch.
func (c *IPCClient) SendRecoverBackup(archivePath string, addresses []string, exportPassphrase []byte) error {
	passphrase := SensitiveBytes(append([]byte(nil), exportPassphrase...))
	defer passphrase.Zero()
	return c.sendMessage(RecoverBackupMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeRecoverBackup,
			ID:   fmt.Sprintf("recover-backup-%d", time.Now().UnixNano()),
		},
		ArchivePath:      archivePath,
		Addresses:        append([]string(nil), addresses...),
		ExportPassphrase: passphrase,
	})
}

// SendReviewRecovered requests the current destination-bound activation review.
func (c *IPCClient) SendReviewRecovered(restoreID string) error {
	return c.sendMessage(ReviewRecoveredMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeReviewRecovered,
			ID:   fmt.Sprintf("review-recovered-%d", time.Now().UnixNano()),
		},
		RestoreID: restoreID,
	})
}

// SendActivateRecovered submits the exact reviewed intent and acknowledgement.
func (c *IPCClient) SendActivateRecovered(
	restoreID, reviewToken string,
	unattendedAcknowledged, replaceExisting bool,
) error {
	return c.sendMessage(ActivateRecoveredMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeActivateRecovered,
			ID:   fmt.Sprintf("activate-recovered-%d", time.Now().UnixNano()),
		},
		RestoreID:                    restoreID,
		ReviewToken:                  reviewToken,
		AcknowledgeUnattendedSigning: unattendedAcknowledged,
		ReplaceExisting:              replaceExisting,
	})
}

// SendListRecovered requests the recovered-batch inventory. Reopening a
// batch from that inventory never requires the archive export passphrase.
func (c *IPCClient) SendListRecovered() error {
	return c.sendMessage(ListRecoveredMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeListRecovered,
			ID:   fmt.Sprintf("list-recovered-%d", time.Now().UnixNano()),
		},
	})
}

// SendPurgeRecovered requests deletion of one inactive recovered batch.
func (c *IPCClient) SendPurgeRecovered(restoreID string) error {
	return c.sendMessage(PurgeRecoveredMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypePurgeRecovered,
			ID:   fmt.Sprintf("purge-recovered-%d", time.Now().UnixNano()),
		},
		RestoreID: restoreID,
	})
}

// SendGenerateKeyWithParams sends a request to generate a new key with parameters
// Used for generic LogicSigs like timelock that require additional configuration
func (c *IPCClient) SendGenerateKeyWithParams(keyType, name string, params map[string]string) error {
	msg := GenerateKeyMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeGenerateKey,
			ID:   fmt.Sprintf("gen-%d", time.Now().UnixNano()),
		},
		KeyType:    keyType,
		Name:       name,
		Parameters: params,
	}
	return c.sendMessage(msg)
}

// SendDeleteKey sends a request to delete a key
func (c *IPCClient) SendDeleteKey(address string) error {
	msg := DeleteKeyMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeDeleteKey,
			ID:   fmt.Sprintf("del-%d", time.Now().UnixNano()),
		},
		Address: address,
	}
	return c.sendMessage(msg)
}

// SendListKeysCmd returns a tea.Cmd that sends a list keys request
func (m Model) sendListKeysCmd() tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendListKeys() })
}

// SendGenerateKeyCmd returns a tea.Cmd that sends a generate key request
func (m Model) sendGenerateKeyCmd(keyType, name string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendGenerateKey(keyType, name) })
}

func (m Model) sendBackupCmd(exportPassphrase string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendBackup(exportPassphrase) })
}

func (m Model) sendListBackupsCmd() tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendListBackups() })
}

func (m Model) sendPreviewRestoreCmd(archivePath string, exportPassphrase []byte) tea.Cmd {
	passphrase := cloneBytes(exportPassphrase)
	return func() tea.Msg {
		defer zeroBytes(passphrase)
		if m.adminClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}
		if err := m.adminClient.SendPreviewRestore(archivePath, passphrase); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
}

func (m Model) sendRecoverBackupCmd(archivePath string, addresses []string, exportPassphrase []byte) tea.Cmd {
	passphrase := cloneBytes(exportPassphrase)
	selectedAddresses := append([]string(nil), addresses...)
	return func() tea.Msg {
		defer zeroBytes(passphrase)
		if m.adminClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}
		if err := m.adminClient.SendRecoverBackup(archivePath, selectedAddresses, passphrase); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
}

func (m Model) sendReviewRecoveredCmd(restoreID string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error {
		return c.SendReviewRecovered(restoreID)
	})
}

func (m Model) sendActivateRecoveredCmd(
	restoreID, reviewToken string,
	unattendedAcknowledged, replaceExisting bool,
) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error {
		return c.SendActivateRecovered(
			restoreID,
			reviewToken,
			unattendedAcknowledged,
			replaceExisting,
		)
	})
}

func (m Model) sendListRecoveredCmd() tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error {
		return c.SendListRecovered()
	})
}

func (m Model) sendPurgeRecoveredCmd(restoreID string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error {
		return c.SendPurgeRecovered(restoreID)
	})
}

// SendGenerateKeyWithParamsCmd returns a tea.Cmd that sends a generate key request with parameters
func (m Model) sendGenerateKeyWithParamsCmd(keyType, name string, params map[string]string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendGenerateKeyWithParams(keyType, name, params) })
}

// SendDeleteKeyCmd returns a tea.Cmd that sends a delete key request
func (m Model) sendDeleteKeyCmd(address string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendDeleteKey(address) })
}

// SendRevokeToken sends a request to revoke and regenerate the API token
func (c *IPCClient) SendRevokeToken() error {
	msg := RevokeTokenMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeRevokeToken,
			ID:   fmt.Sprintf("revoke-%d", time.Now().UnixNano()),
		},
	}
	return c.sendMessage(msg)
}

// SendRevokeTokenCmd returns a tea.Cmd that sends a revoke token request
func (m Model) sendRevokeTokenCmd() tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendRevokeToken() })
}

// SendImportKey sends a request to import a key from mnemonic
func (c *IPCClient) SendImportKey(keyType, mnemonic string) error {
	msg := ImportKeyMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeImportKey,
			ID:   fmt.Sprintf("imp-%d", time.Now().UnixNano()),
		},
		KeyType:  keyType,
		Mnemonic: mnemonic,
	}
	return c.sendMessage(msg)
}

// SendImportKeyWithParams sends a request to import a key with additional parameters.
func (c *IPCClient) SendImportKeyWithParams(keyType, mnemonic string, params map[string]string) error {
	msg := ImportKeyMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeImportKey,
			ID:   fmt.Sprintf("imp-%d", time.Now().UnixNano()),
		},
		KeyType:    keyType,
		Mnemonic:   mnemonic,
		Parameters: params,
	}
	return c.sendMessage(msg)
}

// SendImportKeyCmd returns a tea.Cmd that sends an import key request
func (m Model) sendImportKeyCmd(keyType, mnemonic string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendImportKey(keyType, mnemonic) })
}

// SendImportKeyWithParamsCmd returns a tea.Cmd that sends an import key request with parameters.
func (m Model) sendImportKeyWithParamsCmd(keyType, mnemonic string, params map[string]string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendImportKeyWithParams(keyType, mnemonic, params) })
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

func (c *IPCClient) SendInstallLibraryTemplate(keyType, templateType string) error {
	msg := InstallLibraryTemplateMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeInstallLibraryTemplate,
			ID:   fmt.Sprintf("tmpl-install-%d", time.Now().UnixNano()),
		},
		KeyType:      keyType,
		TemplateType: templateType,
	}
	return c.sendMessage(msg)
}

func (m Model) sendInstallLibraryTemplateCmd(keyType, templateType string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendInstallLibraryTemplate(keyType, templateType) })
}

func (c *IPCClient) SendShowLibraryTemplate(keyType, templateType string) error {
	msg := ShowLibraryTemplateMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeShowLibraryTemplate,
			ID:   fmt.Sprintf("tmpl-show-library-%d", time.Now().UnixNano()),
		},
		KeyType:      keyType,
		TemplateType: templateType,
	}
	return c.sendMessage(msg)
}

func (m Model) sendShowLibraryTemplateCmd(keyType, templateType string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendShowLibraryTemplate(keyType, templateType) })
}

func (c *IPCClient) SendActivateKeyType(keyType string) error {
	msg := ActivateKeyTypeMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeActivateKeyType,
			ID:   fmt.Sprintf("keytype-activate-%d", time.Now().UnixNano()),
		},
		KeyType: keyType,
	}
	return c.sendMessage(msg)
}

func (m Model) sendActivateKeyTypeCmd(keyType string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendActivateKeyType(keyType) })
}

func (c *IPCClient) SendDeactivateKeyType(keyType string) error {
	msg := DeactivateKeyTypeMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeDeactivateKeyType,
			ID:   fmt.Sprintf("keytype-deactivate-%d", time.Now().UnixNano()),
		},
		KeyType: keyType,
	}
	return c.sendMessage(msg)
}

func (m Model) sendDeactivateKeyTypeCmd(keyType string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendDeactivateKeyType(keyType) })
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

// ReconnectCmd returns a tea.Cmd that forces a reconnection attempt
func (m Model) reconnectCmd() tea.Cmd {
	return func() tea.Msg {
		// Close existing client if any
		if m.adminClient != nil {
			m.adminClient.Disconnect()
		}

		// Create new client and connect
		client := NewAdminClient(m.connector)

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
