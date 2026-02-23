// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// ReconnectingMsg is sent when attempting to reconnect
type ReconnectingMsg struct {
	Delay time.Duration
}

// IPCClient manages the IPC connection to aplane
type IPCClient struct {
	conn   net.Conn
	reader *bufio.Reader
	path   string

	// Mutex for connection state
	mu        sync.Mutex
	connected bool

	// Channel for incoming messages to forward to TUI
	msgChan chan tea.Msg

	// Done channel for shutdown
	done chan struct{}

	// Displacement state
	displaced bool // True when displaced by another client (suppress reconnect)

	// Reconnection state
	reconnecting   bool
	reconnectDelay time.Duration
	maxDelay       time.Duration
}

// NewIPCClient creates a new IPC client
func NewIPCClient(path string) *IPCClient {
	return &IPCClient{
		path:           path,
		msgChan:        make(chan tea.Msg, 10),
		done:           make(chan struct{}),
		reconnectDelay: 1 * time.Second,
		maxDelay:       30 * time.Second,
	}
}

// Connect establishes the IPC connection
func (c *IPCClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	conn, err := net.Dial("unix", c.path)
	if err != nil {
		return fmt.Errorf("failed to connect to IPC socket: %w", err)
	}

	c.conn = conn
	c.reader = bufio.NewReader(conn)
	c.connected = true

	// Start message reader goroutine
	go c.readMessages()

	return nil
}

// Disconnect closes the IPC connection
func (c *IPCClient) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return
	}

	close(c.done)
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.connected = false
}

// SendAuth sends an authentication request
func (c *IPCClient) SendAuth(passphrase string) error {
	msg := AuthMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeAuth,
			ID:   fmt.Sprintf("auth-%d", time.Now().UnixNano()),
		},
		Passphrase: passphrase,
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
		Passphrase: passphrase,
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

	if !c.connected || c.conn == nil {
		return fmt.Errorf("not connected")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	data = append(data, '\n')
	_, err = c.conn.Write(data)
	return err
}

// readMessages reads messages from IPC and forwards them to the TUI
func (c *IPCClient) readMessages() {
	defer func() {
		c.mu.Lock()
		c.connected = false
		displaced := c.displaced
		c.mu.Unlock()

		if displaced {
			// DisplacedMsg was already sent; don't send a redundant DisconnectedMsg
			// and don't auto-reconnect
			return
		}

		c.msgChan <- DisconnectedMsg{Error: nil}
		go c.reconnect()
	}()

	for {
		select {
		case <-c.done:
			return
		default:
		}

		line, err := c.reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				c.msgChan <- DisconnectedMsg{Error: err}
			}
			return
		}

		// Trim newline
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}

		// Parse base message to determine type
		var base BaseMessage
		if err := json.Unmarshal(line, &base); err != nil {
			c.msgChan <- ErrorMsg{Error: fmt.Errorf("invalid message: %w", err)}
			continue
		}

		switch base.Type {
		case MsgTypeAuthRequired:
			// Server requires authentication before any other operations
			c.msgChan <- AuthRequiredMsg{}

		case MsgTypeAuthResult:
			var authResult AuthResultMessage
			if err := json.Unmarshal(line, &authResult); err != nil {
				continue
			}
			c.msgChan <- AuthResultMsg{
				Success: authResult.Success,
				Error:   authResult.Error,
			}

		case MsgTypeStatus:
			var status StatusMessage
			if err := json.Unmarshal(line, &status); err != nil {
				continue
			}
			c.msgChan <- SignerStatusMsg{
				Locked:   status.State == "locked",
				KeyCount: status.KeyCount,
			}

		case MsgTypeUnlockResult:
			var result UnlockResultMessage
			if err := json.Unmarshal(line, &result); err != nil {
				continue
			}
			c.msgChan <- UnlockResultMsg{
				Success:  result.Success,
				KeyCount: result.KeyCount,
				Error:    result.Error,
			}

		case MsgTypeSignRequest:
			var req SignRequestMessage
			if err := json.Unmarshal(line, &req); err != nil {
				continue
			}
			c.msgChan <- SignRequestReceivedMsg{
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
			}

		case MsgTypeError:
			var errMsg ErrorMessage
			if err := json.Unmarshal(line, &errMsg); err != nil {
				continue
			}
			c.msgChan <- ErrorMsg{Error: fmt.Errorf("%s", errMsg.Error)}

		case MsgTypeKeysList:
			var keysList KeysListMessage
			if err := json.Unmarshal(line, &keysList); err != nil {
				continue
			}
			keys := make([]KeyInfo, 0, len(keysList.Keys))
			for _, k := range keysList.Keys {
				keys = append(keys, KeyInfo{
					Address: k.Address,
					KeyType: k.KeyType,
				})
			}
			c.msgChan <- KeysListMsg{Keys: keys}

		case MsgTypeGenerateResult:
			var genResult GenerateResultMessage
			if err := json.Unmarshal(line, &genResult); err != nil {
				continue
			}
			c.msgChan <- GenerateResultMsg{
				Success:    genResult.Success,
				Address:    genResult.Address,
				KeyType:    genResult.KeyType,
				Mnemonic:   genResult.Mnemonic,
				WordCount:  genResult.WordCount,
				Parameters: genResult.Parameters,
				Error:      genResult.Error,
			}

		case MsgTypeDeleteResult:
			var delResult DeleteResultMessage
			if err := json.Unmarshal(line, &delResult); err != nil {
				continue
			}
			c.msgChan <- DeleteResultMsg{
				Success: delResult.Success,
				Error:   delResult.Error,
			}

		case MsgTypeExportResult:
			var expResult ExportResultMessage
			if err := json.Unmarshal(line, &expResult); err != nil {
				continue
			}
			c.msgChan <- ExportResultMsg{
				Success:    expResult.Success,
				Address:    expResult.Address,
				KeyType:    expResult.KeyType,
				Mnemonic:   expResult.Mnemonic,
				WordCount:  expResult.WordCount,
				Parameters: expResult.Parameters,
				Error:      expResult.Error,
			}

		case MsgTypeImportResult:
			var impResult ImportResultMessage
			if err := json.Unmarshal(line, &impResult); err != nil {
				continue
			}
			c.msgChan <- ImportResultMsg{
				Success: impResult.Success,
				Address: impResult.Address,
				KeyType: impResult.KeyType,
				Error:   impResult.Error,
			}

		case MsgTypeKeyDetails:
			var detailsResult KeyDetailsMessage
			if err := json.Unmarshal(line, &detailsResult); err != nil {
				continue
			}
			c.msgChan <- KeyDetailsMsg{
				Success:     detailsResult.Success,
				Address:     detailsResult.Address,
				KeyType:     detailsResult.KeyType,
				Parameters:  detailsResult.Parameters,
				DisplayTEAL: detailsResult.DisplayTEAL,
				Error:       detailsResult.Error,
			}

		case MsgTypeKeysChanged:
			var keysChanged KeysChangedMessage
			if err := json.Unmarshal(line, &keysChanged); err != nil {
				continue
			}
			c.msgChan <- KeysChangedMsg{
				KeyCount: keysChanged.KeyCount,
			}

		case MsgTypeSignerLocked:
			// Server auto-locked (e.g., inactivity timeout) - transition to unlock screen
			c.msgChan <- SignerStatusMsg{
				Locked:   true,
				KeyCount: 0,
			}

		case MsgTypeTokenProvisioningRequest:
			var req TokenProvisioningRequestMessage
			if err := json.Unmarshal(line, &req); err != nil {
				continue
			}
			c.msgChan <- TokenProvisioningRequestReceivedMsg{
				Request: PendingTokenRequest{
					ID:             req.ID,
					IdentityID:     req.IdentityID,
					SSHFingerprint: req.SSHFingerprint,
					RemoteAddr:     req.RemoteAddr,
					Timestamp:      time.Unix(req.Timestamp, 0),
				},
			}

		case MsgTypeClientExists:
			c.msgChan <- ClientExistsMsg{}

		case MsgTypeDisplaced:
			var displaced DisplacedMessage
			if err := json.Unmarshal(line, &displaced); err != nil {
				continue
			}
			c.mu.Lock()
			c.displaced = true
			c.mu.Unlock()
			c.msgChan <- DisplacedMsg{Reason: displaced.Reason}
			return
		}
	}
}

// reconnect attempts to reconnect with exponential backoff
func (c *IPCClient) reconnect() {
	c.mu.Lock()
	if c.reconnecting {
		c.mu.Unlock()
		return
	}
	c.reconnecting = true
	delay := c.reconnectDelay
	c.mu.Unlock()

	for {
		select {
		case <-c.done:
			return
		default:
		}

		// Wait before attempting reconnection
		time.Sleep(delay)

		// Check if we're still supposed to reconnect
		c.mu.Lock()
		if c.connected {
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
			c.mu.Unlock()

			c.msgChan <- ConnectedMsg{}
			return
		}

		// Failed - increase delay with exponential backoff
		c.mu.Lock()
		delay = delay * 2
		if delay > c.maxDelay {
			delay = c.maxDelay
		}
		c.mu.Unlock()

		// Notify TUI of reconnection attempt
		c.msgChan <- ReconnectingMsg{Delay: delay}
	}
}

// ListenForMessages returns a tea.Cmd that listens for IPC messages
func (c *IPCClient) ListenForMessages() tea.Cmd {
	return func() tea.Msg {
		select {
		case msg := <-c.msgChan:
			return msg
		case <-c.done:
			return nil
		}
	}
}

// Global client instance (for use with tea.Cmd functions)
var globalIPCClient *IPCClient

// SetGlobalIPCClient sets the global IPC client
func SetGlobalIPCClient(client *IPCClient) {
	globalIPCClient = client
}

// ConnectCmd returns a tea.Cmd that connects to the server via IPC
func ConnectCmd(ipcPath, _ string) tea.Cmd {
	return func() tea.Msg {
		client := NewIPCClient(ipcPath)
		SetGlobalIPCClient(client)

		if err := client.Connect(); err != nil {
			return DisconnectedMsg{Error: err}
		}
		return ConnectedMsg{}
	}
}

// SendAuthCmd returns a tea.Cmd that sends an authentication request
func SendAuthCmd(passphrase string) tea.Cmd {
	return func() tea.Msg {
		if globalIPCClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}

		if err := globalIPCClient.SendAuth(passphrase); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
}

// SendUnlockCmd returns a tea.Cmd that sends an unlock request
func SendUnlockCmd(passphrase string) tea.Cmd {
	return func() tea.Msg {
		if globalIPCClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}

		if err := globalIPCClient.SendUnlock(passphrase); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
}

// sendSignResponseCmd returns a tea.Cmd that sends a sign response
func sendSignResponseCmd(requestID string, approved bool) tea.Cmd {
	return func() tea.Msg {
		if globalIPCClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}

		reason := ""
		if !approved {
			reason = "rejected by user"
		}
		if err := globalIPCClient.SendSignResponse(requestID, approved, reason); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
}

// sendTokenProvisioningResponseCmd returns a tea.Cmd that sends a token provisioning response
func sendTokenProvisioningResponseCmd(requestID string, approved bool) tea.Cmd {
	return func() tea.Msg {
		if globalIPCClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}

		reason := ""
		if !approved {
			reason = "rejected by user"
		}
		if err := globalIPCClient.SendTokenProvisioningResponse(requestID, approved, reason); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
}

// WaitForMessageCmd returns a tea.Cmd that waits for the next message
func WaitForMessageCmd() tea.Cmd {
	return func() tea.Msg {
		if globalIPCClient == nil {
			return nil
		}
		return globalIPCClient.ListenForMessages()()
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
func SendDisplaceConfirmCmd() tea.Cmd {
	return func() tea.Msg {
		if globalIPCClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}
		if err := globalIPCClient.SendDisplaceConfirm(); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
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
func SendListKeysCmd() tea.Cmd {
	return func() tea.Msg {
		if globalIPCClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}
		if err := globalIPCClient.SendListKeys(); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
}

// SendGenerateKeyCmd returns a tea.Cmd that sends a generate key request
func SendGenerateKeyCmd(keyType, name string) tea.Cmd {
	return func() tea.Msg {
		if globalIPCClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}
		if err := globalIPCClient.SendGenerateKey(keyType, name); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
}

// SendGenerateKeyWithParamsCmd returns a tea.Cmd that sends a generate key request with parameters
func SendGenerateKeyWithParamsCmd(keyType, name string, params map[string]string) tea.Cmd {
	return func() tea.Msg {
		if globalIPCClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}
		if err := globalIPCClient.SendGenerateKeyWithParams(keyType, name, params); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
}

// SendDeleteKeyCmd returns a tea.Cmd that sends a delete key request
func SendDeleteKeyCmd(address string) tea.Cmd {
	return func() tea.Msg {
		if globalIPCClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}
		if err := globalIPCClient.SendDeleteKey(address); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
}

// SendExportKey sends a request to export a key's mnemonic (with passphrase verification)
func (c *IPCClient) SendExportKey(address, passphrase string) error {
	msg := ExportKeyMessage{
		BaseMessage: BaseMessage{
			Type: MsgTypeExportKey,
			ID:   fmt.Sprintf("exp-%d", time.Now().UnixNano()),
		},
		Address:    address,
		Passphrase: passphrase,
	}
	return c.sendMessage(msg)
}

// SendExportKeyWithPassphraseCmd returns a tea.Cmd that sends an export key request with passphrase
func SendExportKeyWithPassphraseCmd(address, passphrase string) tea.Cmd {
	return func() tea.Msg {
		if globalIPCClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}
		if err := globalIPCClient.SendExportKey(address, passphrase); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
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
func SendImportKeyCmd(keyType, mnemonic string) tea.Cmd {
	return func() tea.Msg {
		if globalIPCClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}
		if err := globalIPCClient.SendImportKey(keyType, mnemonic); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
}

// SendImportKeyWithParamsCmd returns a tea.Cmd that sends an import key request with parameters.
func SendImportKeyWithParamsCmd(keyType, mnemonic string, params map[string]string) tea.Cmd {
	return func() tea.Msg {
		if globalIPCClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}
		if err := globalIPCClient.SendImportKeyWithParams(keyType, mnemonic, params); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
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
func SendGetKeyDetailsCmd(address string) tea.Cmd {
	return func() tea.Msg {
		if globalIPCClient == nil {
			return ErrorMsg{Error: fmt.Errorf("not connected")}
		}
		if err := globalIPCClient.SendGetKeyDetails(address); err != nil {
			return ErrorMsg{Error: err}
		}
		return nil
	}
}

// ReconnectCmd returns a tea.Cmd that forces a reconnection attempt
func ReconnectCmd(ipcPath string) tea.Cmd {
	return func() tea.Msg {
		// Close existing client if any
		if globalIPCClient != nil {
			globalIPCClient.Disconnect()
		}

		// Create new client and connect
		client := NewIPCClient(ipcPath)
		SetGlobalIPCClient(client)

		if err := client.Connect(); err != nil {
			return DisconnectedMsg{Error: err}
		}
		return ConnectedMsg{}
	}
}
