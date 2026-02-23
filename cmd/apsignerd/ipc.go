// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"

	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/protocol"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// IPCServer handles Unix socket connections for local IPC.
type IPCServer struct {
	listener net.Listener
	hub      *Hub
	path     string

	// Single IPC client
	client        net.Conn // Only set after authentication succeeds
	clientPending net.Conn // Set to the conn currently authenticating (to reject duplicates)
	clientLock    sync.Mutex

	// Configuration
	lockOnDisconnect bool
	sessionTimeout   time.Duration
}

// NewIPCServer creates a new IPC server.
func NewIPCServer(path string, hub *Hub, lockOnDisconnect bool, sessionTimeout time.Duration) *IPCServer {
	return &IPCServer{
		path:             path,
		hub:              hub,
		lockOnDisconnect: lockOnDisconnect,
		sessionTimeout:   sessionTimeout,
	}
}

// Start begins listening on the Unix socket.
func (s *IPCServer) Start() error {
	// Security: Check for symlink attacks and ownership issues before removing
	if err := s.validateSocketPath(); err != nil {
		return err
	}

	// Warn if socket path is in a world-writable directory
	s.warnIfInsecureDirectory()

	// Remove existing socket file if present
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	listener, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("failed to listen on IPC socket: %w", err)
	}

	// Set socket permissions (only owner can access)
	if err := os.Chmod(s.path, 0600); err != nil {
		_ = listener.Close() // Best-effort cleanup
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	s.listener = listener
	go s.acceptLoop()
	return nil
}

// validateSocketPath checks for symlink attacks and ownership issues.
// This prevents an attacker from:
// 1. Creating a symlink at the socket path pointing to a sensitive file
// 2. Replacing a socket with one they control
func (s *IPCServer) validateSocketPath() error {
	info, err := os.Lstat(s.path)
	if os.IsNotExist(err) {
		// Socket doesn't exist yet - safe to create
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to stat socket path: %w", err)
	}

	// Check for symlink attack
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("SECURITY: socket path is a symlink (possible attack): %s", s.path)
	}

	// Verify ownership - socket must be owned by current user
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok {
		uid := os.Getuid()
		if uid < 0 {
			return fmt.Errorf("invalid UID: %d", uid)
		}
		currentUID := uint32(uid) // #nosec G115 - UIDs on Linux are 32-bit, safe conversion
		if stat.Uid != currentUID {
			return fmt.Errorf("SECURITY: socket owned by different user (uid %d, expected %d): %s",
				stat.Uid, currentUID, s.path)
		}
	}

	return nil
}

// warnIfInsecureDirectory prints a warning if the socket is in a world-writable directory.
func (s *IPCServer) warnIfInsecureDirectory() {
	dir := filepath.Dir(s.path)

	// Check for common world-writable directories
	if strings.HasPrefix(dir, "/tmp") || strings.HasPrefix(dir, "/var/tmp") {
		fmt.Printf("⚠️  WARNING: IPC socket in world-writable directory: %s\n", s.path)
		fmt.Printf("   Consider using $XDG_RUNTIME_DIR or $SIGNERD_HOME for better security\n")
		return
	}

	// Check actual directory permissions
	info, err := os.Stat(dir)
	if err != nil {
		return // Can't check, skip warning
	}

	// Check if directory is world-writable (others have write permission)
	if info.Mode().Perm()&0002 != 0 {
		fmt.Printf("⚠️  WARNING: IPC socket directory is world-writable: %s\n", dir)
		fmt.Printf("   This may allow other users to interfere with the socket\n")
	}
}

// Stop closes the IPC server.
func (s *IPCServer) Stop() {
	if s.listener != nil {
		_ = s.listener.Close() // Best-effort cleanup
	}
	s.clientLock.Lock()
	if s.client != nil {
		_ = s.client.Close() // Best-effort cleanup
	}
	s.clientLock.Unlock()
	// Clean up socket file
	_ = os.Remove(s.path) // Best-effort cleanup
}

// acceptLoop accepts incoming IPC connections.
func (s *IPCServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Listener closed
			return
		}

		// Only allow one client at a time (check both authenticated and pending)
		s.clientLock.Lock()
		if s.clientPending != nil {
			s.clientLock.Unlock()
			// Reject: another client is mid-authentication, can't displace
			errMsg := protocol.ErrorMessage{
				BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeError},
				Error:       "another apadmin client is currently authenticating",
			}
			data, _ := json.Marshal(errMsg)
			_, _ = conn.Write(append(data, '\n'))
			_ = conn.Close() // Best-effort cleanup
			continue
		}

		var existingReader *bufio.Reader
		if s.client != nil {
			// An authenticated client exists - offer displacement to the new connection
			s.clientLock.Unlock()

			reader, ok := s.offerDisplacement(conn)
			if !ok {
				// New client declined or error - close new connection
				_ = conn.Close()
				continue
			}
			existingReader = reader
			// Displacement confirmed - old client was displaced, proceed with new client
		} else {
			s.clientLock.Unlock()
		}

		// Mark as pending (client will be set after authentication succeeds)
		s.clientLock.Lock()
		s.clientPending = conn
		s.clientLock.Unlock()

		fmt.Println("✓ apadmin client connected via IPC")
		go s.handleClient(conn, existingReader)
	}
}

// displacementTimeout is the maximum time to wait for a displacement confirmation.
const displacementTimeout = 30 * time.Second

// offerDisplacement sends a client_exists message to the new connection and waits
// for a displace_confirm response. If confirmed, it displaces the old client.
// Returns the bufio.Reader (to avoid data loss from buffering) and true on success.
func (s *IPCServer) offerDisplacement(newConn net.Conn) (*bufio.Reader, bool) {
	// Send client_exists to the new connection
	existsMsg := protocol.ClientExistsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeClientExists},
	}
	data, err := json.Marshal(existsMsg)
	if err != nil {
		return nil, false
	}
	if _, err := newConn.Write(append(data, '\n')); err != nil {
		return nil, false
	}

	// Set a read deadline so a stalled client doesn't block acceptLoop forever
	_ = newConn.SetReadDeadline(time.Now().Add(displacementTimeout))

	// Wait for response from the new connection
	reader := bufio.NewReader(newConn)
	line, err := reader.ReadBytes('\n')

	// Clear the deadline for subsequent I/O
	_ = newConn.SetReadDeadline(time.Time{})

	if err != nil {
		return nil, false
	}

	// Trim newline
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}

	// Parse response
	var base protocol.BaseMessage
	if err := json.Unmarshal(line, &base); err != nil {
		return nil, false
	}

	if base.Type != protocol.MsgTypeDisplaceConfirm {
		// New client did not confirm displacement
		return nil, false
	}

	// Displacement confirmed - notify and close the old client
	s.clientLock.Lock()
	oldClient := s.client
	s.client = nil
	s.clientLock.Unlock()

	if oldClient != nil {
		// Send displaced message to old client
		displacedMsg := protocol.DisplacedMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDisplaced},
			Reason:      "Displaced by another apadmin client",
		}
		displacedData, _ := json.Marshal(displacedMsg)
		_, _ = oldClient.Write(append(displacedData, '\n'))
		_ = oldClient.Close()
		fmt.Println("⚠ Existing apadmin client displaced by new connection")
	}

	return reader, true
}

// handleClient handles a single IPC client connection.
// existingReader is non-nil when the connection went through displacement negotiation
// (to preserve any data buffered by the reader created during that phase).
func (s *IPCServer) handleClient(conn net.Conn, existingReader *bufio.Reader) {
	// Track whether we successfully authenticated (for cleanup logic)
	authenticated := false

	defer func() {
		s.clientLock.Lock()
		// Only clear clientPending if this conn is the one pending (not a displaced predecessor)
		if s.clientPending == conn {
			s.clientPending = nil
		}
		// Track whether this conn was the active client (vs displaced)
		wasActiveClient := s.client == conn
		if wasActiveClient {
			s.client = nil
		}
		s.clientLock.Unlock()
		_ = conn.Close() // Best-effort cleanup

		// Only do disconnect cleanup if we were the active authenticated client.
		// Displaced clients should not fail pending requests or lock the signer,
		// because the new client is taking over.
		if authenticated && wasActiveClient {
			// Fail all pending requests when client disconnects
			s.hub.failAllPendingRequests("apadmin disconnected")

			// Lock the signer if configured to do so
			if s.lockOnDisconnect {
				s.hub.lock()
				fmt.Println("⚠ apadmin client disconnected - signer locked")
			} else {
				if s.sessionTimeout > 0 {
					fmt.Printf("apadmin disconnected — signer will remain unlocked. Timeout: %s\n", s.sessionTimeout)
				} else {
					fmt.Println("apadmin disconnected — signer will remain unlocked. Timeout: none")
				}
			}
		}
	}()

	// Create an IPC connection wrapper, reusing reader from displacement if present
	reader := existingReader
	if reader == nil {
		reader = bufio.NewReader(conn)
	}
	ipcConn := &IPCConn{conn: conn, reader: reader}

	// Authenticate the client before allowing any operations
	if !s.authenticateClient(ipcConn) {
		fmt.Println("✗ IPC client authentication failed")
		return
	}
	fmt.Println("✓ IPC client authenticated")

	// Now register as the active client (after auth succeeds)
	// This ensures NotifyKeysChanged won't send messages during auth
	s.clientLock.Lock()
	s.client = conn
	s.clientPending = nil // No longer pending, now fully connected
	authenticated = true
	s.clientLock.Unlock()

	// Send initial status after successful authentication
	s.sendStatus(ipcConn)

	// Message loop
	for {
		line, err := ipcConn.reader.ReadBytes('\n')
		if err != nil {
			return
		}

		// Trim newline
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}

		// Parse base message
		var base protocol.BaseMessage
		if err := json.Unmarshal(line, &base); err != nil {
			s.sendError(ipcConn, "", "invalid message format")
			continue
		}

		// Handle message based on type
		s.handleMessage(ipcConn, base.Type, line)
	}
}

// sendStatus sends the current signer status.
func (s *IPCServer) sendStatus(conn *IPCConn) {
	identityID := conn.IdentityID()
	s.hub.signer.keysLock.RLock()
	idKeys := s.hub.signer.keysForIdentity(identityID)
	keyCount := len(idKeys)
	s.hub.signer.keysLock.RUnlock()

	status := protocol.StatusMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeStatus},
		State:       s.hub.GetState().String(),
		KeyCount:    keyCount,
	}
	_ = conn.WriteJSON(status)
}

// sendError sends an error message.
func (s *IPCServer) sendError(conn *IPCConn, requestID, errMsg string) {
	msg := protocol.ErrorMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeError,
			ID:   requestID,
		},
		Error: errMsg,
	}
	_ = conn.WriteJSON(msg)
}

// authenticateClient performs passphrase authentication for the IPC session.
// Returns true if authentication succeeds, false otherwise.
// Allows unlimited retries for wrong passphrase; only returns false on connection errors.
func (s *IPCServer) authenticateClient(conn *IPCConn) bool {
	// Send auth_required message
	authReq := protocol.AuthRequiredMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAuthRequired},
	}
	if err := conn.WriteJSON(authReq); err != nil {
		return false
	}

	// Authentication loop - allow retries for wrong passphrase
	for {
		// Wait for auth message
		line, err := conn.reader.ReadBytes('\n')
		if err != nil {
			return false
		}

		// Trim newline
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}

		// Parse the message
		var base protocol.BaseMessage
		if err := json.Unmarshal(line, &base); err != nil {
			s.sendAuthResult(conn, false, "invalid message format")
			return false
		}

		// Must be an auth message
		if base.Type != protocol.MsgTypeAuth {
			s.sendAuthResult(conn, false, "expected auth message")
			return false
		}

		// Parse the auth message
		var authMsg protocol.AuthMessage
		if err := json.Unmarshal(line, &authMsg); err != nil {
			s.sendAuthResult(conn, false, "invalid auth message format")
			return false
		}

		// Convert passphrase to bytes for secure handling
		passphraseBytes := []byte(authMsg.Passphrase)

		// Verify the passphrase using the control file
		if err := crypto.VerifyPassphraseWithMetadata(passphraseBytes, utilkeys.KeystorePath()); err != nil {
			crypto.ZeroBytes(passphraseBytes)
			s.sendAuthResult(conn, false, "invalid passphrase")
			// Continue loop to allow retry
			continue
		}

		// Authentication successful - also unlock signer if it's locked
		if s.hub.GetState() == SignerStateLocked {
			success, _, errMsg := s.hub.tryUnlock(passphraseBytes)
			crypto.ZeroBytes(passphraseBytes)
			if !success {
				// Auth succeeded but unlock failed (shouldn't happen with same passphrase)
				s.sendAuthResult(conn, false, "auth ok but unlock failed: "+errMsg)
				return false
			}
		} else {
			crypto.ZeroBytes(passphraseBytes)
		}

		conn.identity = auth.NewDefaultIdentity("ipc-passphrase")
		s.sendAuthResult(conn, true, "")
		return true
	}
}

// sendAuthResult sends an authentication result message.
func (s *IPCServer) sendAuthResult(conn *IPCConn, success bool, errMsg string) {
	msg := protocol.AuthResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAuthResult},
		Success:     success,
		Error:       errMsg,
	}
	_ = conn.WriteJSON(msg)
}

// handleMessage routes messages to the appropriate handler.
func (s *IPCServer) handleMessage(conn *IPCConn, msgType string, raw []byte) {
	switch msgType {
	case protocol.MsgTypeUnlock:
		var msg protocol.UnlockMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			s.sendError(conn, "", "invalid unlock message")
			return
		}
		s.handleUnlock(conn, &msg)

	case protocol.MsgTypeListKeys:
		var msg protocol.ListKeysMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			s.sendError(conn, "", "invalid list keys message")
			return
		}
		s.handleListKeys(conn, msg.ID)

	case protocol.MsgTypeGenerateKey:
		var msg protocol.GenerateKeyMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			s.sendError(conn, "", "invalid generate key message")
			return
		}
		s.handleGenerateKey(conn, &msg)

	case protocol.MsgTypeDeleteKey:
		var msg protocol.DeleteKeyMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			s.sendError(conn, "", "invalid delete key message")
			return
		}
		s.handleDeleteKey(conn, &msg)

	case protocol.MsgTypeExportKey:
		var msg protocol.ExportKeyMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			s.sendError(conn, "", "invalid export key message")
			return
		}
		s.handleExportKey(conn, &msg)

	case protocol.MsgTypeImportKey:
		var msg protocol.ImportKeyMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			s.sendError(conn, "", "invalid import key message")
			return
		}
		s.handleImportKey(conn, &msg)

	case protocol.MsgTypeGetKeyDetails:
		var msg protocol.GetKeyDetailsMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			s.sendError(conn, "", "invalid get key details message")
			return
		}
		s.handleGetKeyDetails(conn, &msg)

	case protocol.MsgTypeSignResponse:
		var msg protocol.SignResponseMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			s.sendError(conn, "", "invalid sign response message")
			return
		}
		s.hub.handleSignResponse(&msg)

	case protocol.MsgTypeTokenProvisioningResponse:
		var msg protocol.TokenProvisioningResponseMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			s.sendError(conn, "", "invalid token provisioning response message")
			return
		}
		s.hub.handleTokenProvisioningResponse(&msg)

	default:
		s.sendError(conn, "", "unknown message type: "+msgType)
	}
}

// handleUnlock handles unlock requests.
func (s *IPCServer) handleUnlock(conn *IPCConn, msg *protocol.UnlockMessage) {
	// Convert passphrase to bytes for secure handling
	passphraseBytes := []byte(msg.Passphrase)
	defer crypto.ZeroBytes(passphraseBytes)

	success, keyCount, errStr := s.hub.tryUnlock(passphraseBytes)

	result := protocol.UnlockResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeUnlockResult,
			ID:   msg.ID,
		},
		Success:  success,
		KeyCount: keyCount,
		Error:    errStr,
	}
	_ = conn.WriteJSON(result)
}

// handleListKeys handles key listing requests.
func (s *IPCServer) handleListKeys(conn *IPCConn, requestID string) {
	if !s.hub.IsUnlocked() {
		s.sendError(conn, requestID, "Signer is locked")
		return
	}

	identityID := conn.IdentityID()
	s.hub.signer.keysLock.RLock()
	idKeys := s.hub.signer.keysForIdentity(identityID)
	keysSnapshot := make(map[string]string, len(idKeys))
	for k, v := range idKeys {
		keysSnapshot[k] = v
	}
	s.hub.signer.keysLock.RUnlock()

	// Get key types using master key
	masterKey := s.hub.signer.keyStore.GetMasterKey()
	keysList := make([]protocol.KeyInfo, 0, len(keysSnapshot))
	for addr, keyFile := range keysSnapshot {
		keyType := "unknown"
		if info, err := keymgmt.DetectKeyInfoFromFileWithMasterKey(keyFile, masterKey); err == nil {
			keyType = info.Type
		}
		keysList = append(keysList, protocol.KeyInfo{
			Address: addr,
			KeyType: keyType,
		})
	}

	result := protocol.KeysListMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeKeysList,
			ID:   requestID,
		},
		Keys: keysList,
	}
	_ = conn.WriteJSON(result)
}

// handleGenerateKey handles key generation requests.
func (s *IPCServer) handleGenerateKey(conn *IPCConn, msg *protocol.GenerateKeyMessage) {
	result := protocol.GenerateResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeGenerateResult,
			ID:   msg.ID,
		},
	}

	if !s.hub.IsUnlocked() {
		result.Success = false
		result.Error = "Signer is locked"
		_ = conn.WriteJSON(result)
		return
	}

	// Handle generic LogicSig (timelock, etc.) generation separately
	if genericlsig.IsGenericLSigType(msg.KeyType) {
		s.handleGenerateGenericLSig(conn, msg, &result)
		return
	}

	// Standard key generation (ed25519, falcon1024, etc.)
	// Use master key for encryption (not passphrase)
	masterKey := s.hub.signer.keyStore.GetMasterKey()
	if masterKey == nil {
		result.Success = false
		result.Error = "Master key not available"
		_ = conn.WriteJSON(result)
		return
	}

	genResult, err := keymgmt.GenerateKey(msg.KeyType, masterKey, msg.Parameters)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		_ = conn.WriteJSON(result)
		return
	}

	// Note: Keys will be reloaded automatically by the file watcher

	result.Success = true
	result.Address = genResult.Address
	result.KeyType = genResult.KeyType
	result.Mnemonic = genResult.Mnemonic
	result.WordCount = len(strings.Fields(genResult.Mnemonic))
	result.Parameters = msg.Parameters
	_ = conn.WriteJSON(result)

	fmt.Printf("✓ Generated new %s key via IPC: %s\n", genResult.KeyType, genResult.Address)
}

// handleGenerateGenericLSig handles generic LogicSig generation (timelock, etc.).
// This uses the genericlsig registry to find the appropriate template.
func (s *IPCServer) handleGenerateGenericLSig(conn *IPCConn, msg *protocol.GenerateKeyMessage, result *protocol.GenerateResultMessage) {
	// Get the template from the registry
	template, err := genericlsig.GetOrError(msg.KeyType)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Unknown generic lsig type: %s", msg.KeyType)
		_ = conn.WriteJSON(result)
		return
	}

	// Create algod client for TEAL compilation
	// Requires explicit configuration - no silent defaults
	algodURL := s.hub.signer.tealCompilerAlgodURL
	if algodURL == "" {
		result.Success = false
		result.Error = "TEAL compilation requires teal_compiler_algod_url to be configured in config.yaml"
		_ = conn.WriteJSON(result)
		return
	}
	algodClient, err := algod.MakeClient(algodURL, s.hub.signer.tealCompilerAlgodToken)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to create algod client: %v", err)
		_ = conn.WriteJSON(result)
		return
	}

	// Validate parameters
	if err := template.ValidateCreationParams(msg.Parameters); err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Parameter validation failed: %v", err)
		_ = conn.WriteJSON(result)
		return
	}

	// Generate TEAL source for documentation
	tealSource, err := template.GenerateTEAL(msg.Parameters)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("TEAL generation failed: %v", err)
		_ = conn.WriteJSON(result)
		return
	}

	// Compile the template
	bytecode, address, err := template.Compile(msg.Parameters, algodClient)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("%s generation failed: %v", template.DisplayName(), err)
		_ = conn.WriteJSON(result)
		return
	}

	// Write key file (encrypted with master key)
	masterKey := s.hub.signer.keyStore.GetMasterKey()
	if masterKey == nil {
		result.Success = false
		result.Error = "Master key not available"
		_ = conn.WriteJSON(result)
		return
	}
	err = keys.WriteLSigFile(conn.IdentityID(), address, msg.KeyType, template.Family(), msg.Parameters, bytecode, tealSource, masterKey)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to save %s file: %v", template.DisplayName(), err)
		_ = conn.WriteJSON(result)
		return
	}

	// Note: Keys will be reloaded automatically by the file watcher

	result.Success = true
	result.Address = address
	result.KeyType = msg.KeyType
	result.Parameters = msg.Parameters
	// No mnemonic for generic LogicSigs (no private key)
	result.Mnemonic = ""
	result.WordCount = 0
	_ = conn.WriteJSON(result)

	fmt.Printf("✓ Generated %s via IPC: %s\n", template.DisplayName(), address)
	fmt.Printf("  TEAL compiler: %s\n", algodURL)
	// Log parameters
	for _, param := range template.CreationParams() {
		if val, ok := msg.Parameters[param.Name]; ok {
			fmt.Printf("  %s: %s\n", param.Label, val)
		}
	}
}

// handleDeleteKey handles key deletion requests.
func (s *IPCServer) handleDeleteKey(conn *IPCConn, msg *protocol.DeleteKeyMessage) {
	result := protocol.DeleteResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeDeleteResult,
			ID:   msg.ID,
		},
	}

	if !s.hub.IsUnlocked() {
		result.Success = false
		result.Error = "Signer is locked"
		_ = conn.WriteJSON(result)
		return
	}

	identityID := conn.IdentityID()
	s.hub.signer.keysLock.RLock()
	idKeys := s.hub.signer.keysForIdentity(identityID)
	var keyFile string
	var exists bool
	if idKeys != nil {
		keyFile, exists = idKeys[msg.Address]
	}
	s.hub.signer.keysLock.RUnlock()

	if !exists {
		result.Success = false
		result.Error = "Key not found: " + msg.Address
		_ = conn.WriteJSON(result)
		return
	}

	keysDir := filepath.Dir(keyFile)
	delResult, err := keymgmt.DeleteKey(msg.Address, keyFile, keysDir, identityID)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		_ = conn.WriteJSON(result)
		return
	}

	// Note: Keys will be reloaded automatically by the file watcher

	result.Success = true
	_ = conn.WriteJSON(result)

	fmt.Printf("✓ Deleted key via IPC: %s (moved to %s)\n", msg.Address, delResult.DeletedPath)
}

// handleExportKey handles key export requests.
func (s *IPCServer) handleExportKey(conn *IPCConn, msg *protocol.ExportKeyMessage) {
	result := protocol.ExportResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeExportResult,
			ID:   msg.ID,
		},
	}

	if !s.hub.IsUnlocked() {
		result.Success = false
		result.Error = "Signer is locked"
		_ = conn.WriteJSON(result)
		return
	}

	identityID := conn.IdentityID()
	s.hub.signer.keysLock.RLock()
	idKeys := s.hub.signer.keysForIdentity(identityID)
	var keyFile string
	var exists bool
	if idKeys != nil {
		keyFile, exists = idKeys[msg.Address]
	}
	s.hub.signer.keysLock.RUnlock()

	if !exists {
		result.Success = false
		result.Error = "Key not found: " + msg.Address
		_ = conn.WriteJSON(result)
		return
	}

	// Verify passphrase matches before allowing export
	var passphraseValid bool
	s.hub.signer.passphraseLock.RLock()
	pp := s.hub.signer.encryptionPassphrase
	if pp != nil {
		_ = pp.WithBytes(func(storedP []byte) error {
			passphraseValid = (msg.Passphrase == string(storedP))
			return nil
		})
	}
	s.hub.signer.passphraseLock.RUnlock()
	if !passphraseValid {
		result.Success = false
		result.Error = "Incorrect passphrase"
		_ = conn.WriteJSON(result)
		return
	}

	// Use master key for decryption
	masterKey := s.hub.signer.keyStore.GetMasterKey()
	if masterKey == nil {
		result.Success = false
		result.Error = "Master key not available"
		_ = conn.WriteJSON(result)
		return
	}

	expResult, err := keymgmt.ExportKey(msg.Address, keyFile, masterKey)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		_ = conn.WriteJSON(result)
		return
	}

	result.Success = true
	result.Address = expResult.Address
	result.Mnemonic = expResult.Mnemonic
	result.KeyType = expResult.KeyType
	result.WordCount = expResult.WordCount
	result.Parameters = expResult.Parameters
	_ = conn.WriteJSON(result)
}

// handleImportKey handles key import requests.
func (s *IPCServer) handleImportKey(conn *IPCConn, msg *protocol.ImportKeyMessage) {
	result := protocol.ImportResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeImportResult,
			ID:   msg.ID,
		},
	}

	if !s.hub.IsUnlocked() {
		result.Success = false
		result.Error = "Signer is locked"
		_ = conn.WriteJSON(result)
		return
	}

	// Use master key for encryption (not passphrase)
	masterKey := s.hub.signer.keyStore.GetMasterKey()
	if masterKey == nil {
		result.Success = false
		result.Error = "Master key not available"
		_ = conn.WriteJSON(result)
		return
	}

	importResult, err := keymgmt.ImportKey(msg.KeyType, msg.Mnemonic, masterKey, msg.Parameters)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		_ = conn.WriteJSON(result)
		return
	}

	// Note: Keys will be reloaded automatically by the file watcher

	result.Success = true
	result.Address = importResult.Address
	_ = conn.WriteJSON(result)

	fmt.Printf("✓ Imported %s key via IPC: %s\n", msg.KeyType, importResult.Address)
}

// handleGetKeyDetails handles requests for detailed key information.
func (s *IPCServer) handleGetKeyDetails(conn *IPCConn, msg *protocol.GetKeyDetailsMessage) {
	result := protocol.KeyDetailsMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeKeyDetails,
			ID:   msg.ID,
		},
	}

	if !s.hub.IsUnlocked() {
		result.Success = false
		result.Error = "Signer is locked"
		_ = conn.WriteJSON(result)
		return
	}

	// Get key file path from signer's key map
	identityID := conn.IdentityID()
	s.hub.signer.keysLock.RLock()
	idKeys := s.hub.signer.keysForIdentity(identityID)
	var keyFile string
	var exists bool
	if idKeys != nil {
		keyFile, exists = idKeys[msg.Address]
	}
	s.hub.signer.keysLock.RUnlock()

	if !exists {
		result.Success = false
		result.Error = "Key not found"
		_ = conn.WriteJSON(result)
		return
	}

	// Read the key file to get type, parameters, and display TEAL using master key
	masterKey := s.hub.signer.keyStore.GetMasterKey()
	info, err := keymgmt.DetectKeyInfoFromFileWithMasterKey(keyFile, masterKey)
	if err != nil {
		result.KeyType = "unknown"
	} else {
		result.KeyType = info.Type
		result.Parameters = info.Parameters

		// Get display TEAL for LogicSig keys (non-critical, ignore errors)
		teal, _ := keymgmt.GetDisplayTEALWithMasterKey(keyFile, masterKey)
		result.DisplayTEAL = teal
	}

	result.Success = true
	result.Address = msg.Address

	_ = conn.WriteJSON(result)
}

// HasClient returns true if an IPC client is connected.
func (s *IPCServer) HasClient() bool {
	s.clientLock.Lock()
	defer s.clientLock.Unlock()
	return s.client != nil
}

// SendSignRequest sends a signing request to the IPC client.
func (s *IPCServer) SendSignRequest(req *protocol.SignRequestMessage) bool {
	s.clientLock.Lock()
	client := s.client
	s.clientLock.Unlock()

	if client == nil {
		return false
	}

	ipcConn := &IPCConn{conn: client, reader: nil}
	return ipcConn.WriteJSON(req) == nil
}

// SendTokenProvisioningRequest sends a token provisioning request to the IPC client.
func (s *IPCServer) SendTokenProvisioningRequest(req *protocol.TokenProvisioningRequestMessage) bool {
	s.clientLock.Lock()
	client := s.client
	s.clientLock.Unlock()

	if client == nil {
		return false
	}

	ipcConn := &IPCConn{conn: client, reader: nil}
	return ipcConn.WriteJSON(req) == nil
}

// NotifyLocked sends a signer_locked notification to the connected IPC client.
// This allows apadmin to transition to the unlock screen when the signer auto-locks.
func (s *IPCServer) NotifyLocked(reason string) {
	s.clientLock.Lock()
	client := s.client
	s.clientLock.Unlock()

	if client == nil {
		return
	}

	msg := protocol.SignerLockedMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSignerLocked},
		Reason:      reason,
	}

	ipcConn := &IPCConn{conn: client, reader: nil}
	_ = ipcConn.WriteJSON(msg) // Best-effort notification
}

// NotifyKeysChanged sends a keys_changed notification to the connected IPC client.
// This allows apadmin to refresh its key list when keys are added/removed.
func (s *IPCServer) NotifyKeysChanged(keyCount int) {
	s.clientLock.Lock()
	client := s.client
	s.clientLock.Unlock()

	if client == nil {
		return
	}

	msg := protocol.KeysChangedMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeKeysChanged},
		KeyCount:    keyCount,
	}

	ipcConn := &IPCConn{conn: client, reader: nil}
	_ = ipcConn.WriteJSON(msg) // Best-effort notification
}

// IPCConn wraps a net.Conn with JSON read/write methods.
type IPCConn struct {
	conn     net.Conn
	reader   *bufio.Reader
	identity *auth.Identity // Authenticated identity for this connection
}

// IdentityID returns the identity ID for this connection, falling back to DefaultIdentityID
// if the connection has not been authenticated yet.
func (c *IPCConn) IdentityID() string {
	if c.identity != nil {
		return c.identity.ID
	}
	return auth.DefaultIdentityID
}

// WriteJSON writes a JSON message followed by newline.
func (c *IPCConn) WriteJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = c.conn.Write(data)
	return err
}
