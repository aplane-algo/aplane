// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/protocol"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
)

// SignerState represents the current state of the apsignerd daemon
type SignerState int

const (
	SignerStateLocked SignerState = iota
	SignerStateUnlocked
)

func (s SignerState) String() string {
	switch s {
	case SignerStateLocked:
		return "locked"
	case SignerStateUnlocked:
		return "unlocked"
	default:
		return "unknown"
	}
}

// Hub manages signer state and pending signing requests
type Hub struct {
	// Signer state
	state     SignerState
	stateLock sync.RWMutex

	// Pending signing requests: map[requestID]chan protocol.SignResponseMessage
	pendingRequests     map[string]chan protocol.SignResponseMessage
	pendingRequestsLock sync.Mutex

	// Pending token provisioning requests: map[requestID]chan protocol.TokenProvisioningResponseMessage
	pendingTokenRequests     map[string]chan protocol.TokenProvisioningResponseMessage
	pendingTokenRequestsLock sync.Mutex

	// Reference to Signer for key operations
	signer *Signer
}

// NewHub creates a new signer hub
func NewHub(signer *Signer) *Hub {
	return &Hub{
		state:                SignerStateLocked,
		pendingRequests:      make(map[string]chan protocol.SignResponseMessage),
		pendingTokenRequests: make(map[string]chan protocol.TokenProvisioningResponseMessage),
		signer:               signer,
	}
}

// GetState returns the current signer state
func (h *Hub) GetState() SignerState {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()
	return h.state
}

// IsUnlocked returns true if the signer is unlocked
func (h *Hub) IsUnlocked() bool {
	return h.GetState() == SignerStateUnlocked
}

// SetUnlocked sets the signer state to unlocked (used by TEST_PASSPHRASE for testing)
func (h *Hub) SetUnlocked() {
	h.stateLock.Lock()
	h.state = SignerStateUnlocked
	h.stateLock.Unlock()
}

// lock locks the signer and clears sensitive data from memory.
func (h *Hub) lock() {
	// Set state to locked
	h.stateLock.Lock()
	wasUnlocked := h.state == SignerStateUnlocked
	h.state = SignerStateLocked
	h.stateLock.Unlock()

	if !wasUnlocked {
		return // Already locked, nothing to clear
	}

	// Stop the inactivity timer
	h.signer.stopSessionTimer()

	// Clear the encryption passphrase and key session from memory
	h.signer.passphraseLock.Lock()
	if h.signer.encryptionPassphrase != nil {
		h.signer.encryptionPassphrase.Destroy()
		h.signer.encryptionPassphrase = nil
	}
	if h.signer.keySession != nil {
		h.signer.keySession.Destroy()
		// Reinitialize session with same keyStore (will be rescanned on unlock)
		h.signer.keySession = keystore.NewKeySession(h.signer.keyStore)
	}
	h.signer.passphraseLock.Unlock()

	// Clear all identity keyspaces
	h.signer.keysLock.Lock()
	for id := range h.signer.keys {
		h.signer.keys[id] = make(map[string]string)
		h.signer.keyTypes[id] = make(map[string]string)
		h.signer.keyLsigSizes[id] = make(map[string]int)
	}
	h.signer.keysLock.Unlock()

	fmt.Println("🔒 Signer locked - sensitive data cleared from memory")

	// Notify connected apadmin client about the lock
	if h.signer.ipcServer != nil {
		h.signer.ipcServer.NotifyLocked("locked")
	}
}

// HasClient returns true if an IPC client is connected
func (h *Hub) HasClient() bool {
	if h.signer.ipcServer == nil {
		return false
	}
	return h.signer.ipcServer.HasClient()
}

// tryUnlock attempts to unlock the signer with the given passphrase.
// Returns (success, keyCount, errorMessage).
// The passphrase bytes are NOT zeroed by this function - caller is responsible.
func (h *Hub) tryUnlock(passphrase []byte) (bool, int, string) {
	// Verify passphrase against existing control file
	// (control file existence is validated at startup)
	if err := crypto.VerifyPassphraseWithMetadata(passphrase, utilkeys.KeystorePath()); err != nil {
		return false, 0, "Invalid passphrase"
	}

	// Set encryption passphrase and reload keys under write lock.
	// IPC unlock always provides a passphrase, so update unsealKind to match.
	// This ensures subsequent reloads (e.g., file watcher) also use passphrase derivation.
	h.signer.passphraseLock.Lock()
	if h.signer.encryptionPassphrase != nil {
		h.signer.encryptionPassphrase.Destroy()
	}
	h.signer.encryptionPassphrase = crypto.NewSecureStringFromBytes(passphrase)
	h.signer.unsealKind = "passphrase"
	if err := h.signer.reloadKeysLocked(); err != nil {
		h.signer.passphraseLock.Unlock()
		return false, 0, fmt.Sprintf("Failed to load keys: %v", err)
	}
	// Pre-initialize session with passphrase
	h.signer.keySession.InitializeSession(passphrase)
	h.signer.passphraseLock.Unlock()

	// Transition to unlocked state
	h.stateLock.Lock()
	h.state = SignerStateUnlocked
	h.stateLock.Unlock()

	// Start inactivity timer
	h.signer.resetSessionTimer()

	// Get key count
	h.signer.keysLock.RLock()
	keyCount := len(h.signer.keysForIdentity(auth.DefaultIdentityID))
	h.signer.keysLock.RUnlock()

	fmt.Printf("🔓 Signer unlocked (%d keys loaded)\n", keyCount)
	return true, keyCount, ""
}

// handleSignResponse processes a signing approval/rejection from apadmin
func (h *Hub) handleSignResponse(msg *protocol.SignResponseMessage) {
	h.pendingRequestsLock.Lock()
	ch, exists := h.pendingRequests[msg.ID]
	if exists {
		delete(h.pendingRequests, msg.ID)
	}
	h.pendingRequestsLock.Unlock()

	if exists && ch != nil {
		ch <- *msg
		close(ch)
	}
}

// RequestSigningApproval sends a signing request to apadmin and waits for response
// Returns (approved, error). If approved=false and error=nil, user rejected.
func (h *Hub) RequestSigningApproval(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []protocol.PolicyViolation, timeout time.Duration) (bool, error) {
	if !h.HasClient() {
		return false, fmt.Errorf("no apadmin client connected")
	}

	// Create response channel
	responseChan := make(chan protocol.SignResponseMessage, 1)

	h.pendingRequestsLock.Lock()
	h.pendingRequests[requestID] = responseChan
	h.pendingRequestsLock.Unlock()

	// Ensure cleanup on all exit paths
	defer func() {
		h.pendingRequestsLock.Lock()
		delete(h.pendingRequests, requestID)
		h.pendingRequestsLock.Unlock()
	}()

	// Send signing request via IPC
	request := &protocol.SignRequestMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeSignRequest,
			ID:   requestID,
		},
		Address:     address,
		TxnSender:   txnSender,
		Description: description,
		Timestamp:   time.Now().Unix(),
		FirstValid:  firstValid,
		LastValid:   lastValid,
		Violations:  violations,
	}

	if !h.signer.ipcServer.SendSignRequest(request) {
		return false, fmt.Errorf("failed to send signing request via IPC")
	}

	// Wait for response with timeout
	select {
	case response := <-responseChan:
		if !response.Approved {
			return false, nil // User rejected, not an error
		}
		return true, nil

	case <-time.After(timeout):
		return false, fmt.Errorf("approval timeout - no response from apadmin within %v", timeout)
	}
}

// failAllPendingRequests fails all pending requests (called on disconnect)
func (h *Hub) failAllPendingRequests(reason string) {
	h.pendingRequestsLock.Lock()
	defer h.pendingRequestsLock.Unlock()

	for id, ch := range h.pendingRequests {
		ch <- protocol.SignResponseMessage{
			BaseMessage: protocol.BaseMessage{
				Type: protocol.MsgTypeSignResponse,
				ID:   id,
			},
			Approved: false,
			Reason:   reason,
		}
		close(ch)
	}

	h.pendingRequests = make(map[string]chan protocol.SignResponseMessage)

	// Also fail pending token provisioning requests
	h.pendingTokenRequestsLock.Lock()
	defer h.pendingTokenRequestsLock.Unlock()

	for id, ch := range h.pendingTokenRequests {
		ch <- protocol.TokenProvisioningResponseMessage{
			BaseMessage: protocol.BaseMessage{
				Type: protocol.MsgTypeTokenProvisioningResponse,
				ID:   id,
			},
			Approved: false,
			Reason:   reason,
		}
		close(ch)
	}

	h.pendingTokenRequests = make(map[string]chan protocol.TokenProvisioningResponseMessage)
}

// handleTokenProvisioningResponse processes a token provisioning approval/rejection from apadmin
func (h *Hub) handleTokenProvisioningResponse(msg *protocol.TokenProvisioningResponseMessage) {
	h.pendingTokenRequestsLock.Lock()
	ch, exists := h.pendingTokenRequests[msg.ID]
	if exists {
		delete(h.pendingTokenRequests, msg.ID)
	}
	h.pendingTokenRequestsLock.Unlock()

	if exists && ch != nil {
		ch <- *msg
		close(ch)
	}
}

// RequestTokenProvisioning sends a token provisioning request to apadmin and waits for response.
// Returns (approved, error). If approved=false and error=nil, user rejected.
func (h *Hub) RequestTokenProvisioning(requestID, identityID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error) {
	if !h.HasClient() {
		return false, fmt.Errorf("no apadmin client connected")
	}

	// Create response channel
	responseChan := make(chan protocol.TokenProvisioningResponseMessage, 1)

	h.pendingTokenRequestsLock.Lock()
	h.pendingTokenRequests[requestID] = responseChan
	h.pendingTokenRequestsLock.Unlock()

	// Ensure cleanup on all exit paths
	defer func() {
		h.pendingTokenRequestsLock.Lock()
		delete(h.pendingTokenRequests, requestID)
		h.pendingTokenRequestsLock.Unlock()
	}()

	// Send token provisioning request via IPC
	request := &protocol.TokenProvisioningRequestMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeTokenProvisioningRequest,
			ID:   requestID,
		},
		IdentityID:     identityID,
		SSHFingerprint: sshFingerprint,
		RemoteAddr:     remoteAddr,
		Timestamp:      time.Now().Unix(),
	}

	if !h.signer.ipcServer.SendTokenProvisioningRequest(request) {
		return false, fmt.Errorf("failed to send token provisioning request via IPC")
	}

	// Wait for response with timeout
	select {
	case response := <-responseChan:
		if !response.Approved {
			return false, nil // User rejected, not an error
		}
		return true, nil

	case <-time.After(timeout):
		return false, fmt.Errorf("approval timeout - no response from apadmin within %v", timeout)
	}
}
