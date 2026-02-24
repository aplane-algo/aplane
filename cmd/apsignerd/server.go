// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/auth"
	algocrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsig"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/util"
	falcon1024template "github.com/aplane-algo/aplane/lsig/falcon1024/v1/template"
	"github.com/aplane-algo/aplane/lsig/multitemplate"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// SignRequest and SignResponse are defined in internal/util/types.go
// Use util.SignRequest and util.SignResponse throughout this file

// writeJSON writes a JSON response with the given status code.
// This consolidates the repetitive pattern of setting Content-Type,
// writing status, and encoding JSON.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// encodeTxnToHex encodes a transaction to TX-prefixed hex string (same format as TxnBytesHex)
func encodeTxnToHex(txn types.Transaction) string {
	txnBytes := msgpack.Encode(txn)
	withPrefix := append([]byte("TX"), txnBytes...)
	return hex.EncodeToString(withPrefix)
}

// encodeTxnToBytes encodes a transaction to TX-prefixed bytes
func encodeTxnToBytes(txn types.Transaction) []byte {
	txnBytes := msgpack.Encode(txn)
	return append([]byte("TX"), txnBytes...)
}

// isValidationTransaction checks if transaction is a 0 ALGO self-send
func isValidationTransaction(messageBytes []byte, txnSender string, _ string) bool {
	txnBytes := messageBytes
	if len(messageBytes) > 2 && messageBytes[0] == 'T' && messageBytes[1] == 'X' {
		txnBytes = messageBytes[2:]
	}

	var txn types.Transaction
	if err := msgpack.Decode(txnBytes, &txn); err != nil {
		return false
	}

	// Must be a payment transaction
	if txn.Type != types.PaymentTx {
		return false
	}

	// Must be 0 ALGO
	if txn.Amount != 0 {
		return false
	}

	senderAddr := txn.Sender.String()
	receiverAddr := txn.Receiver.String()

	// Must be self-send
	if senderAddr != receiverAddr {
		return false
	}

	if txnSender != "" && txnSender != senderAddr {
		return false
	}

	// CRITICAL: Ensure no other actions are performed
	// A pure validation transaction should ONLY be a 0 ALGO self-send

	// No rekeying allowed
	if !txn.RekeyTo.IsZero() {
		return false
	}

	// No account closing allowed
	if !txn.CloseRemainderTo.IsZero() {
		return false
	}

	// No asset closing allowed
	if !txn.AssetCloseTo.IsZero() {
		return false
	}

	return true
}

// assembleSignedTransaction creates a complete signed transaction ready for submission.
// It handles Ed25519 (SignedTransaction), LogicSig DSA (LogicSigTransaction with sig in args),
// and generic LogicSig (LogicSigTransaction with just bytecode and args).
//
// Parameters:
//   - txnBytesHex: Full transaction bytes as hex (TX prefix + msgpack)
//   - keyType: Type of key used (ed25519, falcon1024-v1, timelock-v1, etc.)
//   - signature: Cryptographic signature (nil for generic lsigs)
//   - bytecode: LogicSig bytecode (nil for ed25519)
//   - orderedArgs: Runtime args for generic lsigs (nil otherwise)
//   - authAddress: Address of the signing key
//   - txnSender: Address of the transaction sender
//
// Returns hex-encoded msgpack of the signed transaction, or error.
// TransactionDescriber generates human-readable descriptions for transaction types.
// Plugin authors can register custom describers in transactionDescribers map.

type Signer struct {
	keyStore               *keystore.FileKeyStore       // Key storage abstraction
	keys                   map[string]map[string]string // identity -> (address -> keyfile path)
	keyTypes               map[string]map[string]string // identity -> (address -> key type)
	keyLsigSizes           map[string]map[string]int    // identity -> (address -> LSig size in bytes)
	keysLock               sync.RWMutex                 // Protects keys, keyTypes, and keyLsigSizes maps
	passphraseLock         sync.RWMutex                 // Protects encryptionPassphrase and keySession pointers
	keySession             *keystore.KeySession
	sessionTimeout         time.Duration // Inactivity timeout (0 = never, >0 = auto-lock after inactivity)
	sessionTimerMu         sync.Mutex    // Protects sessionTimer across goroutines (HTTP handlers, hub lock/unlock, timer callback)
	sessionTimer           *time.Timer   // Fires hub.lock() after inactivity
	lastActivity           atomic.Int64  // UnixNano of last activity; callback checks before locking
	encryptionPassphrase   *algocrypto.SecureString
	authenticator          auth.Authenticator // Pluggable authentication
	authorizer             auth.Authorizer    // Pluggable authorization
	auditLog               *AuditLogger       // Audit logger for security events
	hub                    *Hub               // Signer hub for apadmin/apapprover
	ipcServer              *IPCServer         // IPC server for local Unix socket connections
	config                 *util.ServerConfig // Server configuration (includes policy settings)
	tealCompilerAlgodURL   string             // Algod URL for TEAL compilation (defaults to Nodely testnet)
	tealCompilerAlgodToken string             // Algod token for TEAL compilation (optional)
}

// resetSessionTimer resets (or starts) the inactivity timer.
// When the timer fires, it calls hub.lock() to zero the master key.
// Safe for concurrent use from HTTP handlers, IPC handlers, and startup.
func (fs *Signer) resetSessionTimer() {
	if fs.sessionTimeout <= 0 {
		return
	}
	fs.lastActivity.Store(time.Now().UnixNano())
	fs.sessionTimerMu.Lock()
	defer fs.sessionTimerMu.Unlock()
	if fs.sessionTimer != nil {
		fs.sessionTimer.Reset(fs.sessionTimeout)
	} else {
		fs.sessionTimer = time.AfterFunc(fs.sessionTimeout, func() {
			// Guard against stale callback: if activity occurred after this timer
			// was scheduled, re-arm instead of locking.
			if time.Since(time.Unix(0, fs.lastActivity.Load())) < fs.sessionTimeout {
				fs.resetSessionTimer()
				return
			}
			fmt.Printf("⏰ Session timeout (%s of inactivity) - locking signer\n", fs.sessionTimeout)
			fs.hub.lock()
		})
	}
}

// stopSessionTimer stops the inactivity timer if running.
// Safe for concurrent use from hub.lock(), shutdown, and timer callbacks.
func (fs *Signer) stopSessionTimer() {
	fs.sessionTimerMu.Lock()
	defer fs.sessionTimerMu.Unlock()
	if fs.sessionTimer != nil {
		fs.sessionTimer.Stop()
		fs.sessionTimer = nil
	}
}

// requireAuth is middleware that validates authentication and authorization
// using the configured authenticator and authorizer
func (fs *Signer) requireAuth(action auth.Action, resource auth.Resource, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Step 1: Authentication - who is this?
		identity, err := fs.authenticator.Authenticate(ctx, r)
		if err != nil {
			var reason string
			switch err {
			case auth.ErrNoCredentials:
				reason = "missing_credentials"
			case auth.ErrInvalidCredentials:
				reason = "invalid_credentials"
			default:
				reason = "auth_failed"
			}

			if fs.auditLog != nil {
				fs.auditLog.LogAuthFailed("", r.RemoteAddr, reason)
			}

			// Return appropriate error message based on authenticator type
			if fs.authenticator.Method() == "aplane-token" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
			} else {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
			}
			return
		}

		// Step 2: Authorization - are they allowed to do this?
		if fs.authorizer != nil {
			if err := fs.authorizer.Authorize(ctx, identity, action, resource); err != nil {
				if fs.auditLog != nil {
					fs.auditLog.LogAuthFailed(identity.ID, r.RemoteAddr, "unauthorized: "+string(action))
				}
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		// Inject identity into request context and proceed to handler
		ctx = auth.ContextWithIdentity(ctx, identity)
		next(w, r.WithContext(ctx))
	}
}

// keysForIdentity returns the address→keyfile map for the given identity (caller must hold read lock).
func (fs *Signer) keysForIdentity(identityID string) map[string]string {
	if m := fs.keys[identityID]; m != nil {
		return m
	}
	return nil
}

// keyTypesForIdentity returns the address→keytype map for the given identity (caller must hold read lock).
func (fs *Signer) keyTypesForIdentity(identityID string) map[string]string {
	if m := fs.keyTypes[identityID]; m != nil {
		return m
	}
	return nil
}

// lsigSizesForIdentity returns the address→lsigsize map for the given identity (caller must hold read lock).
func (fs *Signer) lsigSizesForIdentity(identityID string) map[string]int {
	if m := fs.keyLsigSizes[identityID]; m != nil {
		return m
	}
	return nil
}

func (fs *Signer) findKeyFileForAddress(identityID, address string) (string, error) {
	fs.keysLock.RLock()
	idKeys := fs.keysForIdentity(identityID)
	var keyFile string
	var exists bool
	if idKeys != nil {
		keyFile, exists = idKeys[address]
	}
	fs.keysLock.RUnlock()
	if !exists {
		return "", fmt.Errorf("no key found for address: %s", address)
	}
	return keyFile, nil
}

// reloadKeys rescans the keys directory and updates the keys map thread-safely.
// It acquires passphraseLock.RLock to protect access to encryptionPassphrase and keySession.
func (fs *Signer) reloadKeys() error {
	fs.passphraseLock.RLock()
	defer fs.passphraseLock.RUnlock()
	return fs.reloadKeysLocked()
}

// reloadKeysLocked is the internal implementation of reloadKeys.
// Caller must hold passphraseLock (read or write).
func (fs *Signer) reloadKeysLocked() error {
	// Check if signer is locked (passphrase cleared)
	if fs.encryptionPassphrase == nil {
		return fmt.Errorf("signer is locked")
	}

	// Use WithBytes to avoid creating unzeroed string copies
	var err error

	// Step 1: Initialize master key (verify passphrase and derive key via Argon2id)
	// This must happen first so we can use the master key for both templates and keys
	var masterKey []byte
	err = fs.encryptionPassphrase.WithBytes(func(p []byte) error {
		var initErr error
		masterKey, initErr = fs.keyStore.InitializeMasterKey(p)
		return initErr
	})
	if err != nil {
		return fmt.Errorf("failed to initialize master key: %w", err)
	}

	// Step 2: Load and register runtime generic templates using master key
	// This ensures IsGenericLSigType() recognizes runtime template key types during scan
	if err := multitemplate.RegisterKeystoreTemplates(masterKey); err != nil {
		// Log warning but don't fail - keys are more important
		fmt.Printf("Warning: Failed to load generic templates: %v\n", err)
	}

	// Step 2b: Load and register Falcon DSA composition templates from keystore
	if err := falcon1024template.RegisterKeystoreTemplates(masterKey); err != nil {
		fmt.Printf("Warning: Failed to load falcon templates: %v\n", err)
	}

	// Step 3: Scan keys using master key (already initialized, will be reused)
	err = fs.encryptionPassphrase.WithBytes(func(p []byte) error {
		return fs.keyStore.Scan(p)
	})
	if err != nil {
		return fmt.Errorf("failed to rescan keys directory: %w", err)
	}

	// Get all cached maps from keystore (all populated during single-pass scan)
	newKeysMap := fs.keyStore.GetCache()
	newKeyTypes := fs.keyStore.GetKeyTypes()
	newLsigSizes := fs.keyStore.GetLsigSizes()

	// Update identity-scoped maps with write lock (default identity)
	fs.keysLock.Lock()
	fs.keys[auth.DefaultIdentityID] = newKeysMap
	fs.keyTypes[auth.DefaultIdentityID] = newKeyTypes
	fs.keyLsigSizes[auth.DefaultIdentityID] = newLsigSizes
	fs.keysLock.Unlock()

	// KeySession uses KeyStore directly, so no need to update it separately
	// Re-initialize session with passphrase to ensure keys can be decrypted for signing
	if fs.encryptionPassphrase != nil {
		err = fs.encryptionPassphrase.WithBytes(func(p []byte) error {
			fs.keySession.InitializeSession(p)
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to reinitialize session: %w", err)
		}
	}

	keyCount := len(newKeysMap)

	// Audit log: keys reloaded
	if fs.auditLog != nil {
		fs.auditLog.LogKeyReload(keyCount)
	}

	fmt.Printf("🔄 Keys reloaded: %d key(s) available\n", keyCount)

	// Notify connected IPC client (apadmin) about key change
	if fs.ipcServer != nil {
		fs.ipcServer.NotifyKeysChanged(keyCount)
	}

	return nil
}

// planResult contains the output of group-building (planGroup).
// It holds everything needed by both handleSign (for signing) and handlePlan (for previewing).
type planResult struct {
	allTxns               []types.Transaction  // Final transaction list (main + dummies)
	dummyTxns             []types.Transaction  // Dummy transactions only
	passthroughIndices    map[int]bool         // Which request indices are passthrough
	passthroughSignedTxns map[int][]byte       // Index -> raw signed txn bytes (for passthrough output)
	foreignIndices        map[int]bool         // Which request indices are foreign (not signed by this signer)
	hasForeign            bool                 // Whether any foreign transactions exist
	lsigIndices           []int                // Indices of LSig transactions in the original request
	dummiesNeeded         int                  // Number of dummy transactions added
	feeInfo               signing.DummyFeeInfo // Fee distribution info
	needsRegroup          bool                 // Whether group ID was (re)computed
	isPreGrouped          bool                 // Whether input was pre-grouped
	hasPassthrough        bool                 // Whether any passthrough transactions exist
}

// planGroup performs the group-building phase of transaction signing.
// It parses, validates, decodes transactions, checks keys exist, calculates dummies,
// creates dummies, pools fees, and computes group ID.
// No keys are touched, no approval flow is triggered.
//
// Returns (*planResult, httpStatus, errorMessage). On success, status is 0 and error is empty.
func (fs *Signer) planGroup(identityID string, req util.GroupSignRequest) (*planResult, int, string) {
	// Validate request
	if len(req.Requests) == 0 {
		return nil, http.StatusBadRequest, "requests array is empty"
	}

	// Categorize requests: sign mode vs passthrough mode vs foreign mode
	// - sign: txn_bytes_hex + auth_address (server signs with its key)
	// - passthrough: signed_txn_hex (already signed, included as-is)
	// - foreign: txn_bytes_hex without auth_address (belongs to another signer)
	passthroughIndices := make(map[int]bool)
	foreignIndices := make(map[int]bool)
	for i, txReq := range req.Requests {
		hasPassthrough := txReq.SignedTxnHex != ""
		hasTxnBytes := txReq.TxnBytesHex != ""
		hasAuthAddr := txReq.AuthAddress != ""

		if hasPassthrough && (hasTxnBytes || hasAuthAddr) {
			return nil, http.StatusBadRequest, fmt.Sprintf("transaction %d: cannot specify both sign fields (auth_address/txn_bytes_hex) and passthrough field (signed_txn_hex)", i+1)
		}
		if hasPassthrough {
			passthroughIndices[i] = true
		} else if hasTxnBytes && hasAuthAddr {
			// Sign mode — validated further below
		} else if hasTxnBytes && !hasAuthAddr {
			// Foreign mode — txn_bytes_hex without auth_address
			foreignIndices[i] = true
		} else if hasAuthAddr && !hasTxnBytes {
			return nil, http.StatusBadRequest, fmt.Sprintf("transaction %d: txn_bytes_hex is required for sign mode", i+1)
		} else {
			return nil, http.StatusBadRequest, fmt.Sprintf("transaction %d: must specify sign fields (auth_address + txn_bytes_hex), passthrough field (signed_txn_hex), or foreign (txn_bytes_hex only)", i+1)
		}
	}

	hasPassthrough := len(passthroughIndices) > 0
	hasForeign := len(foreignIndices) > 0

	// Reject mix of passthrough + foreign: passthrough requires pre-grouped,
	// foreign implies server computes group ID — these are incompatible.
	if hasPassthrough && hasForeign {
		return nil, http.StatusBadRequest, "cannot mix passthrough and foreign transactions: passthrough requires pre-grouped, foreign requires server-computed group ID"
	}

	fmt.Printf("[GROUP] Received %d transaction(s)", len(req.Requests))
	if hasPassthrough || hasForeign {
		signCount := len(req.Requests) - len(passthroughIndices) - len(foreignIndices)
		if hasPassthrough {
			fmt.Printf(" (%d passthrough, %d to sign)", len(passthroughIndices), signCount)
		}
		if hasForeign {
			fmt.Printf(" (%d foreign, %d to sign)", len(foreignIndices), signCount)
		}
	}
	fmt.Println()

	// Audit log: sign request received
	if fs.auditLog != nil {
		for i, txReq := range req.Requests {
			if passthroughIndices[i] {
				fs.auditLog.LogSignRequest(identityID, "", "", "passthrough", "pre-signed transaction")
			} else if foreignIndices[i] {
				fs.auditLog.LogSignRequest(identityID, "", "", "foreign", generateTransactionDescription(txReq.TxnBytesHex))
			} else {
				fs.auditLog.LogSignRequest(identityID, txReq.AuthAddress, txReq.TxnSender, "", generateTransactionDescription(txReq.TxnBytesHex))
			}
		}
	}

	// Step 1: Decode all transactions
	// For sign mode: decode TxnBytesHex (unsigned transaction)
	// For passthrough: decode SignedTxnHex and extract the embedded Transaction
	txns := make([]types.Transaction, len(req.Requests))
	passthroughSignedTxns := make(map[int][]byte) // Index -> raw signed txn bytes (for output)
	for i, txReq := range req.Requests {
		if passthroughIndices[i] {
			// Passthrough mode: decode SignedTxn to extract Transaction for validation
			stxnBytes, err := hex.DecodeString(txReq.SignedTxnHex)
			if err != nil {
				return nil, http.StatusBadRequest, fmt.Sprintf("transaction %d (passthrough): invalid hex encoding", i+1)
			}

			var stxn types.SignedTxn
			if err := msgpack.Decode(stxnBytes, &stxn); err != nil {
				return nil, http.StatusBadRequest, fmt.Sprintf("transaction %d (passthrough): invalid signed transaction msgpack", i+1)
			}

			txns[i] = stxn.Txn
			passthroughSignedTxns[i] = stxnBytes
			fmt.Printf("  [%d] sender=%s group=%x (passthrough)\n", i+1, stxn.Txn.Sender.String(), stxn.Txn.Group[:8])
		} else {
			// Sign mode: decode unsigned transaction
			txnBytesWithPrefix, err := hex.DecodeString(txReq.TxnBytesHex)
			if err != nil {
				return nil, http.StatusBadRequest, fmt.Sprintf("transaction %d: invalid hex encoding", i+1)
			}

			// Strip TX prefix if present
			txnBytes := txnBytesWithPrefix
			if len(txnBytes) > 2 && txnBytes[0] == 'T' && txnBytes[1] == 'X' {
				txnBytes = txnBytes[2:]
			}

			// Decode msgpack
			var txn types.Transaction
			if err := msgpack.Decode(txnBytes, &txn); err != nil {
				return nil, http.StatusBadRequest, fmt.Sprintf("transaction %d: invalid msgpack", i+1)
			}

			txns[i] = txn
			fmt.Printf("  [%d] sender=%s group=%x\n", i+1, txn.Sender.String(), txn.Group[:8])
		}
	}

	// Step 2: Validate group consistency
	var emptyDigest types.Digest
	firstGroup := txns[0].Group
	isPreGrouped := firstGroup != emptyDigest

	for i, txn := range txns {
		if isPreGrouped {
			// All must have the same non-zero group ID
			if txn.Group != firstGroup {
				return nil, http.StatusBadRequest, fmt.Sprintf("transaction %d has different group ID - request must contain single group", i+1)
			}
		} else {
			// All must have zero group ID (ungrouped)
			if txn.Group != emptyDigest {
				return nil, http.StatusBadRequest, fmt.Sprintf("transaction %d has group ID but transaction 1 does not - inconsistent grouping", i+1)
			}
		}
	}

	// Passthrough requires pre-grouped transactions (can't add dummies without invalidating signatures)
	if hasPassthrough && !isPreGrouped {
		return nil, http.StatusBadRequest, "passthrough transactions require pre-set group ID - server cannot add dummies or modify group without invalidating existing signatures"
	}

	if isPreGrouped {
		fmt.Printf("[GROUP] Pre-grouped transactions (group ID: %x...)\n", firstGroup[:8])
	} else if len(txns) > 1 {
		fmt.Printf("[GROUP] Ungrouped transactions - will compute group ID\n")
	} else {
		fmt.Printf("[GROUP] Single ungrouped transaction\n")
	}

	// Step 2b: Validate network params and validity windows are compatible
	// This prevents creating an invalid group or misleading approvals
	if len(txns) > 1 {
		firstTxn := txns[0]
		// Track the intersection of validity windows
		maxFirstValid := firstTxn.FirstValid
		minLastValid := firstTxn.LastValid

		for i := 1; i < len(txns); i++ {
			txn := txns[i]

			// Validate genesis hash matches
			if txn.GenesisHash != firstTxn.GenesisHash {
				return nil, http.StatusBadRequest, fmt.Sprintf("transaction %d has different genesis hash - all transactions must target the same network", i+1)
			}

			// Validate genesis ID matches
			if txn.GenesisID != firstTxn.GenesisID {
				return nil, http.StatusBadRequest, fmt.Sprintf("transaction %d has different genesis ID (%s vs %s) - all transactions must target the same network", i+1, txn.GenesisID, firstTxn.GenesisID)
			}

			// Track validity window intersection
			if txn.FirstValid > maxFirstValid {
				maxFirstValid = txn.FirstValid
			}
			if txn.LastValid < minLastValid {
				minLastValid = txn.LastValid
			}
		}

		// Verify validity windows overlap (there must be at least one valid round for all txns)
		if maxFirstValid > minLastValid {
			return nil, http.StatusBadRequest, fmt.Sprintf("transaction validity windows do not overlap (earliest LastValid: %d, latest FirstValid: %d) - group would never be valid", minLastValid, maxFirstValid)
		}

		fmt.Printf("[GROUP] Network params validated, validity window: rounds %d-%d\n", maxFirstValid, minLastValid)
	}

	// Step 3: Verify all auth_addresses are signable (skip passthrough and foreign transactions)
	signableCount := 0
	for i, txReq := range req.Requests {
		if passthroughIndices[i] {
			// Passthrough - already signed, no key needed
			fmt.Printf("  [%d] passthrough ✓\n", i+1)
			continue
		}
		if foreignIndices[i] {
			// Foreign - belongs to another signer, no key needed
			if txReq.LsigSize > 0 {
				fmt.Printf("  [%d] foreign (lsig_size=%d) ✓\n", i+1, txReq.LsigSize)
			} else {
				fmt.Printf("  [%d] foreign ✓\n", i+1)
			}
			continue
		}

		// Sign mode - verify we have the key
		_, err := fs.findKeyFileForAddress(identityID, txReq.AuthAddress)
		if err != nil {
			return nil, http.StatusBadRequest, fmt.Sprintf("transaction %d: %v", i+1, err)
		}

		// Get key type for logging
		fs.keysLock.RLock()
		keyType := fs.keyTypesForIdentity(identityID)[txReq.AuthAddress]
		fs.keysLock.RUnlock()

		fmt.Printf("  [%d] auth=%s type=%s ✓\n", i+1, txReq.AuthAddress[:8]+"...", keyType)
		signableCount++
	}

	if signableCount > 0 {
		fmt.Printf("[GROUP] %d key(s) available for signing\n", signableCount)
	}
	if hasPassthrough {
		fmt.Printf("[GROUP] %d passthrough transaction(s) will be included as-is\n", len(passthroughIndices))
	}
	if hasForeign {
		fmt.Printf("[GROUP] %d foreign transaction(s) will not be signed\n", len(foreignIndices))
	}

	// Reject all-foreign requests: no signable transactions means no signatures
	// produced by this signer. Use /plan for group-building without signing.
	if signableCount == 0 && !hasPassthrough {
		return nil, http.StatusBadRequest, "no signable transactions: all entries are foreign. Use /plan to preview group building without signing"
	}

	// Step 4: Calculate dummy requirements based on total LSig byte load
	// Skip dummy calculation entirely if group has passthrough transactions
	// (passthrough implies pre-grouped, and we trust the group is already complete)
	var dummiesNeeded int
	var lsigIndices []int
	var feeInfo signing.DummyFeeInfo
	var totalLsigBytes, currentBudget int

	fs.keysLock.RLock()
	lsigSizes := fs.lsigSizesForIdentity(identityID)
	fs.keysLock.RUnlock()

	if hasPassthrough {
		// Passthrough mode: trust the pre-formed group is complete
		// Don't calculate dummies - group structure is fixed
		fmt.Printf("[GROUP] Passthrough mode: trusting pre-formed group structure (no dummy calculation)\n")

		// Still track LSig indices for transactions we'll sign (for logging)
		for i, txReq := range req.Requests {
			if !passthroughIndices[i] {
				if lsigSizes != nil {
					if size, ok := lsigSizes[txReq.AuthAddress]; ok && size > 0 {
						lsigIndices = append(lsigIndices, i)
					}
				}
			}
		}
	} else {
		// Standard mode: calculate LSig budget and dummies needed
		// Sum up total LSig bytes for this group (local keys + foreign lsig_size hints)
		for i, txReq := range req.Requests {
			if foreignIndices[i] {
				// Foreign: use client-provided lsig_size hint
				if txReq.LsigSize > 0 {
					totalLsigBytes += txReq.LsigSize
				}
			} else if lsigSizes != nil {
				if size, ok := lsigSizes[txReq.AuthAddress]; ok {
					totalLsigBytes += size
				}
			}
		}

		// Calculate budget and dummies needed
		// Each transaction contributes TxLsigBudget (1000 bytes) to the group pool
		currentBudget = len(txns) * lsig.TxLsigBudget
		if totalLsigBytes > currentBudget {
			extraBudgetNeeded := totalLsigBytes - currentBudget
			dummiesNeeded = (extraBudgetNeeded + lsig.TxLsigBudget - 1) / lsig.TxLsigBudget // Ceiling division
		}

		// Validate group size limit (Algorand max is 16 transactions)
		const maxGroupSize = 16
		finalGroupSize := len(txns) + dummiesNeeded
		if finalGroupSize > maxGroupSize {
			return nil, http.StatusBadRequest, fmt.Sprintf("group would be %d transactions (max %d) - cannot add %d dummies for LSig budget",
				finalGroupSize, maxGroupSize, dummiesNeeded)
		}

		// Check if we would modify pre-grouped transactions (requires allow_group_modification)
		wouldModifyGroup := isPreGrouped && dummiesNeeded > 0
		if wouldModifyGroup {
			if !fs.config.AllowGroupModification {
				return nil, http.StatusBadRequest, fmt.Sprintf("pre-grouped transactions require %d dummies which would change group ID - enable allow_group_modification in policy or provide ungrouped transactions",
					dummiesNeeded)
			}
			fmt.Printf("[GROUP] WARNING: Will modify pre-grouped transactions (allow_group_modification: true)\n")
		}

		fmt.Printf("[GROUP] LSig budget: %d bytes needed, %d bytes available (%d txns × %d)\n",
			totalLsigBytes, currentBudget, len(txns), lsig.TxLsigBudget)
		if dummiesNeeded > 0 {
			fmt.Printf("[GROUP] Need %d dummy transaction(s) for additional budget\n", dummiesNeeded)
		}

		// Track which transactions are LSig (have lsig_size > 0) for fee distribution
		// Include both local keys and foreign entries with lsig_size hint
		for i, txReq := range req.Requests {
			if foreignIndices[i] {
				if txReq.LsigSize > 0 {
					lsigIndices = append(lsigIndices, i)
				}
			} else if lsigSizes != nil {
				if size, ok := lsigSizes[txReq.AuthAddress]; ok && size > 0 {
					lsigIndices = append(lsigIndices, i)
				}
			}
		}
	}

	// Get minimum fee from algod if available, otherwise use default
	// This is used for both fee calculation and display
	minFee := signing.DefaultMinFee
	if fs.tealCompilerAlgodURL != "" {
		algodClient, err := signing.CreateAlgodClient(fs.tealCompilerAlgodURL, fs.tealCompilerAlgodToken)
		if err == nil && algodClient != nil {
			minFee = signing.GetMinFeeFromAlgod(algodClient)
		}
	}

	// Calculate fee info for display (even before applying)
	if dummiesNeeded > 0 {
		feeInfo = signing.CalculateDummyFees(dummiesNeeded, len(lsigIndices), minFee)
	}

	// Step 5: Add dummies if needed and recompute group ID
	var dummyTxns []types.Transaction
	if dummiesNeeded > 0 {
		// Extract SuggestedParams from first transaction
		firstTxn := txns[0]
		sp := types.SuggestedParams{
			Fee:             types.MicroAlgos(firstTxn.Fee),
			FirstRoundValid: types.Round(firstTxn.FirstValid),
			LastRoundValid:  types.Round(firstTxn.LastValid),
			GenesisID:       firstTxn.GenesisID,
			GenesisHash:     firstTxn.GenesisHash[:],
			FlatFee:         true,
		}

		// Create dummy transactions
		var err error
		dummyTxns, err = lsig.CreateDummyTransactions(dummiesNeeded, sp)
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Sprintf("failed to create dummy transactions: %v", err)
		}

		// Distribute dummy fees across LSig transactions (or fallback to first txn)
		feeInfo, err = signing.ApplyDummyFees(txns, lsigIndices, dummiesNeeded, minFee)
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Sprintf("failed to adjust fees: %v", err)
		}

		// Log fee distribution
		if len(lsigIndices) > 0 {
			fmt.Printf("[GROUP] Distributed %d microAlgos dummy fees across %d LSig txn(s) (~%d each)\n",
				feeInfo.TotalFees, feeInfo.LSigCount, feeInfo.FeePerLSig)
		} else {
			fmt.Printf("[GROUP] Added %d dummy transaction(s), fee on first txn\n", dummiesNeeded)
		}
	}

	// Build final transaction list: [main txns..., dummy txns...]
	allTxns := make([]types.Transaction, 0, len(txns)+len(dummyTxns))
	allTxns = append(allTxns, txns...)
	allTxns = append(allTxns, dummyTxns...)

	// Recompute group ID if needed
	// Cases:
	// - Single ungrouped txn: don't assign group ID (stays empty)
	// - Single pre-grouped txn: preserve existing group ID (client may have other txns elsewhere)
	// - Multiple txns with dummies added or not pre-grouped: compute new group ID
	needsRegroup := dummiesNeeded > 0 || !isPreGrouped
	if needsRegroup && len(allTxns) > 1 {
		// Clear existing group IDs before computing new one
		for i := range allTxns {
			allTxns[i].Group = types.Digest{}
		}

		gid, err := crypto.ComputeGroupID(allTxns)
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Sprintf("failed to compute group ID: %v", err)
		}

		for i := range allTxns {
			allTxns[i].Group = gid
		}

		fmt.Printf("[GROUP] Computed new group ID: %x\n", gid[:8])
	}
	// Note: Single pre-grouped transactions keep their group ID (isPreGrouped=true)
	// Single ungrouped transactions stay ungrouped (group ID already empty)

	return &planResult{
		allTxns:               allTxns,
		dummyTxns:             dummyTxns,
		passthroughIndices:    passthroughIndices,
		passthroughSignedTxns: passthroughSignedTxns,
		foreignIndices:        foreignIndices,
		hasForeign:            hasForeign,
		lsigIndices:           lsigIndices,
		dummiesNeeded:         dummiesNeeded,
		feeInfo:               feeInfo,
		needsRegroup:          needsRegroup,
		isPreGrouped:          isPreGrouped,
		hasPassthrough:        hasPassthrough,
	}, 0, ""
}

// buildMutationReport creates a MutationReport from a planResult and the original request.
func buildMutationReport(plan *planResult, originalCount int) *util.MutationReport {
	groupIDChanged := plan.needsRegroup && len(plan.allTxns) > 1
	if plan.dummiesNeeded == 0 && !groupIDChanged && !plan.hasPassthrough && !plan.hasForeign {
		return nil
	}

	mutations := &util.MutationReport{
		OriginalCount: originalCount,
		FinalCount:    len(plan.allTxns),
	}

	if plan.dummiesNeeded > 0 {
		mutations.DummiesAdded = plan.dummiesNeeded
		mutations.TotalFeesDelta = int(plan.feeInfo.TotalFees)
		mutations.Reason = "lsig_budget"

		// Record which transactions had fees modified
		if len(plan.lsigIndices) > 0 {
			mutations.FeesModified = plan.lsigIndices
		} else {
			// Fees added to first transaction when no LSig transactions
			mutations.FeesModified = []int{0}
		}
	}

	if groupIDChanged {
		mutations.GroupIDChanged = true
	}

	if plan.hasPassthrough {
		mutations.PassthroughCount = len(plan.passthroughIndices)
		if mutations.Reason == "" {
			mutations.Reason = "passthrough"
		}
	}

	if plan.hasForeign {
		mutations.ForeignCount = len(plan.foreignIndices)
		if mutations.Reason == "" {
			mutations.Reason = "foreign"
		}
	}

	return mutations
}

// handleSign handles the /sign endpoint for signing transactions.
// Supports single transactions and transaction groups with:
// - Automatic dummy transaction creation for large LogicSigs
// - Fee pooling across the group
// - Two-checkpoint approval (group level + per-transaction)
func (fs *Signer) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, util.GroupSignResponse{Error: "Method not allowed"})
		return
	}

	// Check if signer is locked (e.g., after inactivity timeout)
	if fs.hub != nil && !fs.hub.IsUnlocked() {
		writeJSON(w, http.StatusForbidden, util.GroupSignResponse{Error: "signer is locked"})
		return
	}

	// Reset inactivity timer on each signing request
	fs.resetSessionTimer()

	// Extract authenticated identity from context
	identity := auth.IdentityFromContext(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, util.GroupSignResponse{Error: "no authenticated identity"})
		return
	}
	identityID := identity.ID

	var req util.GroupSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, util.GroupSignResponse{Error: "Invalid JSON"})
		return
	}

	// Phase 1: Group building (shared with /plan)
	plan, status, errMsg := fs.planGroup(identityID, req)
	if plan == nil {
		writeJSON(w, status, util.GroupSignResponse{Error: errMsg})
		return
	}

	allTxns := plan.allTxns
	passthroughIndices := plan.passthroughIndices
	passthroughSignedTxns := plan.passthroughSignedTxns
	foreignIndices := plan.foreignIndices
	hasForeign := plan.hasForeign
	dummiesNeeded := plan.dummiesNeeded
	feeInfo := plan.feeInfo
	hasPassthrough := plan.hasPassthrough
	dummyTxns := plan.dummyTxns

	// Reconstruct txns (original request transactions, before dummies)
	txns := allTxns[:len(req.Requests)]

	// Phase 2: Approval + signing (only in handleSign)

	// Step 6: Group-level approval via apadmin TUI
	// Check if signer is locked
	if fs.hub != nil && !fs.hub.IsUnlocked() {
		writeJSON(w, http.StatusServiceUnavailable, util.GroupSignResponse{Error: "Signer is locked - unlock via apadmin TUI first"})
		return
	}

	// Build combined description for all transactions
	var groupDescBuilder strings.Builder
	isSingleTxn := len(req.Requests) == 1 && dummiesNeeded == 0
	if isSingleTxn {
		groupDescBuilder.WriteString("=== SINGLE TRANSACTION ===\n\n")
	} else {
		groupDescBuilder.WriteString(fmt.Sprintf("=== TRANSACTION GROUP (%d transactions) ===\n", len(req.Requests)))
		if hasPassthrough {
			groupDescBuilder.WriteString(fmt.Sprintf("[MIXED MODE: %d to sign, %d passthrough]\n", len(req.Requests)-len(passthroughIndices), len(passthroughIndices)))
		}
		if hasForeign {
			signCount := len(req.Requests) - len(foreignIndices)
			groupDescBuilder.WriteString(fmt.Sprintf("[MULTI-PARTY: %d to sign, %d foreign (not signing)]\n", signCount, len(foreignIndices)))
		}
		if dummiesNeeded > 0 {
			groupDescBuilder.WriteString("[MODIFIED BY SERVER]\n")
			groupDescBuilder.WriteString(fmt.Sprintf("  • Added %d dummy transaction(s) for LSig budget\n", dummiesNeeded))
			// Disclose fee adjustment so operator knows exact economic impact
			if feeInfo.LSigCount > 0 {
				groupDescBuilder.WriteString(fmt.Sprintf("  • Fee adjustment: +%d microAlgos across %d LSig txn(s)\n", feeInfo.TotalFees, feeInfo.LSigCount))
			} else {
				groupDescBuilder.WriteString(fmt.Sprintf("  • Fee adjustment: +%d microAlgos on first txn\n", feeInfo.TotalFees))
			}
			groupDescBuilder.WriteString("  • Group ID recomputed\n")
		}
		groupDescBuilder.WriteString("\n")
	}

	var firstValid, lastValid uint64
	for i := range req.Requests {
		if !isSingleTxn {
			if passthroughIndices[i] {
				groupDescBuilder.WriteString(fmt.Sprintf("--- Transaction %d of %d [PASSTHROUGH] ---\n", i+1, len(req.Requests)))
			} else if foreignIndices[i] {
				groupDescBuilder.WriteString(fmt.Sprintf("--- Transaction %d of %d [FOREIGN - not signing] ---\n", i+1, len(req.Requests)))
			} else {
				groupDescBuilder.WriteString(fmt.Sprintf("--- Transaction %d of %d ---\n", i+1, len(req.Requests)))
			}
		}
		// Use modified transaction (with adjusted fees/group ID) for description
		desc := generateTransactionDescriptionFromTxn(allTxns[i])
		groupDescBuilder.WriteString(desc)
		groupDescBuilder.WriteString("\n")

		// Extract validity window from first transaction
		if i == 0 {
			firstValid = uint64(allTxns[0].FirstValid)
			lastValid = uint64(allTxns[0].LastValid)
		}
	}

	groupDesc := groupDescBuilder.String()
	fmt.Println("\n" + strings.Repeat("-", 60))
	if isSingleTxn {
		fmt.Println("SIGNATURE REQUEST")
	} else {
		fmt.Println("GROUP SIGNATURE REQUEST")
	}
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println(groupDesc)
	_ = os.Stdout.Sync()

	// Step 6: Policy linting (Layer 1)
	// Hard constraints - if failed, reject immediately (no human override)
	// NOTE: We lint allTxns (final output) not txns (client request) so that
	// fee adjustments, dummies, and regrouping are reflected in policy checks.
	isGroup := len(req.Requests) > 1

	if isGroup {
		// Group policy linter (includes dummies if added)
		if err := util.CheckGroupPolicyLinter(allTxns); err != nil {
			fmt.Printf("[POLICY LINTER] Group rejected: %v\n", err)
			_ = os.Stdout.Sync()
			writeJSON(w, http.StatusForbidden, util.GroupSignResponse{Error: fmt.Sprintf("policy linter rejected group: %v", err)})
			return
		}
	}

	// Transaction policy linter (for all transactions including dummies)
	for i, txn := range allTxns {
		if err := util.CheckTxnPolicyLinter(txn, txn.Sender.String()); err != nil {
			fmt.Printf("[POLICY LINTER] Transaction %d rejected: %v\n", i+1, err)
			_ = os.Stdout.Sync()
			writeJSON(w, http.StatusForbidden, util.GroupSignResponse{Error: fmt.Sprintf("policy linter rejected transaction %d: %v", i+1, err)})
			return
		}
	}

	// Step 7: Human approval (Layer 2)
	// - Single transactions: transaction-level approval only
	// - Groups: group-level approval only (no per-transaction approval)

	if isGroup {
		// === GROUP PATH: Group-level human approval ===
		groupApproved := false

		if fs.config.GroupAutoApprove {
			groupApproved = true
			fmt.Println("[POLICY] Group auto-approved (group_auto_approve: true)")
			_ = os.Stdout.Sync()
		}

		if !groupApproved {
			// Request group-level approval via apadmin TUI
			if fs.hub == nil || !fs.hub.HasClient() {
				writeJSON(w, http.StatusServiceUnavailable, util.GroupSignResponse{Error: "no apadmin connected - cannot approve group request"})
				return
			}

			requestID := fmt.Sprintf("grp-%d", time.Now().UnixNano())
			fmt.Printf("[IPC] GROUP APPROVAL: Waiting for approval from apadmin TUI (request %s)...\n", requestID[:20])
			_ = os.Stdout.Sync()

			displaySender := fmt.Sprintf("GROUP(%d txns)", len(req.Requests))

			// Find first non-foreign auth_address for display
			groupAuthAddr := ""
			for _, txReq := range req.Requests {
				if txReq.AuthAddress != "" {
					groupAuthAddr = txReq.AuthAddress
					break
				}
			}

			approved, err := fs.hub.RequestSigningApproval(
				requestID,
				groupAuthAddr,
				displaySender,
				"[GROUP APPROVAL]\n"+groupDesc,
				firstValid,
				lastValid,
				nil, // No policy violations at group level
				5*time.Minute,
			)
			if err != nil {
				fmt.Printf("[X] Group approval error: %v\n", err)
				_ = os.Stdout.Sync()
				writeJSON(w, http.StatusServiceUnavailable, util.GroupSignResponse{Error: fmt.Sprintf("group approval error: %v", err)})
				return
			}
			if !approved {
				fmt.Println("[X] GROUP REQUEST REJECTED")
				_ = os.Stdout.Sync()
				if fs.auditLog != nil {
					for i, txReq := range req.Requests {
						authAddr := txReq.AuthAddress
						if foreignIndices[i] {
							authAddr = ""
						}
						fs.auditLog.LogSignRejected(identityID, authAddr, txns[i].Sender.String(), "group_rejected_by_operator")
					}
				}
				writeJSON(w, http.StatusForbidden, util.GroupSignResponse{Error: "Group request rejected by operator"})
				return
			}

			fmt.Println("[OK] GROUP APPROVED")
			_ = os.Stdout.Sync()
		}
		// Groups: no transaction-level approval needed
	} else {
		// === SINGLE TRANSACTION PATH: Transaction-level human approval ===
		// Single transaction: apply transaction-level human approval
		txReq := req.Requests[0]
		txnApproved := false
		approvalReason := ""

		// SECURITY: Use decoded sender from transaction, not client-provided TxnSender
		// This prevents allowlist bypass by spoofing TxnSender field
		decodedSender := txns[0].Sender.String()

		// Use modified transaction bytes for policy checks (with adjusted fees/group ID)
		modifiedTxnBytes := encodeTxnToBytes(allTxns[0])

		// Validation transactions (0 ALGO self-send) are always auto-approved, even without a policy file
		if isValidationTransaction(modifiedTxnBytes, decodedSender, txReq.AuthAddress) {
			txnApproved = true
			approvalReason = "validation transaction (0 ALGO self-send)"
		}

		if !txnApproved {
			// Check txn_auto_approve
			if fs.config.EffectiveTxnAutoApprove() {
				txnApproved = true
				approvalReason = "txn_auto_approve: true"
			}
		}

		if txnApproved {
			fmt.Printf("[POLICY] Txn auto-approved (%s)\n", approvalReason)
			_ = os.Stdout.Sync()
		} else {
			// Request single-signer approval via apadmin TUI
			if fs.hub == nil || !fs.hub.HasClient() {
				writeJSON(w, http.StatusServiceUnavailable, util.GroupSignResponse{Error: "no apadmin connected - cannot approve transaction"})
				return
			}

			requestID := fmt.Sprintf("txn-%d", time.Now().UnixNano())
			fmt.Println("[IPC] TXN APPROVAL: Waiting for approval from apadmin TUI...")
			_ = os.Stdout.Sync()

			// Generate description for this transaction using modified txn
			txnDesc := "[TXN APPROVAL]\n"
			if dummiesNeeded > 0 {
				txnDesc += "[MODIFIED: Fee adjusted for dummy transactions]\n"
			}
			txnDesc += generateTransactionDescriptionFromTxn(allTxns[0])

			// Check for policy violations using modified transaction
			modifiedTxnHex := encodeTxnToHex(allTxns[0])
			violations := util.CheckTxnWarnings(modifiedTxnHex)

			// SECURITY: Use decoded sender for TUI display, not client-provided TxnSender
			approved, err := fs.hub.RequestSigningApproval(
				requestID,
				txReq.AuthAddress,
				decodedSender, // Use decoded sender, not txReq.TxnSender
				txnDesc,
				firstValid,
				lastValid,
				violations,
				5*time.Minute,
			)
			if err != nil {
				fmt.Printf("[X] Txn approval error: %v\n", err)
				_ = os.Stdout.Sync()
				writeJSON(w, http.StatusServiceUnavailable, util.GroupSignResponse{Error: fmt.Sprintf("txn approval error: %v", err)})
				return
			}
			if !approved {
				fmt.Println("[X] TXN REJECTED")
				_ = os.Stdout.Sync()
				if fs.auditLog != nil {
					fs.auditLog.LogSignRejected(identityID, txReq.AuthAddress, decodedSender, "txn_rejected_by_operator")
				}
				writeJSON(w, http.StatusForbidden, util.GroupSignResponse{Error: "Transaction rejected by operator"})
				return
			}

			fmt.Println("[OK] TXN APPROVED")
			_ = os.Stdout.Sync()
		}
	}
	_ = os.Stdout.Sync()

	// Step 7: Sign each transaction

	// Prepare passphrase callback for key decryption
	promptPassphrase := func() ([]byte, error) {
		fs.passphraseLock.RLock()
		defer fs.passphraseLock.RUnlock()
		if fs.encryptionPassphrase == nil || fs.encryptionPassphrase.IsEmpty() {
			return nil, fmt.Errorf("signer not unlocked - connect apadmin to unlock")
		}
		var passphraseCopy []byte
		err := fs.encryptionPassphrase.WithBytes(func(p []byte) error {
			passphraseCopy = make([]byte, len(p))
			copy(passphraseCopy, p)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return passphraseCopy, nil
	}

	signedTxns := make([]string, len(allTxns))

	// Snapshot keySession pointer under lock to avoid racing with hub.lock()
	fs.passphraseLock.RLock()
	session := fs.keySession
	fs.passphraseLock.RUnlock()

	// Sign main transactions (or passthrough/foreign ones)
	for i := 0; i < len(txns); i++ {
		// Check if this is a passthrough transaction
		if passthroughIndices[i] {
			// Passthrough: use the pre-signed transaction bytes directly
			signedTxns[i] = hex.EncodeToString(passthroughSignedTxns[i])
			fmt.Printf("  [%d] passthrough (included as-is)\n", i+1)
			continue
		}

		// Check if this is a foreign transaction
		if foreignIndices[i] {
			// Foreign: not signed by this signer
			signedTxns[i] = ""
			fmt.Printf("  [%d] foreign (not signed)\n", i+1)
			continue
		}

		txn := allTxns[i]
		authAddr := req.Requests[i].AuthAddress
		// SECURITY: Use decoded sender for audit logs, not client-provided TxnSender
		txnSender := txns[i].Sender.String()
		lsigArgs := req.Requests[i].LsigArgs

		// Get key material
		keyMaterial, err := session.GetKey(authAddr, promptPassphrase)
		if err != nil {
			if fs.auditLog != nil {
				fs.auditLog.LogSignFailed(identityID, authAddr, txnSender, fmt.Sprintf("failed to load key: %v", err))
			}
			writeJSON(w, http.StatusInternalServerError, util.GroupSignResponse{Error: fmt.Sprintf("transaction %d: failed to load key: %v", i+1, err)})
			return
		}

		keyType := keyMaterial.Type
		var signedTxnBytes []byte

		if keys.IsGenericLSigType(keyType) {
			// Generic LogicSig - no crypto signature needed
			provider := lsigprovider.Get(keyType)
			if provider == nil {
				algocrypto.ZeroBytes(keyMaterial.Bytecode)
				writeJSON(w, http.StatusInternalServerError, util.GroupSignResponse{Error: fmt.Sprintf("transaction %d: provider not found for key type %s", i+1, keyType)})
				return
			}

			// Decode runtime args from hex
			decodedArgs, err := decodeRuntimeArgs(lsigArgs)
			if err != nil {
				algocrypto.ZeroBytes(keyMaterial.Bytecode)
				writeJSON(w, http.StatusBadRequest, util.GroupSignResponse{Error: fmt.Sprintf("transaction %d: %v", i+1, err)})
				return
			}

			// Build args using provider (no signature for generic LSigs)
			orderedArgsBytes, err := provider.BuildArgs(nil, decodedArgs)
			if err != nil {
				algocrypto.ZeroBytes(keyMaterial.Bytecode)
				writeJSON(w, http.StatusBadRequest, util.GroupSignResponse{Error: fmt.Sprintf("transaction %d: %v", i+1, err)})
				return
			}

			lsigAcct := crypto.LogicSigAccount{
				Lsig: types.LogicSig{
					Logic: keyMaterial.Bytecode,
					Args:  orderedArgsBytes,
				},
			}
			_, signedTxnBytes, err = crypto.SignLogicSigAccountTransaction(lsigAcct, txn)
			if err != nil {
				algocrypto.ZeroBytes(keyMaterial.Bytecode)
				if fs.auditLog != nil {
					fs.auditLog.LogSignFailed(identityID, authAddr, txnSender, fmt.Sprintf("generic lsig sign failed: %v", err))
				}
				writeJSON(w, http.StatusInternalServerError, util.GroupSignResponse{Error: fmt.Sprintf("transaction %d: failed to sign: %v", i+1, err)})
				return
			}
			algocrypto.ZeroBytes(keyMaterial.Bytecode)
		} else {
			// Ed25519 or DSA-based LogicSig
			provider := signing.GetProvider(keyType)
			if provider == nil {
				writeJSON(w, http.StatusInternalServerError, util.GroupSignResponse{Error: fmt.Sprintf("transaction %d: unsupported key type: %s", i+1, keyType)})
				return
			}
			// Determine what to sign based on key type
			var messageBytes []byte
			if keyMaterial.Bytecode != nil {
				// DSA-based LogicSig (e.g., Falcon) - sign txn ID
				txnID := crypto.TransactionID(txn)
				messageBytes = txnID[:]
			} else {
				// Ed25519 - sign full TX + msgpack bytes
				messageBytes = append([]byte("TX"), msgpack.Encode(txn)...)
			}

			sig, err := provider.SignMessage(keyMaterial, messageBytes)
			if err != nil {
				provider.ZeroKey(keyMaterial)
				if fs.auditLog != nil {
					fs.auditLog.LogSignFailed(identityID, authAddr, txnSender, fmt.Sprintf("sign failed: %v", err))
				}
				writeJSON(w, http.StatusInternalServerError, util.GroupSignResponse{Error: fmt.Sprintf("transaction %d: failed to sign: %v", i+1, err)})
				return
			}

			if keyMaterial.Bytecode != nil {
				// DSA-based LogicSig - use BuildArgs for proper arg ordering
				lsigProvider := lsigprovider.Get(keyType)
				if lsigProvider == nil {
					provider.ZeroKey(keyMaterial)
					writeJSON(w, http.StatusInternalServerError, util.GroupSignResponse{Error: fmt.Sprintf("transaction %d: provider not found for key type %s", i+1, keyType)})
					return
				}

				// Decode runtime args from hex
				decodedArgs, err := decodeRuntimeArgs(lsigArgs)
				if err != nil {
					provider.ZeroKey(keyMaterial)
					writeJSON(w, http.StatusBadRequest, util.GroupSignResponse{Error: fmt.Sprintf("transaction %d: %v", i+1, err)})
					return
				}

				// Build args using provider (signature + runtime args)
				lsigArgBytes, err := lsigProvider.BuildArgs(sig, decodedArgs)
				if err != nil {
					provider.ZeroKey(keyMaterial)
					writeJSON(w, http.StatusBadRequest, util.GroupSignResponse{Error: fmt.Sprintf("transaction %d: %v", i+1, err)})
					return
				}

				lsigAcct := crypto.LogicSigAccount{
					Lsig: types.LogicSig{
						Logic: keyMaterial.Bytecode,
						Args:  lsigArgBytes,
					},
				}
				_, signedTxnBytes, err = crypto.SignLogicSigAccountTransaction(lsigAcct, txn)
				if err != nil {
					provider.ZeroKey(keyMaterial)
					if fs.auditLog != nil {
						fs.auditLog.LogSignFailed(identityID, authAddr, txnSender, fmt.Sprintf("lsig assembly failed: %v", err))
					}
					writeJSON(w, http.StatusInternalServerError, util.GroupSignResponse{Error: fmt.Sprintf("transaction %d: failed to assemble lsig txn: %v", i+1, err)})
					return
				}
			} else {
				// Ed25519
				var sigArr types.Signature
				copy(sigArr[:], sig)
				stxn := types.SignedTxn{
					Txn: txn,
					Sig: sigArr,
				}
				// Set AuthAddr if rekeyed
				if authAddr != txnSender && txnSender != "" {
					authAddrDecoded, _ := types.DecodeAddress(authAddr)
					stxn.AuthAddr = authAddrDecoded
				}
				signedTxnBytes = msgpack.Encode(stxn)
			}
			provider.ZeroKey(keyMaterial)
		}

		signedTxns[i] = hex.EncodeToString(signedTxnBytes)
		fmt.Printf("  [%d] signed (%s)\n", i+1, keyType)
	}

	// Sign dummy transactions (use allTxns slice which has updated group ID)
	if len(dummyTxns) > 0 {
		signedDummyBytes, err := lsig.SignDummyTransactions(allTxns[len(txns):])
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, util.GroupSignResponse{Error: fmt.Sprintf("failed to sign dummy transactions: %v", err)})
			return
		}
		for i, stxnBytes := range signedDummyBytes {
			signedTxns[len(txns)+i] = hex.EncodeToString(stxnBytes)
			fmt.Printf("  [%d] signed (dummy)\n", len(txns)+i+1)
		}
	}

	signedCount := len(req.Requests) - len(passthroughIndices) - len(foreignIndices)
	if hasPassthrough || hasForeign {
		parts := []string{fmt.Sprintf("%d signed", signedCount)}
		if hasPassthrough {
			parts = append(parts, fmt.Sprintf("%d passthrough", len(passthroughIndices)))
		}
		if hasForeign {
			parts = append(parts, fmt.Sprintf("%d foreign", len(foreignIndices)))
		}
		fmt.Printf("[GROUP] Successfully processed %d transaction(s) (%s)\n",
			len(signedTxns), strings.Join(parts, ", "))
	} else {
		fmt.Printf("[GROUP] Successfully signed %d transaction(s)\n", len(signedTxns))
	}

	// Audit log: all transactions processed successfully
	if fs.auditLog != nil {
		for i, txReq := range req.Requests {
			// SECURITY: Use decoded sender for audit logs, not client-provided TxnSender
			if passthroughIndices[i] {
				fs.auditLog.LogSignApproved(identityID, "", txns[i].Sender.String(), fmt.Sprintf("txn %d/%d passthrough", i+1, len(req.Requests)))
			} else if foreignIndices[i] {
				fs.auditLog.LogSignApproved(identityID, "", txns[i].Sender.String(), fmt.Sprintf("txn %d/%d foreign", i+1, len(req.Requests)))
			} else {
				fs.auditLog.LogSignApproved(identityID, txReq.AuthAddress, txns[i].Sender.String(), fmt.Sprintf("txn %d/%d signed", i+1, len(req.Requests)))
			}
		}
	}

	// Build mutation report if server made any modifications or has passthrough
	mutations := buildMutationReport(plan, len(req.Requests))

	response := util.GroupSignResponse{
		Signed:    signedTxns,
		Mutations: mutations,
	}

	writeJSON(w, http.StatusOK, response)
}

// handlePlan handles the /plan endpoint for previewing group building.
// Same input as /sign, but only executes the group-building phase:
// validates, decodes, checks keys, calculates dummies, creates dummies,
// pools fees, and computes group ID. No keys are touched, no approval flow.
func (fs *Signer) handlePlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, util.GroupPlanResponse{Error: "Method not allowed"})
		return
	}

	// Check if signer is locked
	if fs.hub != nil && !fs.hub.IsUnlocked() {
		writeJSON(w, http.StatusForbidden, util.GroupPlanResponse{Error: "signer is locked"})
		return
	}

	// Reset inactivity timer
	fs.resetSessionTimer()

	// Extract authenticated identity from context
	identity := auth.IdentityFromContext(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, util.GroupPlanResponse{Error: "no authenticated identity"})
		return
	}
	identityID := identity.ID

	var req util.GroupSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, util.GroupPlanResponse{Error: "Invalid JSON"})
		return
	}

	plan, status, errMsg := fs.planGroup(identityID, req)
	if plan == nil {
		writeJSON(w, status, util.GroupPlanResponse{Error: errMsg})
		return
	}

	// Encode each transaction in the final group as TX-prefixed hex
	txnHexes := make([]string, len(plan.allTxns))
	for i, txn := range plan.allTxns {
		txnHexes[i] = encodeTxnToHex(txn)
	}

	mutations := buildMutationReport(plan, len(req.Requests))

	writeJSON(w, http.StatusOK, util.GroupPlanResponse{
		Transactions: txnHexes,
		Mutations:    mutations,
	})
}

func (fs *Signer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "healthy",
		"service": "Signer",
	})
}

// decodeRuntimeArgs decodes hex-encoded runtime args to bytes.
func decodeRuntimeArgs(lsigArgs map[string]string) (map[string][]byte, error) {
	if len(lsigArgs) == 0 {
		return nil, nil
	}
	decoded := make(map[string][]byte, len(lsigArgs))
	for name, hexValue := range lsigArgs {
		bytes, err := hex.DecodeString(hexValue)
		if err != nil {
			return nil, fmt.Errorf("invalid hex for arg %s: %w", name, err)
		}
		decoded[name] = bytes
	}
	return decoded, nil
}

// RuntimeArgInfo describes a runtime argument for generic LogicSig keys.
// Position is implicit: the index in the RuntimeArgs slice corresponds to the TEAL arg index.
type RuntimeArgInfo struct {
	Name        string `json:"name"`                  // Internal name for --lsig-arg (e.g., "preimage")
	Label       string `json:"label"`                 // Human-readable label for UI
	Description string `json:"description,omitempty"` // Help text
	Type        string `json:"type"`                  // "bytes", "string", "uint64"
	Required    bool   `json:"required"`              // If true, must be provided at signing time
	ByteLength  int    `json:"byte_length,omitempty"` // Expected byte length (0 = variable)
}

// KeyInfoResponse represents key information returned by the /keys endpoint
type KeyInfoResponse struct {
	Address       string           `json:"address"`
	PublicKeyHex  string           `json:"public_key_hex"`
	KeyType       string           `json:"key_type"`
	LsigSize      int              `json:"lsig_size,omitempty"`       // Total LogicSig size (bytecode + crypto sig) for budget calculation
	IsGenericLsig bool             `json:"is_generic_lsig,omitempty"` // True if no crypto signature needed
	RuntimeArgs   []RuntimeArgInfo `json:"runtime_args,omitempty"`    // Runtime arguments for generic LogicSigs (position = index)
}

// KeyTypeInfo represents a key type available for generation, returned by the /keytypes endpoint
type KeyTypeInfo struct {
	KeyType           string              `json:"key_type"`
	Family            string              `json:"family"`
	DisplayName       string              `json:"display_name"`
	Description       string              `json:"description"`
	RequiresLogicSig  bool                `json:"requires_logicsig"`
	MnemonicWordCount int                 `json:"mnemonic_word_count"`
	MnemonicScheme    string              `json:"mnemonic_scheme"`
	CreationParams    []CreationParamInfo `json:"creation_params"`
	RuntimeArgs       []RuntimeArgInfo    `json:"runtime_args"`
}

// CreationParamInfo describes a parameter required to generate a key of a given type
type CreationParamInfo struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type"` // "address", "uint64", "string", "bytes"
	Required    bool   `json:"required"`
	Example     string `json:"example,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
	Default     string `json:"default,omitempty"`
}

// buildKeyInfoList assembles the list of key information from cached data.
// No decryption needed - all data was extracted during Scan().
func (fs *Signer) buildKeyInfoList(identityID string) []KeyInfoResponse {
	// Handle nil keyStore (e.g., in tests)
	if fs.keyStore == nil {
		return []KeyInfoResponse{}
	}

	// Read all cached data with single lock acquisition
	fs.keysLock.RLock()
	idKeys := fs.keysForIdentity(identityID)
	idKeyTypes := fs.keyTypesForIdentity(identityID)
	idLsigSizes := fs.lsigSizesForIdentity(identityID)

	keysCopy := make(map[string]string, len(idKeys))
	for k, v := range idKeys {
		keysCopy[k] = v
	}
	keyTypesCopy := make(map[string]string, len(idKeyTypes))
	for k, v := range idKeyTypes {
		keyTypesCopy[k] = v
	}
	lsigSizesCopy := make(map[string]int, len(idLsigSizes))
	for k, v := range idLsigSizes {
		lsigSizesCopy[k] = v
	}
	fs.keysLock.RUnlock()

	// Get public key hex map from keystore cache (no decryption)
	publicKeyHexMap := fs.keyStore.GetPublicKeyHexMap()

	// Build response list from cached data
	keyList := make([]KeyInfoResponse, 0, len(keysCopy))
	for address := range keysCopy {
		keyType := keyTypesCopy[address]
		isGeneric := keys.IsGenericLSigType(keyType)

		keyInfo := KeyInfoResponse{
			Address:       address,
			PublicKeyHex:  publicKeyHexMap[address],
			KeyType:       keyType,
			LsigSize:      lsigSizesCopy[address],
			IsGenericLsig: isGeneric,
		}

		// Include runtime args schema if the provider has any
		// This applies to both generic LogicSigs and DSA LogicSigs with constraints
		if provider := lsigprovider.Get(keyType); provider != nil {
			runtimeArgDefs := provider.RuntimeArgs()
			if len(runtimeArgDefs) > 0 {
				keyInfo.RuntimeArgs = make([]RuntimeArgInfo, len(runtimeArgDefs))
				for i, argDef := range runtimeArgDefs {
					keyInfo.RuntimeArgs[i] = RuntimeArgInfo{
						Name:        argDef.Name,
						Label:       argDef.Label,
						Description: argDef.Description,
						Type:        argDef.Type,
						Required:    argDef.Required,
						ByteLength:  argDef.ByteLength,
					}
				}
			}
		}

		keyList = append(keyList, keyInfo)
	}

	return keyList
}

// computeKeysChecksum computes a checksum from sorted addresses in the keys map for the given identity.
// This is cheap (no decryption needed) and can be used to detect changes.
func (fs *Signer) computeKeysChecksum(identityID string) string {
	fs.keysLock.RLock()
	idKeys := fs.keysForIdentity(identityID)
	addresses := make([]string, 0, len(idKeys))
	for addr := range idKeys {
		addresses = append(addresses, addr)
	}
	fs.keysLock.RUnlock()

	sort.Strings(addresses)
	combined := strings.Join(addresses, ",")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:8]) // 16 hex chars (64 bits)
}

func (fs *Signer) handleKeys(w http.ResponseWriter, r *http.Request) {
	// Check if signer is locked
	if fs.hub != nil && !fs.hub.IsUnlocked() {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"error": "signer is locked",
		})
		return
	}

	// Extract authenticated identity from context
	identity := auth.IdentityFromContext(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"error": "no authenticated identity",
		})
		return
	}
	identityID := identity.ID

	// Compute current checksum (cheap - no decryption)
	currentChecksum := fs.computeKeysChecksum(identityID)

	// Check if client sent a checksum
	clientChecksum := r.Header.Get("X-Keys-Checksum")
	if clientChecksum != "" && clientChecksum == currentChecksum {
		// Checksums match - client cache is valid
		w.Header().Set("X-Keys-Checksum", currentChecksum)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Checksums differ or no checksum provided - send full list
	keyList := fs.buildKeyInfoList(identityID)
	w.Header().Set("X-Keys-Checksum", currentChecksum)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"count": len(keyList),
		"keys":  keyList,
	})
}

// handleTokenProvisioning handles token provisioning requests from SSH.
// It requests approval from the connected apadmin and returns the token if approved.
func (fs *Signer) handleTokenProvisioning(identityID, sshFingerprint, remoteAddr string) (string, error) {
	// Generate a unique request ID
	requestID := fmt.Sprintf("token-%d", time.Now().UnixNano())

	// Request approval from apadmin (5 minute timeout like signing)
	approved, err := fs.hub.RequestTokenProvisioning(requestID, identityID, sshFingerprint, remoteAddr, 5*time.Minute)
	if err != nil {
		return "", err
	}
	if !approved {
		return "", fmt.Errorf("token provisioning rejected by operator")
	}

	// Load (or generate) the token for this identity
	token, err := util.LoadaPlaneToken(identityID)
	if err != nil {
		return "", fmt.Errorf("failed to load token: %w", err)
	}

	// Audit log
	if fs.auditLog != nil {
		fs.auditLog.LogTokenProvisioned(identityID, sshFingerprint, remoteAddr)
	}

	fmt.Printf("✓ Token provisioned for identity '%s' to %s (key: %s)\n", identityID, remoteAddr, sshFingerprint)
	return token, nil
}

// handleKeyTypes returns all available key types with their creation parameter schemas.
func (fs *Signer) handleKeyTypes(w http.ResponseWriter, _ *http.Request) {
	validTypes := keymgmt.GetValidKeyTypes()
	keyTypes := make([]KeyTypeInfo, 0, len(validTypes))

	for _, keyType := range validTypes {
		info := KeyTypeInfo{
			KeyType:        keyType,
			CreationParams: []CreationParamInfo{},
			RuntimeArgs:    []RuntimeArgInfo{},
		}

		// Get algorithm metadata (works for all types)
		meta, err := algorithm.GetMetadata(keyType)
		if err == nil {
			info.Family = meta.Family()
			info.RequiresLogicSig = meta.RequiresLogicSig()
			info.MnemonicWordCount = meta.MnemonicWordCount()
			info.MnemonicScheme = meta.MnemonicScheme()
		} else {
			info.Family = keyType
		}

		// Get LSig provider metadata (display name, description, creation params, runtime args)
		if provider := lsigprovider.Get(keyType); provider != nil {
			info.DisplayName = provider.DisplayName()
			info.Description = provider.Description()

			for _, p := range provider.CreationParams() {
				info.CreationParams = append(info.CreationParams, CreationParamInfo{
					Name:        p.Name,
					Label:       p.Label,
					Description: p.Description,
					Type:        p.Type,
					Required:    p.Required,
					Example:     p.Example,
					Placeholder: p.Placeholder,
					Default:     p.Default,
				})
			}

			for _, a := range provider.RuntimeArgs() {
				info.RuntimeArgs = append(info.RuntimeArgs, RuntimeArgInfo{
					Name:        a.Name,
					Label:       a.Label,
					Description: a.Description,
					Type:        a.Type,
					Required:    a.Required,
					ByteLength:  a.ByteLength,
				})
			}
		} else {
			// Non-LogicSig types (e.g., ed25519) are not in lsigprovider
			info.DisplayName = strings.ToUpper(keyType[:1]) + keyType[1:]
			info.Description = "Native Algorand signing keys"
		}

		keyTypes = append(keyTypes, info)
	}

	// Add generic LogicSig templates (timelock, hashlock, etc.)
	for _, tmpl := range genericlsig.GetAll() {
		info := KeyTypeInfo{
			KeyType:          tmpl.KeyType(),
			Family:           tmpl.Family(),
			DisplayName:      tmpl.DisplayName(),
			Description:      tmpl.Description(),
			RequiresLogicSig: true,
			CreationParams:   []CreationParamInfo{},
			RuntimeArgs:      []RuntimeArgInfo{},
		}

		for _, p := range tmpl.CreationParams() {
			info.CreationParams = append(info.CreationParams, CreationParamInfo{
				Name:        p.Name,
				Label:       p.Label,
				Description: p.Description,
				Type:        p.Type,
				Required:    p.Required,
				Example:     p.Example,
				Placeholder: p.Placeholder,
				Default:     p.Default,
			})
		}

		for _, a := range tmpl.RuntimeArgs() {
			info.RuntimeArgs = append(info.RuntimeArgs, RuntimeArgInfo{
				Name:        a.Name,
				Label:       a.Label,
				Description: a.Description,
				Type:        a.Type,
				Required:    a.Required,
				ByteLength:  a.ByteLength,
			})
		}

		keyTypes = append(keyTypes, info)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"key_types": keyTypes,
	})
}

// AdminGenerateRequest is the request body for POST /admin/generate.
type AdminGenerateRequest struct {
	KeyType    string            `json:"key_type"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

// AdminGenerateResponse is the response body for POST /admin/generate.
type AdminGenerateResponse struct {
	Address    string            `json:"address,omitempty"`
	KeyType    string            `json:"key_type,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// AdminDeleteResponse is the response body for DELETE /admin/keys.
type AdminDeleteResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// handleAdminGenerate handles POST /admin/generate for key generation via REST.
func (fs *Signer) handleAdminGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, AdminGenerateResponse{Error: "Method not allowed"})
		return
	}

	// Check if signer is locked
	if fs.hub != nil && !fs.hub.IsUnlocked() {
		writeJSON(w, http.StatusForbidden, AdminGenerateResponse{Error: "signer is locked"})
		return
	}

	// Reset inactivity timer on admin operations
	fs.resetSessionTimer()

	// Extract authenticated identity from context
	identity := auth.IdentityFromContext(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, AdminGenerateResponse{Error: "no authenticated identity"})
		return
	}
	identityID := identity.ID

	var req AdminGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, AdminGenerateResponse{Error: "invalid JSON"})
		return
	}

	if req.KeyType == "" {
		writeJSON(w, http.StatusBadRequest, AdminGenerateResponse{Error: "key_type is required"})
		return
	}

	// Handle generic LogicSig types (timelock, hashlock, etc.)
	if genericlsig.IsGenericLSigType(req.KeyType) {
		fs.handleAdminGenerateGenericLSig(w, identityID, &req)
		return
	}

	// Standard key types (ed25519, falcon1024, etc.)
	if !keymgmt.IsValidKeyType(req.KeyType) {
		writeJSON(w, http.StatusBadRequest, AdminGenerateResponse{Error: fmt.Sprintf("invalid key type: %s", req.KeyType)})
		return
	}

	masterKey := fs.keyStore.GetMasterKey()
	if masterKey == nil {
		writeJSON(w, http.StatusInternalServerError, AdminGenerateResponse{Error: "master key not available"})
		return
	}

	genResult, err := keymgmt.GenerateKey(req.KeyType, masterKey, req.Parameters)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, AdminGenerateResponse{Error: err.Error()})
		return
	}

	// File watcher auto-reloads keys

	fmt.Printf("✓ Generated new %s key via REST: %s\n", genResult.KeyType, genResult.Address)

	writeJSON(w, http.StatusOK, AdminGenerateResponse{
		Address:    genResult.Address,
		KeyType:    genResult.KeyType,
		Parameters: req.Parameters,
	})
}

// handleAdminGenerateGenericLSig handles generic LogicSig generation for the REST endpoint.
func (fs *Signer) handleAdminGenerateGenericLSig(w http.ResponseWriter, identityID string, req *AdminGenerateRequest) {
	template, err := genericlsig.GetOrError(req.KeyType)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, AdminGenerateResponse{Error: fmt.Sprintf("unknown generic lsig type: %s", req.KeyType)})
		return
	}

	// Create algod client for TEAL compilation
	algodURL := fs.tealCompilerAlgodURL
	if algodURL == "" {
		writeJSON(w, http.StatusInternalServerError, AdminGenerateResponse{Error: "TEAL compilation requires teal_compiler_algod_url to be configured in config.yaml"})
		return
	}
	algodClient, err := algod.MakeClient(algodURL, fs.tealCompilerAlgodToken)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, AdminGenerateResponse{Error: fmt.Sprintf("failed to create algod client: %v", err)})
		return
	}

	if err := template.ValidateCreationParams(req.Parameters); err != nil {
		writeJSON(w, http.StatusBadRequest, AdminGenerateResponse{Error: fmt.Sprintf("parameter validation failed: %v", err)})
		return
	}

	tealSource, err := template.GenerateTEAL(req.Parameters)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, AdminGenerateResponse{Error: fmt.Sprintf("TEAL generation failed: %v", err)})
		return
	}

	bytecode, address, err := template.Compile(req.Parameters, algodClient)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, AdminGenerateResponse{Error: fmt.Sprintf("%s generation failed: %v", template.DisplayName(), err)})
		return
	}

	masterKey := fs.keyStore.GetMasterKey()
	if masterKey == nil {
		writeJSON(w, http.StatusInternalServerError, AdminGenerateResponse{Error: "master key not available"})
		return
	}

	if err := keys.WriteLSigFile(identityID, address, req.KeyType, template.Family(), req.Parameters, bytecode, tealSource, masterKey); err != nil {
		writeJSON(w, http.StatusInternalServerError, AdminGenerateResponse{Error: fmt.Sprintf("failed to save %s file: %v", template.DisplayName(), err)})
		return
	}

	// File watcher auto-reloads keys

	fmt.Printf("✓ Generated %s via REST: %s\n", template.DisplayName(), address)
	fmt.Printf("  TEAL compiler: %s\n", algodURL)
	for _, param := range template.CreationParams() {
		if val, ok := req.Parameters[param.Name]; ok {
			fmt.Printf("  %s: %s\n", param.Label, val)
		}
	}

	writeJSON(w, http.StatusOK, AdminGenerateResponse{
		Address:    address,
		KeyType:    req.KeyType,
		Parameters: req.Parameters,
	})
}

// handleAdminDelete handles DELETE /admin/keys for key deletion via REST.
func (fs *Signer) handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, AdminDeleteResponse{Error: "Method not allowed"})
		return
	}

	// Check if signer is locked
	if fs.hub != nil && !fs.hub.IsUnlocked() {
		writeJSON(w, http.StatusForbidden, AdminDeleteResponse{Error: "signer is locked"})
		return
	}

	// Reset inactivity timer on admin operations
	fs.resetSessionTimer()

	// Extract authenticated identity from context
	identity := auth.IdentityFromContext(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, AdminDeleteResponse{Error: "no authenticated identity"})
		return
	}
	identityID := identity.ID

	address := r.URL.Query().Get("address")
	if address == "" {
		writeJSON(w, http.StatusBadRequest, AdminDeleteResponse{Error: "address query parameter is required"})
		return
	}

	// Look up key file
	fs.keysLock.RLock()
	idKeys := fs.keysForIdentity(identityID)
	var keyFile string
	var exists bool
	if idKeys != nil {
		keyFile, exists = idKeys[address]
	}
	fs.keysLock.RUnlock()

	if !exists {
		writeJSON(w, http.StatusNotFound, AdminDeleteResponse{Error: "key not found: " + address})
		return
	}

	keysDir := filepath.Dir(keyFile)
	delResult, err := keymgmt.DeleteKey(address, keyFile, keysDir, identityID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, AdminDeleteResponse{Error: err.Error()})
		return
	}

	// File watcher auto-reloads keys

	fmt.Printf("✓ Deleted key via REST: %s (moved to %s)\n", address, delResult.DeletedPath)

	writeJSON(w, http.StatusOK, AdminDeleteResponse{Success: true})
}
