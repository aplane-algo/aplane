// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/signerapp/backupadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/storemut"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/txnutil"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// maxRequestBodyBytes limits HTTP request body size to prevent DoS via
// oversized payloads. 5MB is well above any legitimate request (a maximal
// 16-txn Falcon group is ~300KB hex-encoded) while still blocking multi-GB abuse.
const maxRequestBodyBytes = 5 * 1024 * 1024

// Signer HTTP contract types live in pkg/signerapi and are re-exported
// internally via internal/signerapi.

// encodeTxnToHex encodes a transaction to TX-prefixed hex string (same format as TxnBytesHex)
func encodeTxnToHex(txn types.Transaction) string {
	return txnutil.EncodeWithPrefixHex(txn)
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
//   - keyType: Type of key used (ed25519, aplane.falcon1024.v1, aplane.timed-whitelist.v1, etc.)
//   - signature: Cryptographic signature (nil for generic lsigs)
//   - bytecode: LogicSig bytecode (nil for ed25519)
//   - orderedArgs: Runtime args for generic lsigs (nil otherwise)
//   - authAddress: Address of the signing key
//   - txnSender: Address of the transaction sender
//
// Returns hex-encoded msgpack of the signed transaction, or error.

type Signer struct {
	registry           *identity.Registry                 // Identity runtime registry
	registryAuth       *identity.RegistryAuthenticator    // Scans all identities to resolve token → identity
	authorizer         auth.Authorizer                    // Pluggable authorization
	auditLog           *AuditLogger                       // Audit logger for security events
	ipcServer          *IPCServer                         // IPC server for local Unix socket connections
	hub                adminproto.AdminHub                // Process-root admin facade for non-transport code
	sshServer          *sshtunnel.Server                  // SSH tunnel server (nil if SSH disabled)
	sshRuntime         *sshRuntime                        // SSH runtime holder for live listener restarts
	sshRuntimeMu       sync.RWMutex                       // Protects sshRuntime and sshServer swaps
	config             *apconfig.ServerConfig             // Server configuration (includes policy settings)
	configMu           sync.RWMutex                       // Protects live-mutable ServerConfig fields.
	configMutationMu   sync.Mutex                         // Serializes process-owned config.yaml mutations
	storeMutationMu    sync.Mutex                         // Protects storeMutationLocks map
	storeMutationLocks map[string]*sync.Mutex             // Per-identity key/template mutation serialization
	restoreAttemptMu   sync.Mutex                         // Protects restoreAttempts lazy initialization
	restoreAttempts    *backupadmin.RestoreAttemptLimiter // Per-identity/archive restore backoff state
	keyPaths           storepaths.Paths                   // Explicit keystore path owner
	dataDir            string                             // Data directory path (for saving config)
	makeAlgod          func(string, string) (*algod.Client, error)
}

func (fs *Signer) storeMutationLock(identityID string) *sync.Mutex {
	fs.storeMutationMu.Lock()
	defer fs.storeMutationMu.Unlock()
	if fs.storeMutationLocks == nil {
		fs.storeMutationLocks = make(map[string]*sync.Mutex)
	}
	lock := fs.storeMutationLocks[identityID]
	if lock == nil {
		lock = &sync.Mutex{}
		fs.storeMutationLocks[identityID] = lock
	}
	return lock
}

// Theme returns the current theme setting. Safe for concurrent use.
func (fs *Signer) Theme() string {
	fs.configMu.RLock()
	defer fs.configMu.RUnlock()
	return fs.config.Theme
}

// SetTheme updates the in-memory theme setting. Safe for concurrent use.
func (fs *Signer) SetTheme(v string) {
	fs.configMu.Lock()
	fs.config.Theme = v
	fs.configMu.Unlock()
}

// ConfigSnapshot returns an independent copy of the process config.
func (fs *Signer) ConfigSnapshot() apconfig.ServerConfig {
	fs.configMu.RLock()
	defer fs.configMu.RUnlock()
	if fs.config == nil {
		return apconfig.ServerConfig{}
	}
	return fs.config.Clone()
}

func (fs *Signer) withProcessConfigMutation(fn func() error) error {
	fs.configMutationMu.Lock()
	defer fs.configMutationMu.Unlock()
	return fn()
}

func (fs *Signer) withIdentityMutation(identityID string, fn func() error) error {
	lock := fs.storeMutationLock(identityID)
	lock.Lock()
	defer lock.Unlock()
	return fn()
}

// productIdentityRuntime returns the identity runtime for the current product identity.
// This is a product-boundary compatibility helper for single-user surfaces.
// Internal identity-aware paths should pass an explicit identity ID instead.
func (fs *Signer) productIdentityRuntime() *identity.Runtime {
	return fs.registry.MustGet(auth.CurrentProductIdentityID())
}

// RevokeTokenForIdentity generates a new API token for the given identity.
// The token authenticator is updated before active SSH connections for the
// identity are closed, so connections authenticated with the old token are
// invalidated after rotation. Other identities' SSH connections remain active.
func (fs *Signer) RevokeTokenForIdentity(ir *identity.Runtime) error {
	var httpUpdater storemut.TokenUpdater
	var tokenGeneration uint64
	if ta, ok := ir.Authenticator().(*auth.TokenAuthenticator); ok {
		httpUpdater = ta
	}

	tokenPath, err := storemut.New(ir.ID(), ir.KeyPaths(), httpUpdater, nil).RevokeToken()
	if err != nil {
		return err
	}
	if ta, ok := ir.Authenticator().(*auth.TokenAuthenticator); ok {
		tokenGeneration = ta.Generation()
	}
	if sshServer := fs.currentSSHServer(); sshServer != nil {
		sshServer.CloseIdentityConnections(ir.ID(), tokenGeneration, "token revoked")
	}
	logInfof("api token revoked and regenerated: %s", tokenPath)
	return nil
}
