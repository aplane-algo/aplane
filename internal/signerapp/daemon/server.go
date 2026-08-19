// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	"github.com/aplane-algo/aplane/internal/signerapp/backupadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/storemut"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/txnutil"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
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

// assembleSignedTransaction creates a complete signed transaction ready for submission.
// It handles Ed25519 (SignedTransaction), LogicSig DSA (LogicSigTransaction with sig in args),
// and generic LogicSig (LogicSigTransaction with just bytecode and args).
//
// Parameters:
//   - txnBytesHex: Full transaction bytes as hex (TX prefix + msgpack)
//   - keyType: Type of key used (ed25519, aplane.falcon1024.v1, aplane.htlc.v1, etc.)
//   - signature: Cryptographic signature (nil for generic lsigs)
//   - bytecode: LogicSig bytecode (nil for ed25519)
//   - orderedArgs: Runtime args for generic lsigs (nil otherwise)
//   - authAddress: Address of the signing key
//   - txnSender: Address of the transaction sender
//
// Returns hex-encoded msgpack of the signed transaction, or error.

type Signer struct {
	runtime           *identity.Runtime                  // The one product identity runtime
	nodeFailState     *identity.NodeFailState            // Process-wide first-error-sticky failure state
	httpAuth          auth.Authenticator                 // Product token authenticator; never selects a runtime
	authorizer        auth.Authorizer                    // Pluggable authorization
	auditLog          *AuditLogger                       // Audit logger for security events
	ipcServer         *IPCServer                         // IPC server for local Unix socket connections
	hub               adminserver.AdminHub               // Process-root admin facade for non-transport code
	sshServer         *sshtunnel.Server                  // SSH tunnel server (nil if SSH disabled)
	sshRuntime        *sshRuntime                        // SSH runtime holder for live listener restarts
	sshRuntimeMu      sync.RWMutex                       // Protects sshRuntime and sshServer swaps
	config            *serverconfig.ServerConfig         // Server configuration (includes policy settings)
	configMu          sync.RWMutex                       // Protects live-mutable ServerConfig fields.
	configMutationMu  sync.Mutex                         // Serializes process-owned config.yaml mutations
	storeMutationLock sync.Mutex                         // Product key/template/config/policy mutation serialization
	restoreAttemptMu  sync.Mutex                         // Protects restoreAttempts lazy initialization
	restoreAttempts   *backupadmin.RestoreAttemptLimiter // Per-archive restore backoff state
	keyPaths          storepaths.Paths                   // Explicit keystore path owner
	dataDir           string                             // Data directory path (for saving config)
	makeAlgod         func(string, string) (*algod.Client, error)
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
func (fs *Signer) ConfigSnapshot() serverconfig.ServerConfig {
	fs.configMu.RLock()
	defer fs.configMu.RUnlock()
	if fs.config == nil {
		return serverconfig.ServerConfig{}
	}
	return fs.config.Clone()
}

func (fs *Signer) withProcessConfigMutation(fn func() error) error {
	fs.configMutationMu.Lock()
	defer fs.configMutationMu.Unlock()
	return fn()
}

func (fs *Signer) withStoreMutation(fn func() error) error {
	fs.storeMutationLock.Lock()
	defer fs.storeMutationLock.Unlock()
	return fn()
}

func (fs *Signer) tryWithStoreInspection(fn func() error) error {
	if !fs.storeMutationLock.TryLock() {
		return errIdentityStoreBusy
	}
	defer fs.storeMutationLock.Unlock()
	return fn()
}

// productIdentityRuntime returns the process-owned product runtime.
func (fs *Signer) productIdentityRuntime() *identity.Runtime {
	return fs.runtime
}

func (fs *Signer) nodeFailure() error {
	if fs.nodeFailState == nil {
		return nil
	}
	return fs.nodeFailState.Err()
}

// RevokeProductToken generates a new API token for the product runtime.
// The token authenticator is updated before active SSH connections for the
// product are closed, so connections authenticated with the old token are
// invalidated after rotation.
func (fs *Signer) RevokeProductToken(ir *identity.Runtime) error {
	var httpUpdater storemut.TokenUpdater
	var tokenGeneration uint64
	if ta, ok := ir.Authenticator().(*auth.TokenAuthenticator); ok {
		httpUpdater = ta
	}

	tokenPath, err := storemut.New(ir.KeyPaths(), httpUpdater, nil).RevokeToken()
	if err != nil {
		return err
	}
	if ta, ok := ir.Authenticator().(*auth.TokenAuthenticator); ok {
		tokenGeneration = ta.Generation()
	}
	if sshServer := fs.currentSSHServer(); sshServer != nil {
		sshServer.CloseProductConnections(tokenGeneration, "token revoked")
	}
	logInfof("api token revoked and regenerated: %s", tokenPath)
	return nil
}
