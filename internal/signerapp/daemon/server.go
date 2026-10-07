// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	"github.com/aplane-algo/aplane/internal/signerapp/backupadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/clientregistry"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerrest "github.com/aplane-algo/aplane/internal/signerapp/rest"
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
	runtime           *productruntime.Runtime            // The one product runtime
	nodeFailState     *productruntime.NodeFailState      // Process-wide first-error-sticky failure state
	httpAuth          auth.Authenticator                 // Connection-identity authenticator; never selects a runtime
	authorizer        auth.Authorizer                    // Pluggable authorization
	auditLog          *AuditLogger                       // Audit logger for security events
	ipcServer         *IPCServer                         // IPC server for local Unix socket connections
	hub               adminserver.AdminHub               // Process-root admin facade for non-transport code
	sshServer         *sshtunnel.Server                  // SSH tunnel server (nil if SSH disabled)
	sshRuntime        *sshRuntime                        // SSH runtime holder for live listener restarts
	sshRuntimeMu      sync.RWMutex                       // Protects sshRuntime and sshServer swaps
	apiListener       *sshtunnel.APIListener             // Receives tunneled API channels for the HTTP server
	config            *serverconfig.ServerConfig         // Server configuration (includes policy settings)
	configMu          sync.RWMutex                       // Protects live-mutable ServerConfig fields.
	configMutationMu  sync.Mutex                         // Serializes process-owned config.yaml mutations
	storeHealth       signerrest.StoreHealthCache        // Bounds the unauthenticated /health store inspection
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
		return errStoreBusy
	}
	defer fs.storeMutationLock.Unlock()
	return fn()
}

// productRuntime returns the process-owned product runtime.
func (fs *Signer) productRuntime() *productruntime.Runtime {
	return fs.runtime
}

func (fs *Signer) nodeFailure() error {
	if fs.nodeFailState == nil {
		return nil
	}
	return fs.nodeFailState.Err()
}

// RevokeClientKey removes an enrolled client key and closes its connections.
// The registry is published and installed before any connection is closed,
// and the SSH server re-checks enrollment after every handshake, so a
// connection authenticating during the revocation is refused rather than
// registered after the close pass. A revocation that took effect but is not
// yet durable still closes the connections and is audited; the durability
// failure is reported after that.
func (fs *Signer) RevokeClientKey(ctx adminserver.SessionContext, ir *productruntime.Runtime, fingerprint string) (int, error) {
	if ir == nil {
		return 0, protocol.WithCode(protocol.ErrCodeNoRuntimeBound, errors.New("product runtime unavailable"))
	}
	entry, revoked, err := ir.RevokeAuthorizedKey(fingerprint)
	if !revoked {
		if errors.Is(err, clientregistry.ErrNotEnrolled) {
			return 0, protocol.WithCode(protocol.ErrCodeInvalidRequest, fmt.Errorf("client key %s is not enrolled", fingerprint))
		}
		return 0, err
	}
	closed := 0
	if sshServer := fs.currentSSHServer(); sshServer != nil {
		closed = sshServer.CloseConnectionsForFingerprint(fingerprint, "key revoked")
	}
	if fs.auditLog != nil {
		fs.auditLog.LogClientKeyRevokedContext(ctx, fingerprint, entry.Label, closed)
	}
	if err != nil {
		logWarnf("client key revoked: %s (closed %d connection(s)) but the registry write is not yet durable: %v", fingerprint, closed, err)
		return closed, err
	}
	logInfof("client key revoked: %s (closed %d connection(s))", fingerprint, closed)
	return closed, nil
}

// RevokeAllClientKeys removes every enrolled client key and closes every
// client connection: the emergency lever.
func (fs *Signer) RevokeAllClientKeys(ctx adminserver.SessionContext, ir *productruntime.Runtime) (int, int, error) {
	if ir == nil {
		return 0, 0, protocol.WithCode(protocol.ErrCodeNoRuntimeBound, errors.New("product runtime unavailable"))
	}
	entries, revoked, err := ir.RevokeAllAuthorizedKeys()
	if !revoked {
		return 0, 0, err
	}
	closed := 0
	if sshServer := fs.currentSSHServer(); sshServer != nil {
		closed = sshServer.CloseAllClientConnections("all client keys revoked")
	}
	if fs.auditLog != nil {
		for _, entry := range entries {
			fs.auditLog.LogClientKeyRevokedContext(ctx, entry.Fingerprint, entry.Label, 0)
		}
	}
	if err != nil {
		logWarnf("all client keys revoked: %d key(s), closed %d connection(s), but the registry write is not yet durable: %v", len(entries), closed, err)
		return len(entries), closed, err
	}
	logInfof("all client keys revoked: %d key(s), closed %d connection(s)", len(entries), closed)
	return len(entries), closed, nil
}
