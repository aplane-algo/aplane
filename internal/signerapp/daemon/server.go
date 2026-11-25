// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	"github.com/aplane-algo/aplane/internal/signerapp/backupadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	"github.com/aplane-algo/aplane/internal/signerapp/clientregistry"
	"github.com/aplane-algo/aplane/internal/signerapp/enrollqueue"
	"github.com/aplane-algo/aplane/internal/signerapp/externalcheck"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerrest "github.com/aplane-algo/aplane/internal/signerapp/rest"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/storepaths"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// maxRequestBodyBytes limits HTTP request body size to prevent DoS via
// oversized payloads. 5MB is well above any legitimate request (a maximal
// 16-txn Falcon group is ~300KB hex-encoded) while still blocking multi-GB abuse.
const maxRequestBodyBytes = 5 * 1024 * 1024

type Signer struct {
	runtime           *productruntime.Runtime            // The one product runtime
	nodeFailState     *productruntime.NodeFailState      // Process-wide first-error-sticky failure state
	httpAuth          auth.Authenticator                 // Connection-identity authenticator; never selects a runtime
	authorizer        auth.Authorizer                    // Pluggable authorization
	auditLog          *AuditLogger                       // Audit logger for security events
	ipcServer         *IPCServer                         // IPC server for local Unix socket connections
	hub               adminserver.AdminHub               // Process-root admin facade for non-transport code
	sshRuntime        *sshRuntime                        // SSH tunnel server and its lifecycle (nil if SSH disabled)
	sshRuntimeMu      sync.RWMutex                       // Protects sshRuntime swaps
	apiListener       *sshtunnel.APIListener             // Receives tunneled API channels for the HTTP server
	config            *serverconfig.ServerConfig         // Server configuration, fixed after startup
	storeHealth       signerrest.StoreHealthCache        // Bounds the /health and /status store inspection
	storeMutationLock sync.Mutex                         // Product key/template/config/policy mutation serialization
	restoreAttemptMu  sync.Mutex                         // Protects restoreAttempts lazy initialization
	restoreAttempts   *backupadmin.RestoreAttemptLimiter // Per-archive restore backoff state
	keyPaths          storepaths.Paths                   // Explicit keystore path owner
	dataDir           string                             // Data directory path (for saving config)
	makeAlgod         func(string, string) (*algod.Client, error)
	indexerTransport  http.RoundTripper              // Tests answer the Indexer's requests; nil is the default transport
	indexerTimeout    time.Duration                  // Tests shorten a stage lookup; 0 is chainread.DefaultLookupTimeout
	indexerPause      chainread.IndexerPause         // Per-network pause after a failed stage lookup, shared by every chain reader
	externalFetcher   externalcheck.Fetcher          // Makes cosigner external check lookups; one per node, so its per-origin limit covers every request
	rotatingLocks     signersigning.RotatingLocks    // Serializes rotating sign per account
	rotatingReleases  signersigning.ReleaseMemory    // Last release per rotating account, for status; rebuilt from the audit log at unlock
	rotatingRecovery  signersigning.RotatingRecovery // Per-unlock stage recovery allowance and grants, keyed by the lock generation
	stageFillBatch    int                            // Tests shrink the stage table worker's batch; 0 is the default
	stageFillMaxDeriv int                            // Tests bound derivations per unresolved account per pass; 0 is one batch
	invalidReferences invalidReferenceReport         // The cosigner reference entries key type lists last logged as left out
}

// ConfigSnapshot returns an independent copy of the process config. Nothing
// changes the config after startup; the copy keeps a caller from changing
// it.
func (fs *Signer) ConfigSnapshot() serverconfig.ServerConfig {
	if fs.config == nil {
		return serverconfig.ServerConfig{}
	}
	return fs.config.Clone()
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
func (fs *Signer) RevokeClientKey(ctx adminserver.SessionContext, fingerprint string) (int, error) {
	entry, revoked, err := fs.productRuntime().RevokeAuthorizedKey(fingerprint)
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
	fs.notifyEnrollmentChanged(protocol.EnrollmentChangeRevoked, fingerprint)
	if err != nil {
		logWarnf("client key revoked: %s (closed %d connection(s)) but the registry write is not yet durable: %v", fingerprint, closed, err)
		return closed, err
	}
	logInfof("client key revoked: %s (closed %d connection(s))", fingerprint, closed)
	return closed, nil
}

// ApproveClientEnrollment enrolls the key of a waiting request. label, when
// set, replaces the label the client asked for. A key that entered the live
// registry is audited as enrolled even when the write is not yet durable or
// the request could not be cleared; that failure is reported on top.
func (fs *Signer) ApproveClientEnrollment(ctx adminserver.SessionContext, fingerprint, label string) (string, error) {
	label, err := clientregistry.NormalizeLabel(label)
	if err != nil {
		return "", protocol.WithCode(protocol.ErrCodeInvalidRequest, fmt.Errorf("invalid label: %w", err))
	}
	entry, enrolled, cleared, err := fs.productRuntime().ApproveEnrollment(fingerprint, label)
	if enrolled {
		if fs.auditLog != nil {
			fs.auditLog.LogClientEnrolledContext(ctx, fingerprint, entry.Label, entry.RemoteAddr)
		}
		if err != nil {
			logWarnf("client key enrolled: %s (label %+q, requested from %s) but the approval did not complete: %v", fingerprint, entry.Label, entry.RemoteAddr, err)
		} else {
			logInfof("client key enrolled: %s (label %+q, requested from %s)", fingerprint, entry.Label, entry.RemoteAddr)
		}
	}
	// A retry after a failed queue write enrolls nothing but clears the
	// request; the list changed either way.
	if enrolled || cleared {
		fs.notifyEnrollmentChanged(protocol.EnrollmentChangeApproved, fingerprint)
	}
	if err != nil {
		if errors.Is(err, enrollqueue.ErrNotPending) {
			return "", protocol.WithCode(protocol.ErrCodeInvalidRequest, fmt.Errorf("no enrollment request is waiting for key %s", fingerprint))
		}
		return entry.Label, err
	}
	return entry.Label, nil
}

// RejectClientEnrollment drops a waiting request without enrolling its key.
func (fs *Signer) RejectClientEnrollment(ctx adminserver.SessionContext, fingerprint string) error {
	entry, rejected, err := fs.productRuntime().RejectEnrollment(fingerprint)
	if rejected {
		if fs.auditLog != nil {
			fs.auditLog.LogClientEnrollmentRejectedContext(ctx, fingerprint, entry.Label)
		}
		if err != nil {
			logWarnf("client enrollment request rejected: %s but the queue write is not yet durable: %v", fingerprint, err)
		} else {
			logInfof("client enrollment request rejected: %s", fingerprint)
		}
		fs.notifyEnrollmentChanged(protocol.EnrollmentChangeRejected, fingerprint)
	}
	if err != nil {
		if errors.Is(err, enrollqueue.ErrNotPending) {
			return protocol.WithCode(protocol.ErrCodeInvalidRequest, fmt.Errorf("no enrollment request is waiting for key %s", fingerprint))
		}
		if errors.Is(err, productruntime.ErrAlreadyEnrolled) {
			return protocol.WithCode(protocol.ErrCodeInvalidRequest, fmt.Errorf("client key %s is already enrolled; approve the request again to clear it, or revoke the key", fingerprint))
		}
		return err
	}
	return nil
}

// ImportClientKey enrolls an OpenSSH public-key line the operator supplied,
// the pre-enrollment path. A label the operator gives must meet the label
// rule (clientregistry.NormalizeLabel); without one, the line's comment is
// the label when it meets the rule, and the key is enrolled without a label,
// the result saying so, when it does not: the operator typed no label to
// refuse. A waiting request for the same key is cleared.
//
// The line follows the registry's rule: this version implements no
// authorized_keys options, so an option-bearing line (from=, restrict, ...)
// is refused rather than enrolled without the restriction it asks for.
func (fs *Signer) ImportClientKey(ctx adminserver.SessionContext, publicKey, label string) (adminserver.ImportedClientKey, error) {
	var imported adminserver.ImportedClientKey
	key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(publicKey)))
	if err != nil {
		return imported, protocol.WithCode(protocol.ErrCodeInvalidRequest, fmt.Errorf("invalid public key: %w", err))
	}
	if len(options) != 0 {
		return imported, protocol.WithCode(protocol.ErrCodeInvalidRequest, fmt.Errorf("invalid public key: option %q is not implemented by this version; import the key without options", options[0]))
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return imported, protocol.WithCode(protocol.ErrCodeInvalidRequest, errors.New("invalid public key: expected one OpenSSH public-key line"))
	}
	if err := sshtunnel.CheckClientKey(key); err != nil {
		return imported, protocol.WithCode(protocol.ErrCodeInvalidRequest, err)
	}
	if strings.TrimSpace(label) != "" {
		if label, err = clientregistry.NormalizeLabel(label); err != nil {
			return imported, protocol.WithCode(protocol.ErrCodeInvalidRequest, fmt.Errorf("invalid label: %w", err))
		}
	} else if label, err = clientregistry.NormalizeLabel(comment); err != nil {
		label, imported.CommentRefused = "", true
	}
	fingerprint := ssh.FingerprintSHA256(key)
	added, cleared, err := fs.productRuntime().ImportClientKey(key, label)
	if added {
		if fs.auditLog != nil {
			fs.auditLog.LogClientEnrolledContext(ctx, fingerprint, label, "")
		}
		if err != nil {
			logWarnf("client key imported: %s (label %+q) but the import did not complete: %v", fingerprint, label, err)
		} else {
			logInfof("client key imported: %s (label %+q)", fingerprint, label)
		}
	} else if err == nil {
		logInfof("client key import: %s is already enrolled", fingerprint)
	}
	// Importing a key that is already enrolled still clears its waiting
	// request, if any; the list changed either way.
	if added || cleared {
		fs.notifyEnrollmentChanged(protocol.EnrollmentChangeImported, fingerprint)
	}
	imported.Fingerprint, imported.Label, imported.Added = fingerprint, label, added
	return imported, err
}

// RevokeAllClientKeys removes every enrolled client key and closes every
// client connection: the emergency lever.
func (fs *Signer) RevokeAllClientKeys(ctx adminserver.SessionContext) (int, int, error) {
	entries, revoked, err := fs.productRuntime().RevokeAllAuthorizedKeys()
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
	fs.notifyEnrollmentChanged(protocol.EnrollmentChangeRevokedAll, "")
	if err != nil {
		logWarnf("all client keys revoked: %d key(s), closed %d connection(s), but the registry write is not yet durable: %v", len(entries), closed, err)
		return len(entries), closed, err
	}
	logInfof("all client keys revoked: %d key(s), closed %d connection(s)", len(entries), closed)
	return len(entries), closed, nil
}
