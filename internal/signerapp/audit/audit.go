// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const maxAuditLogSize = 10 * 1024 * 1024 // 10 MB

const (
	AuditSignRequest                AuditEventType = "SIGN_REQUEST"
	AuditSignApproved               AuditEventType = "SIGN_APPROVED"
	AuditSignRejected               AuditEventType = "SIGN_REJECTED"
	AuditSignFailed                 AuditEventType = "SIGN_FAILED"
	AuditAuthFailed                 AuditEventType = "AUTH_FAILED"
	AuditAuthorizationDenied        AuditEventType = "AUTHORIZATION_DENIED"
	AuditServerStart                AuditEventType = "SERVER_START"
	AuditServerStop                 AuditEventType = "SERVER_STOP"
	AuditKeyReload                  AuditEventType = "KEY_RELOAD"
	AuditSessionConnected           AuditEventType = "SESSION_CONNECTED"
	AuditSessionDisconnected        AuditEventType = "SESSION_DISCONNECTED"
	AuditIdentityLocked             AuditEventType = "IDENTITY_LOCKED"
	AuditTokenProvisioned           AuditEventType = "TOKEN_PROVISIONED"
	AuditKeyGenerated               AuditEventType = "KEY_GENERATED"
	AuditKeyDeleted                 AuditEventType = "KEY_DELETED"
	AuditKeyImported                AuditEventType = "KEY_IMPORTED"
	AuditKeyRejected                AuditEventType = "KEY_REJECTED"
	AuditBackupCreated              AuditEventType = "BACKUP_CREATED"
	AuditBackupFailed               AuditEventType = "BACKUP_FAILED"
	AuditBackupRestorePreviewed     AuditEventType = "BACKUP_RESTORE_PREVIEWED"
	AuditBackupRestorePreviewFailed AuditEventType = "BACKUP_RESTORE_PREVIEW_FAILED"
	AuditBackupRestoreStarted       AuditEventType = "BACKUP_RESTORE_STARTED"
	AuditBackupRestoreCompleted     AuditEventType = "BACKUP_RESTORE_COMPLETED"
	AuditBackupRestorePartial       AuditEventType = "BACKUP_RESTORE_PARTIAL"
	AuditBackupRestoreFailed        AuditEventType = "BACKUP_RESTORE_FAILED"
	AuditBackupRecovered            AuditEventType = "BACKUP_RECOVERED"
	AuditBackupRecoveryFailed       AuditEventType = "BACKUP_RECOVERY_FAILED"
	AuditBackupActivationIntent     AuditEventType = "BACKUP_ACTIVATION_INTENT"
	AuditBackupActivated            AuditEventType = "BACKUP_ACTIVATED"
	AuditBackupActivationFailed     AuditEventType = "BACKUP_ACTIVATION_FAILED"
	AuditBackupActivationResumed    AuditEventType = "BACKUP_ACTIVATION_RESUMED"
	AuditBackupActivationRolledBack AuditEventType = "BACKUP_ACTIVATION_ROLLED_BACK"
	AuditBackupRecoveryPurged       AuditEventType = "BACKUP_RECOVERY_PURGED"
	AuditStoreInitialized           AuditEventType = "STORE_INITIALIZED"
	AuditStoreInitializeFailed      AuditEventType = "STORE_INITIALIZE_FAILED"
	AuditPassphraseChanged          AuditEventType = "PASSPHRASE_CHANGED"
	AuditPassphraseChangeFailed     AuditEventType = "PASSPHRASE_CHANGE_FAILED"
)

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	Timestamp               time.Time      `json:"timestamp"`
	Event                   AuditEventType `json:"event"`
	IdentityID              string         `json:"identity_id,omitempty"`         // Backward-compatible owning identity
	TargetIdentityID        string         `json:"target_identity_id,omitempty"`  // Signing identity targeted by the action
	Principal               string         `json:"principal,omitempty"`           // Backward-compatible principal field
	RequesterPrincipal      string         `json:"requester_principal,omitempty"` // Principal requesting the action
	ApproverPrincipal       string         `json:"approver_principal,omitempty"`  // Principal approving or rejecting the action
	AdminSessionID          string         `json:"admin_session_id,omitempty"`    // Admin protocol session ID
	Transport               string         `json:"transport,omitempty"`           // ipc, ssh, http, or empty for process-level events
	Outcome                 string         `json:"outcome,omitempty"`             // requested, approved, rejected, failed, etc.
	TxnAuth                 string         `json:"txn_auth,omitempty"`            // Signing key address (auth addr)
	TxnSender               string         `json:"txn_sender,omitempty"`          // Transaction sender (if different)
	TxnType                 string         `json:"txn_type,omitempty"`            // Transaction type (pay, axfer, etc)
	TxnDetails              string         `json:"txn_details,omitempty"`         // Human-readable transaction summary
	TxID                    string         `json:"txid,omitempty"`                // Transaction ID (after signing)
	RemoteAddr              string         `json:"remote_addr,omitempty"`         // Client IP (for auth failures)
	Reason                  string         `json:"reason,omitempty"`              // Rejection/failure reason
	PolicyRuleID            string         `json:"policy_rule_id,omitempty"`      // Policy rule that forced manual review
	KeyCount                int            `json:"key_count,omitempty"`           // For key reload events
	RestoreID               string         `json:"restore_id,omitempty"`
	ArchiveSHA256           string         `json:"archive_sha256,omitempty"`
	SourcePolicySHA256      string         `json:"source_policy_sha256,omitempty"`
	DestinationPolicySHA256 string         `json:"destination_policy_sha256,omitempty"`
	PolicyComparison        string         `json:"policy_comparison,omitempty"`
	ReplaceExisting         bool           `json:"replace_existing,omitempty"`
}

// AuditLogger handles append-only audit logging
type AuditLogger struct {
	file    *os.File
	mu      sync.Mutex
	path    string
	written uint64
}

// NewAuditLogger creates a new audit logger
// Log file is opened in append-only mode
func NewAuditLogger(path string) (*AuditLogger, error) {
	// Open file in append-only mode, create if not exists
	// Permissions: owner read/write only (0600)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}

	var written uint64
	if info, err := file.Stat(); err == nil {
		written = uint64(info.Size())
	}

	return &AuditLogger{file: file, path: path, written: written}, nil
}

// Log writes an audit entry
func (a *AuditLogger) Log(entry AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Set timestamp if not provided
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	// Encode as JSON (one line per entry)
	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to marshal audit entry: %v\n", err)
		return
	}

	// Rotate if this write would exceed the size limit
	line := append(data, '\n')
	if a.written+uint64(len(line)) > maxAuditLogSize {
		if err := a.rotate(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to rotate audit log: %v\n", err)
			// Continue writing to current file
		}
	}

	// A failed rotation may have left no usable handle; recover instead of
	// erroring on every subsequent entry.
	if a.file == nil {
		a.reopenCurrent()
		if a.file == nil {
			fmt.Fprintf(os.Stderr, "Warning: audit log unavailable, dropping entry\n")
			return
		}
	}

	// Write with newline
	if _, err := a.file.Write(line); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write audit entry: %v\n", err)
		return
	}
	a.written += uint64(len(line))

	// Sync to disk immediately (important for audit trails)
	if err := a.file.Sync(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to sync audit log: %v\n", err)
	}
}

// rotate archives the current log file and opens a fresh one.
// Must be called with a.mu held.
func (a *AuditLogger) rotate() error {
	if err := a.file.Close(); err != nil {
		return fmt.Errorf("close current log: %w", err)
	}
	// Preserve previous backup before overwriting
	if _, err := os.Stat(a.path + ".1"); err == nil {
		_ = os.Rename(a.path+".1", a.path+".2")
	}
	if err := os.Rename(a.path, a.path+".1"); err != nil {
		// Reopen the original path so logging can continue
		a.reopenCurrent()
		return fmt.Errorf("rename log: %w", err)
	}
	file, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		// The old log was already renamed away; restore it so the logger
		// keeps a valid handle instead of writing to a closed file forever.
		_ = os.Rename(a.path+".1", a.path)
		a.reopenCurrent()
		return fmt.Errorf("open new log: %w", err)
	}
	a.file = file
	a.written = 0
	return nil
}

// reopenCurrent opens a.path for append and refreshes the byte counter from
// the file's actual size, so rotation re-attempts at the right threshold.
// Used to recover a usable handle after a rotation step fails; leaves a.file
// nil if the open itself fails (Log drops entries until recovery succeeds).
// Must be called with a.mu held.
func (a *AuditLogger) reopenCurrent() {
	a.file, _ = os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	a.written = 0
	if a.file != nil {
		if info, err := a.file.Stat(); err == nil {
			a.written = uint64(info.Size())
		}
	}
}

// Close closes the audit log file
func (a *AuditLogger) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.file.Close()
}

// Helper methods for common events

type Attribution struct {
	TargetIdentityID   string
	RequesterPrincipal string
	ApproverPrincipal  string
	AdminSessionID     string
	Transport          string
	RemoteAddr         string
}

func (attr Attribution) entry(fallbackIdentityID string, includeApprover bool) AuditEntry {
	targetIdentityID := attr.TargetIdentityID
	if targetIdentityID == "" {
		targetIdentityID = fallbackIdentityID
	}
	requester := attr.RequesterPrincipal
	if requester == "" {
		requester = targetIdentityID
	}
	principal := requester
	approver := ""
	if includeApprover {
		approver = attr.ApproverPrincipal
		if approver == "" {
			approver = targetIdentityID
		}
	}
	return AuditEntry{
		IdentityID:         targetIdentityID,
		TargetIdentityID:   targetIdentityID,
		Principal:          principal,
		RequesterPrincipal: requester,
		ApproverPrincipal:  approver,
		AdminSessionID:     attr.AdminSessionID,
		Transport:          attr.Transport,
		RemoteAddr:         attr.RemoteAddr,
	}
}

func identityAuditFields(identityID string) AuditEntry {
	return AuditEntry{
		IdentityID:         identityID,
		TargetIdentityID:   identityID,
		Principal:          identityID,
		RequesterPrincipal: identityID,
	}
}

func sessionPrincipalID(p adminserver.SessionPrincipal) string {
	return p.ID
}

func sessionAuditFields(ctx adminserver.SessionContext) AuditEntry {
	principal := sessionPrincipalID(ctx.AdminPrincipal)
	requester := sessionPrincipalID(ctx.RequesterPrincipal)
	approver := sessionPrincipalID(ctx.ApproverPrincipal)
	if requester == "" {
		requester = principal
	}
	if approver == "" {
		approver = principal
	}
	return AuditEntry{
		IdentityID:         ctx.TargetIdentityID,
		TargetIdentityID:   ctx.TargetIdentityID,
		Principal:          principal,
		RequesterPrincipal: requester,
		ApproverPrincipal:  approver,
		AdminSessionID:     ctx.SessionID,
		Transport:          ctx.Transport,
		RemoteAddr:         ctx.RemoteAddr,
	}
}

func signRequestEntry(attr Attribution, identityID, address, txnSender, txnType, txnDetails string) AuditEntry {
	entry := attr.entry(identityID, false)
	entry.Event = AuditSignRequest
	entry.Outcome = "requested"
	entry.TxnAuth = address
	entry.TxnSender = txnSender
	entry.TxnType = txnType
	entry.TxnDetails = txnDetails
	return entry
}

func signApprovedEntry(attr Attribution, identityID, address, txnSender, txnDetails, policyRuleID string) AuditEntry {
	entry := attr.entry(identityID, true)
	entry.Event = AuditSignApproved
	entry.Outcome = "approved"
	entry.TxnAuth = address
	entry.TxnSender = txnSender
	entry.TxnDetails = txnDetails
	entry.PolicyRuleID = policyRuleID
	return entry
}

func signRejectedEntry(attr Attribution, identityID, address, txnSender, reason, policyRuleID string) AuditEntry {
	entry := attr.entry(identityID, true)
	entry.Event = AuditSignRejected
	entry.Outcome = "rejected"
	entry.TxnAuth = address
	entry.TxnSender = txnSender
	entry.Reason = reason
	entry.PolicyRuleID = policyRuleID
	return entry
}

func signFailedEntry(attr Attribution, identityID, address, txnSender, reason string) AuditEntry {
	entry := attr.entry(identityID, false)
	entry.Event = AuditSignFailed
	entry.Outcome = "failed"
	entry.TxnAuth = address
	entry.TxnSender = txnSender
	entry.Reason = reason
	return entry
}

// LogSignRequest logs a request to sign a transaction.
func (a *AuditLogger) LogSignRequest(identityID, address, txnSender, txnType, txnDetails string) {
	a.Log(signRequestEntry(Attribution{TargetIdentityID: identityID, RequesterPrincipal: identityID}, identityID, address, txnSender, txnType, txnDetails))
}

// LogSignRequestAttributed logs a signing request with explicit request attribution.
func (a *AuditLogger) LogSignRequestAttributed(attr Attribution, identityID, address, txnSender, txnType, txnDetails string) {
	a.Log(signRequestEntry(attr, identityID, address, txnSender, txnType, txnDetails))
}

// LogSignApproved logs when a signing request is approved.
func (a *AuditLogger) LogSignApproved(identityID, address, txnSender, txnDetails string) {
	a.Log(signApprovedEntry(Attribution{TargetIdentityID: identityID, RequesterPrincipal: identityID, ApproverPrincipal: identityID}, identityID, address, txnSender, txnDetails, ""))
}

// LogSignApprovedWithPolicyRule logs a signing approval caused by a policy rule
// that required manual review.
func (a *AuditLogger) LogSignApprovedWithPolicyRule(identityID, address, txnSender, txnDetails, policyRuleID string) {
	a.Log(signApprovedEntry(Attribution{TargetIdentityID: identityID, RequesterPrincipal: identityID, ApproverPrincipal: identityID}, identityID, address, txnSender, txnDetails, policyRuleID))
}

// LogSignApprovedAttributed logs a signing approval with explicit request attribution.
func (a *AuditLogger) LogSignApprovedAttributed(attr Attribution, identityID, address, txnSender, txnDetails string) {
	a.Log(signApprovedEntry(attr, identityID, address, txnSender, txnDetails, ""))
}

// LogSignApprovedAttributedWithPolicyRule logs a signing approval with explicit
// request attribution and the policy rule that forced manual review.
func (a *AuditLogger) LogSignApprovedAttributedWithPolicyRule(attr Attribution, identityID, address, txnSender, txnDetails, policyRuleID string) {
	a.Log(signApprovedEntry(attr, identityID, address, txnSender, txnDetails, policyRuleID))
}

// LogSignRejected logs when a signing request is rejected by policy or user.
func (a *AuditLogger) LogSignRejected(identityID, address, txnSender, reason string) {
	a.Log(signRejectedEntry(Attribution{TargetIdentityID: identityID, RequesterPrincipal: identityID, ApproverPrincipal: identityID}, identityID, address, txnSender, reason, ""))
}

// LogSignRejectedWithPolicyRule logs a signing rejection from a request that
// entered manual review because of a policy rule.
func (a *AuditLogger) LogSignRejectedWithPolicyRule(identityID, address, txnSender, reason, policyRuleID string) {
	a.Log(signRejectedEntry(Attribution{TargetIdentityID: identityID, RequesterPrincipal: identityID, ApproverPrincipal: identityID}, identityID, address, txnSender, reason, policyRuleID))
}

// LogSignRejectedAttributed logs a signing rejection with explicit request attribution.
func (a *AuditLogger) LogSignRejectedAttributed(attr Attribution, identityID, address, txnSender, reason string) {
	a.Log(signRejectedEntry(attr, identityID, address, txnSender, reason, ""))
}

// LogSignRejectedAttributedWithPolicyRule logs a signing rejection with
// explicit request attribution and the policy rule that forced manual review.
func (a *AuditLogger) LogSignRejectedAttributedWithPolicyRule(attr Attribution, identityID, address, txnSender, reason, policyRuleID string) {
	a.Log(signRejectedEntry(attr, identityID, address, txnSender, reason, policyRuleID))
}

// LogSignFailed logs when a signing attempt fails due to technical errors.
func (a *AuditLogger) LogSignFailed(identityID, address, txnSender, reason string) {
	a.Log(signFailedEntry(Attribution{TargetIdentityID: identityID, RequesterPrincipal: identityID}, identityID, address, txnSender, reason))
}

// LogSignFailedAttributed logs a signing failure with explicit request attribution.
func (a *AuditLogger) LogSignFailedAttributed(attr Attribution, identityID, address, txnSender, reason string) {
	a.Log(signFailedEntry(attr, identityID, address, txnSender, reason))
}

// LogAuthFailed logs an authentication failure from a remote address.
// identityID may be empty if the request failed before identity resolution.
func (a *AuditLogger) LogAuthFailed(identityID, remoteAddr, reason string) {
	entry := identityAuditFields(identityID)
	entry.Event = AuditAuthFailed
	entry.Outcome = "failed"
	entry.RemoteAddr = remoteAddr
	entry.Reason = reason
	a.Log(entry)
}

// LogAuthorizationDenied logs an authorization denial for an authenticated admin session.
func (a *AuditLogger) LogAuthorizationDenied(ctx adminserver.SessionContext, action auth.Action, resource auth.Resource, reason string) {
	entry := sessionAuditFields(ctx)
	if resource.IdentityID != "" {
		entry.IdentityID = resource.IdentityID
		entry.TargetIdentityID = resource.IdentityID
	}
	entry.Event = AuditAuthorizationDenied
	entry.Outcome = "denied"
	entry.Reason = authorizationDeniedReason(action, resource, reason)
	a.Log(entry)
}

func authorizationDeniedReason(action auth.Action, resource auth.Resource, reason string) string {
	out := fmt.Sprintf("action=%s resource_type=%s", action, resource.Type)
	if resource.ID != "" {
		out += " resource_id=" + resource.ID
	}
	if reason != "" {
		out += " reason=" + reason
	}
	return out
}

// LogServerStart logs the startup of the signing server.
func (a *AuditLogger) LogServerStart(keyCount int) {
	a.Log(AuditEntry{
		Event:    AuditServerStart,
		KeyCount: keyCount,
	})
}

// LogServerStop logs the shutdown of the signing server.
func (a *AuditLogger) LogServerStop() {
	a.Log(AuditEntry{
		Event: AuditServerStop,
	})
}

// LogKeyReload logs when keys are reloaded from the keystore.
func (a *AuditLogger) LogKeyReload(identityID string, keyCount int) {
	entry := identityAuditFields(identityID)
	entry.Event = AuditKeyReload
	entry.Outcome = "reloaded"
	entry.KeyCount = keyCount
	a.Log(entry)
}

// LogSessionConnected logs when a new IPC or API session is established.
func (a *AuditLogger) LogSessionConnected(identityID, remoteAddr, user string) {
	entry := identityAuditFields(identityID)
	entry.Event = AuditSessionConnected
	entry.Outcome = "connected"
	entry.RemoteAddr = remoteAddr
	entry.Reason = user
	a.Log(entry)
}

// LogSessionConnectedContext logs a structured admin session connection.
func (a *AuditLogger) LogSessionConnectedContext(ctx adminserver.SessionContext) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditSessionConnected
	entry.Outcome = "connected"
	a.Log(entry)
}

// LogSessionDisconnected logs when a session is terminated.
func (a *AuditLogger) LogSessionDisconnected(identityID, remoteAddr, user string) {
	entry := identityAuditFields(identityID)
	entry.Event = AuditSessionDisconnected
	entry.Outcome = "disconnected"
	entry.RemoteAddr = remoteAddr
	entry.Reason = user
	a.Log(entry)
}

// LogSessionDisconnectedContext logs a structured admin session disconnection.
func (a *AuditLogger) LogSessionDisconnectedContext(ctx adminserver.SessionContext) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditSessionDisconnected
	entry.Outcome = "disconnected"
	a.Log(entry)
}

// LogIdentityLockedContext logs an explicit admin lock request for an identity.
func (a *AuditLogger) LogIdentityLockedContext(ctx adminserver.SessionContext, reason string) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditIdentityLocked
	entry.Outcome = "locked"
	entry.Reason = reason
	a.Log(entry)
}

// LogTokenProvisioned logs when a token is provisioned via SSH.
func (a *AuditLogger) LogTokenProvisioned(identityID, sshFingerprint, remoteAddr string) {
	entry := identityAuditFields(identityID)
	entry.Event = AuditTokenProvisioned
	entry.Outcome = "provisioned"
	entry.RemoteAddr = remoteAddr
	entry.Reason = sshFingerprint
	a.Log(entry)
}

// LogKeyGenerated logs a key generation event.
func (a *AuditLogger) LogKeyGenerated(identityID, address, keyType string) {
	entry := identityAuditFields(identityID)
	entry.Event = AuditKeyGenerated
	entry.Outcome = "generated"
	entry.TxnAuth = address
	entry.Reason = keyType
	a.Log(entry)
}

// LogKeyDeleted logs a key deletion event.
func (a *AuditLogger) LogKeyDeleted(identityID, address, deletedPath string) {
	reason := filepath.Base(deletedPath)
	if reason == "." || reason == string(filepath.Separator) {
		reason = deletedPath
	}
	entry := identityAuditFields(identityID)
	entry.Event = AuditKeyDeleted
	entry.Outcome = "deleted"
	entry.TxnAuth = address
	entry.Reason = reason
	a.Log(entry)
}

// LogKeyImported logs a key import event.
func (a *AuditLogger) LogKeyImported(identityID, address, keyType string) {
	entry := identityAuditFields(identityID)
	entry.Event = AuditKeyImported
	entry.Outcome = "imported"
	entry.TxnAuth = address
	entry.Reason = keyType
	a.Log(entry)
}

// LogKeyRejected logs when a key file is skipped during scan because it violates
// a load-time key-file invariant.
func (a *AuditLogger) LogKeyRejected(identityID, keyFile, reason string) {
	if keyFile != "" {
		base := filepath.Base(keyFile)
		if base != "." && base != string(filepath.Separator) {
			reason = fmt.Sprintf("file=%s reason=%s", base, reason)
		}
	}
	entry := identityAuditFields(identityID)
	entry.Event = AuditKeyRejected
	entry.Outcome = "rejected"
	entry.Reason = reason
	a.Log(entry)
}

func (a *AuditLogger) LogBackupCreatedContext(ctx adminserver.SessionContext, archivePath string) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditBackupCreated
	entry.Outcome = "created"
	entry.Reason = archivePath
	a.Log(entry)
}

func (a *AuditLogger) LogBackupFailedContext(ctx adminserver.SessionContext, reason string) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditBackupFailed
	entry.Outcome = "failed"
	entry.Reason = reason
	a.Log(entry)
}

func (a *AuditLogger) LogBackupRestorePreviewedContext(ctx adminserver.SessionContext, archivePath string, keyCount int) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditBackupRestorePreviewed
	entry.Outcome = "previewed"
	entry.Reason = archivePath
	entry.KeyCount = keyCount
	a.Log(entry)
}

func (a *AuditLogger) LogBackupRestorePreviewFailedContext(ctx adminserver.SessionContext, reason string) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditBackupRestorePreviewFailed
	entry.Outcome = "failed"
	entry.Reason = reason
	a.Log(entry)
}

func (a *AuditLogger) LogBackupRestoreStartedContext(ctx adminserver.SessionContext, archivePath string, selectedCount int) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditBackupRestoreStarted
	entry.Outcome = "started"
	entry.Reason = archivePath
	entry.KeyCount = selectedCount
	a.Log(entry)
}

func (a *AuditLogger) LogBackupRestoreCompletedContext(ctx adminserver.SessionContext, archivePath string, restoredCount int) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditBackupRestoreCompleted
	entry.Outcome = "completed"
	entry.Reason = archivePath
	entry.KeyCount = restoredCount
	a.Log(entry)
}

func (a *AuditLogger) LogBackupRestorePartialContext(ctx adminserver.SessionContext, archivePath string, restoredCount, failedCount int) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditBackupRestorePartial
	entry.Outcome = "partial"
	entry.Reason = fmt.Sprintf("%s restored=%d failed=%d", archivePath, restoredCount, failedCount)
	entry.KeyCount = restoredCount
	a.Log(entry)
}

func (a *AuditLogger) LogBackupRestoreFailedContext(ctx adminserver.SessionContext, reason string) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditBackupRestoreFailed
	entry.Outcome = "failed"
	entry.Reason = reason
	a.Log(entry)
}

func (a *AuditLogger) LogBackupRecoveredContext(
	ctx adminserver.SessionContext,
	result adminproto.RecoverBackupResult,
) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditBackupRecovered
	entry.Outcome = "recovered"
	entry.RestoreID = result.RestoreID
	entry.ArchiveSHA256 = result.ArchiveChecksum
	entry.KeyCount = result.EntryCount
	a.Log(entry)
}

func (a *AuditLogger) LogBackupRecoveryFailedContext(ctx adminserver.SessionContext, restoreID, reason string) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditBackupRecoveryFailed
	entry.Outcome = "failed"
	entry.RestoreID = restoreID
	entry.Reason = reason
	a.Log(entry)
}

func (a *AuditLogger) LogBackupActivationIntentContext(
	ctx adminserver.SessionContext,
	restoreID string,
	replaceExisting bool,
) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditBackupActivationIntent
	entry.Outcome = "requested"
	entry.RestoreID = restoreID
	entry.ReplaceExisting = replaceExisting
	a.Log(entry)
}

func (a *AuditLogger) LogBackupActivatedContext(
	ctx adminserver.SessionContext,
	result adminproto.ActivateRecoveredResult,
) {
	entry := recoveredActivationAuditEntry(ctx, result)
	entry.Event = AuditBackupActivated
	entry.Outcome = "activated"
	entry.KeyCount = len(result.Activated)
	a.Log(entry)
}

func (a *AuditLogger) LogBackupActivationFailedContext(
	ctx adminserver.SessionContext,
	result adminproto.ActivateRecoveredResult,
) {
	entry := recoveredActivationAuditEntry(ctx, result)
	entry.Event = AuditBackupActivationFailed
	entry.Outcome = "failed"
	entry.Reason = result.Error
	a.Log(entry)
}

func (a *AuditLogger) LogBackupActivationResumedContext(
	ctx adminserver.SessionContext,
	result adminproto.ActivateRecoveredResult,
) {
	entry := recoveredActivationAuditEntry(ctx, result)
	entry.Event = AuditBackupActivationResumed
	entry.Outcome = "resumed"
	entry.KeyCount = len(result.Activated)
	a.Log(entry)
}

func recoveredActivationAuditEntry(
	ctx adminserver.SessionContext,
	result adminproto.ActivateRecoveredResult,
) AuditEntry {
	entry := sessionAuditFields(ctx)
	entry.RestoreID = result.RestoreID
	entry.ArchiveSHA256 = result.ArchiveSHA256
	entry.SourcePolicySHA256 = result.SourcePolicySHA256
	entry.DestinationPolicySHA256 = result.DestinationPolicySHA256
	entry.PolicyComparison = result.PolicyComparison
	entry.ReplaceExisting = result.ReplaceExisting
	return entry
}

func (a *AuditLogger) LogBackupActivationRolledBackContext(
	ctx adminserver.SessionContext,
	result adminproto.RollbackRecoveredResult,
) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditBackupActivationRolledBack
	entry.Outcome = "rolled_back"
	entry.RestoreID = result.RestoreID
	entry.KeyCount = result.KeyCount
	if !result.Success {
		entry.Outcome = "failed"
		entry.Reason = result.Error
	}
	a.Log(entry)
}

func (a *AuditLogger) LogBackupRecoveryPurgedContext(
	ctx adminserver.SessionContext,
	result adminproto.PurgeRecoveredResult,
) {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditBackupRecoveryPurged
	entry.Outcome = "purged"
	entry.RestoreID = result.RestoreID
	if !result.Success {
		entry.Outcome = "failed"
		entry.Reason = result.Error
	}
	a.Log(entry)
}

func (a *AuditLogger) LogStoreInitialized(identityID, metadataDir string) {
	entry := identityAuditFields(identityID)
	entry.Event = AuditStoreInitialized
	entry.Outcome = "initialized"
	entry.Reason = metadataDir
	a.Log(entry)
}

func (a *AuditLogger) LogStoreInitializeFailed(identityID, reason string) {
	entry := identityAuditFields(identityID)
	entry.Event = AuditStoreInitializeFailed
	entry.Outcome = "failed"
	entry.Reason = reason
	a.Log(entry)
}

func (a *AuditLogger) LogPassphraseChanged(identityID string, keysMigrated, templatesMigrated, recoveredFilesMigrated int) {
	entry := identityAuditFields(identityID)
	entry.Event = AuditPassphraseChanged
	entry.Outcome = "changed"
	entry.Reason = fmt.Sprintf(
		"keys_migrated=%d templates_migrated=%d recovered_files_migrated=%d",
		keysMigrated,
		templatesMigrated,
		recoveredFilesMigrated,
	)
	a.Log(entry)
}

func (a *AuditLogger) LogPassphraseChangeFailed(identityID, reason string) {
	entry := identityAuditFields(identityID)
	entry.Event = AuditPassphraseChangeFailed
	entry.Outcome = "failed"
	entry.Reason = reason
	a.Log(entry)
}
