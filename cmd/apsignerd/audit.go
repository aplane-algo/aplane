// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const maxAuditLogSize = 10 * 1024 * 1024 // 10 MB

const (
	AuditSignRequest         AuditEventType = "SIGN_REQUEST"
	AuditSignApproved        AuditEventType = "SIGN_APPROVED"
	AuditSignRejected        AuditEventType = "SIGN_REJECTED"
	AuditSignFailed          AuditEventType = "SIGN_FAILED"
	AuditAuthFailed          AuditEventType = "AUTH_FAILED"
	AuditServerStart         AuditEventType = "SERVER_START"
	AuditServerStop          AuditEventType = "SERVER_STOP"
	AuditKeyReload           AuditEventType = "KEY_RELOAD"
	AuditSessionConnected    AuditEventType = "SESSION_CONNECTED"
	AuditSessionDisconnected AuditEventType = "SESSION_DISCONNECTED"
	AuditTokenProvisioned    AuditEventType = "TOKEN_PROVISIONED"
)

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	Timestamp  time.Time      `json:"timestamp"`
	Event      AuditEventType `json:"event"`
	Principal  string         `json:"principal,omitempty"`   // Authenticated identity (e.g., "default")
	TxnAuth    string         `json:"txn_auth,omitempty"`    // Signing key address (auth addr)
	TxnSender  string         `json:"txn_sender,omitempty"`  // Transaction sender (if different)
	TxnType    string         `json:"txn_type,omitempty"`    // Transaction type (pay, axfer, etc)
	TxnDetails string         `json:"txn_details,omitempty"` // Human-readable transaction summary
	TxID       string         `json:"txid,omitempty"`        // Transaction ID (after signing)
	RemoteAddr string         `json:"remote_addr,omitempty"` // Client IP (for auth failures)
	Reason     string         `json:"reason,omitempty"`      // Rejection/failure reason
	KeyCount   int            `json:"key_count,omitempty"`   // For key reload events
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

	// Write with newline
	if _, err := a.file.Write(line); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write audit entry: %v\n", err)
		return
	}
	a.written += uint64(len(line))

	// Sync to disk immediately (important for audit trails)
	_ = a.file.Sync()
}

// rotate archives the current log file and opens a fresh one.
// Must be called with a.mu held.
func (a *AuditLogger) rotate() error {
	if err := a.file.Close(); err != nil {
		return fmt.Errorf("close current log: %w", err)
	}
	if err := os.Rename(a.path, a.path+".1"); err != nil {
		// Reopen the original path so logging can continue
		a.file, _ = os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		a.written = 0
		return fmt.Errorf("rename log: %w", err)
	}
	file, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open new log: %w", err)
	}
	a.file = file
	a.written = 0
	return nil
}

// Close closes the audit log file
func (a *AuditLogger) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.file.Close()
}

// Helper methods for common events

// LogSignRequest logs a request to sign a transaction.
func (a *AuditLogger) LogSignRequest(principal, address, txnSender, txnType, txnDetails string) {
	a.Log(AuditEntry{
		Event:      AuditSignRequest,
		Principal:  principal,
		TxnAuth:    address,
		TxnSender:  txnSender,
		TxnType:    txnType,
		TxnDetails: txnDetails,
	})
}

// LogSignApproved logs when a signing request is approved.
func (a *AuditLogger) LogSignApproved(principal, address, txnSender, txnDetails string) {
	a.Log(AuditEntry{
		Event:      AuditSignApproved,
		Principal:  principal,
		TxnAuth:    address,
		TxnSender:  txnSender,
		TxnDetails: txnDetails,
	})
}

// LogSignRejected logs when a signing request is rejected by policy or user.
func (a *AuditLogger) LogSignRejected(principal, address, txnSender, reason string) {
	a.Log(AuditEntry{
		Event:     AuditSignRejected,
		Principal: principal,
		TxnAuth:   address,
		TxnSender: txnSender,
		Reason:    reason,
	})
}

// LogSignFailed logs when a signing attempt fails due to technical errors.
func (a *AuditLogger) LogSignFailed(principal, address, txnSender, reason string) {
	a.Log(AuditEntry{
		Event:     AuditSignFailed,
		Principal: principal,
		TxnAuth:   address,
		TxnSender: txnSender,
		Reason:    reason,
	})
}

// LogAuthFailed logs an authentication failure from a remote address.
func (a *AuditLogger) LogAuthFailed(principal, remoteAddr, reason string) {
	a.Log(AuditEntry{
		Event:      AuditAuthFailed,
		Principal:  principal,
		RemoteAddr: remoteAddr,
		Reason:     reason,
	})
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
func (a *AuditLogger) LogKeyReload(keyCount int) {
	a.Log(AuditEntry{
		Event:    AuditKeyReload,
		KeyCount: keyCount,
	})
}

// LogSessionConnected logs when a new IPC or API session is established.
func (a *AuditLogger) LogSessionConnected(principal, remoteAddr, user string) {
	a.Log(AuditEntry{
		Event:      AuditSessionConnected,
		Principal:  principal,
		RemoteAddr: remoteAddr,
		Reason:     user, // Reusing Reason field for username
	})
}

// LogSessionDisconnected logs when a session is terminated.
func (a *AuditLogger) LogSessionDisconnected(principal, remoteAddr, user string) {
	a.Log(AuditEntry{
		Event:      AuditSessionDisconnected,
		Principal:  principal,
		RemoteAddr: remoteAddr,
		Reason:     user,
	})
}

// LogTokenProvisioned logs when a token is provisioned via SSH.
func (a *AuditLogger) LogTokenProvisioned(identityID, sshFingerprint, remoteAddr string) {
	a.Log(AuditEntry{
		Event:      AuditTokenProvisioned,
		Principal:  identityID,
		RemoteAddr: remoteAddr,
		Reason:     sshFingerprint, // Reusing Reason field for SSH fingerprint
	})
}
