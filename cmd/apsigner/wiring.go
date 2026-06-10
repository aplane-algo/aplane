// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/adminproto"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
)

// lazyReloadAuditLogger resolves the server's audit logger at log time so
// hooks built before the audit logger is assigned still record reload events.
type lazyReloadAuditLogger struct {
	fs *Signer
}

func (l lazyReloadAuditLogger) LogKeyReload(identityID string, keyCount int) {
	if l.fs.auditLog != nil {
		l.fs.auditLog.LogKeyReload(identityID, keyCount)
	}
}

func (l lazyReloadAuditLogger) LogKeyRejected(identityID, keyFile, reason string) {
	if l.fs.auditLog != nil {
		l.fs.auditLog.LogKeyRejected(identityID, keyFile, reason)
	}
}

// identityBuildHooks returns the process callbacks identity runtime assembly
// needs from the server. It is the single wiring source for both startup and
// test-constructed identity runtimes.
func (fs *Signer) identityBuildHooks() signerstartup.IdentityBuildHooks {
	return signerstartup.IdentityBuildHooks{
		HasAdminClient: func(targetIdentityID string) bool {
			hub := fs.adminHub()
			if hub == nil {
				return false
			}
			return hub.HasClient(targetIdentityID)
		},
		SendSignRequest: func(targetIdentityID string, msg *signerapproval.SignRequest) bool {
			hub := fs.adminHub()
			if hub == nil {
				return false
			}
			return hub.SendSignRequest(targetIdentityID, msg)
		},
		SendSignRequestCanceled: func(targetIdentityID string, msg *signerapproval.SignRequestCanceled) bool {
			hub := fs.adminHub()
			if hub == nil {
				return false
			}
			return hub.SendSignRequestCanceled(targetIdentityID, msg)
		},
		SendTokenProvisioningRequest: func(targetIdentityID string, msg *signerapproval.TokenProvisioningRequest) bool {
			hub := fs.adminHub()
			if hub == nil {
				return false
			}
			return hub.SendTokenProvisioningRequest(targetIdentityID, msg)
		},
		NotifyLocked: func(lockedIdentityID string) {
			if hub := fs.adminHub(); hub != nil {
				hub.NotifyLocked(lockedIdentityID, adminproto.SignerLockedNotification{Reason: "locked"})
			}
		},
		NotifyKeysChanged: func(changedIdentityID string, keyCount int) {
			if hub := fs.adminHub(); hub != nil {
				hub.NotifyKeysChanged(changedIdentityID, adminproto.KeysChangedNotification{KeyCount: keyCount})
			}
		},
		ReloadAuditLog: lazyReloadAuditLogger{fs: fs},
		NodeFailClosed: func(err error) {
			if fs.registry != nil {
				fs.registry.CloseFailClosed(err)
			}
		},
		ReloadMutationLock: func(identityID string) sync.Locker {
			return fs.storeMutationLock(identityID)
		},
		Info: func(msg string) {
			logInfof("%s", msg)
		},
		Warn: func(msg string) {
			logWarnf("%s", msg)
		},
	}
}
