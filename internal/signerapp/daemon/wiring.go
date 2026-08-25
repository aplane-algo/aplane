// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

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

func (l lazyReloadAuditLogger) LogKeyReload(keyCount int) {
	if l.fs.auditLog != nil {
		l.fs.auditLog.LogKeyReload(keyCount)
	}
}

func (l lazyReloadAuditLogger) LogKeyRejected(keyFile, reason string) {
	if l.fs.auditLog != nil {
		l.fs.auditLog.LogKeyRejected(keyFile, reason)
	}
}

// productBuildHooks returns the process callbacks product runtime assembly
// needs from the server. It is the single wiring source for both startup and
// test-constructed product runtimes.
func (fs *Signer) productBuildHooks() signerstartup.ProductBuildHooks {
	return signerstartup.ProductBuildHooks{
		HasAdminClient: func() bool {
			hub := fs.adminHub()
			if hub == nil {
				return false
			}
			return hub.HasClient()
		},
		SendSignRequest: func(msg *signerapproval.SignRequest) bool {
			hub := fs.adminHub()
			if hub == nil {
				return false
			}
			return hub.SendSignRequest(msg)
		},
		SendSignRequestCanceled: func(msg *signerapproval.SignRequestCanceled) bool {
			hub := fs.adminHub()
			if hub == nil {
				return false
			}
			return hub.SendSignRequestCanceled(msg)
		},
		SendTokenProvisioningRequest: func(msg *signerapproval.TokenProvisioningRequest) bool {
			hub := fs.adminHub()
			if hub == nil {
				return false
			}
			return hub.SendTokenProvisioningRequest(msg)
		},
		NotifyLocked: func() {
			if hub := fs.adminHub(); hub != nil {
				hub.NotifyLocked(adminproto.SignerLockedNotification{Reason: "locked"})
			}
		},
		NotifyKeysChanged: func(keyCount int) {
			if hub := fs.adminHub(); hub != nil {
				hub.NotifyKeysChanged(adminproto.KeysChangedNotification{KeyCount: keyCount})
			}
		},
		ReloadAuditLog: lazyReloadAuditLogger{fs: fs},
		NodeFailClosed: func(err error) {
			if fs.nodeFailState != nil {
				fs.nodeFailState.Fail(err)
			}
		},
		ReloadMutationLock: func() sync.Locker {
			return &fs.storeMutationLock
		},
		Info: func(msg string) {
			logInfof("%s", msg)
		},
		Warn: func(msg string) {
			logWarnf("%s", msg)
		},
	}
}
