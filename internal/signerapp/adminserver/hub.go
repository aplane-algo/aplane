// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"github.com/aplane-algo/aplane/internal/adminproto"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
)

// AdminHub is the process-root facade for server-originated admin protocol
// traffic and process-wide session presence checks.
type AdminHub interface {
	HasClient() bool
	SendSignRequest(req *signerapproval.SignRequest) bool
	SendSignRequestCanceled(msg *signerapproval.SignRequestCanceled) bool
	SendTokenProvisioningRequest(req *signerapproval.TokenProvisioningRequest) bool
	NotifyLocked(notification adminproto.SignerLockedNotification)
	NotifyKeysChanged(notification adminproto.KeysChangedNotification)
	NotifyStatus(state string, keyCount int)
}
