// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"github.com/aplane-algo/aplane/internal/adminproto"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
)

// AdminHub is the process-root facade for server-originated admin protocol
// traffic and identity-targeted session presence checks.
type AdminHub interface {
	HasClient(identityID string) bool
	SendSignRequest(identityID string, req *signerapproval.SignRequest) bool
	SendSignRequestCanceled(identityID string, msg *signerapproval.SignRequestCanceled) bool
	SendTokenProvisioningRequest(identityID string, req *signerapproval.TokenProvisioningRequest) bool
	NotifyLocked(identityID string, notification adminproto.SignerLockedNotification)
	NotifyKeysChanged(identityID string, notification adminproto.KeysChangedNotification)
}
