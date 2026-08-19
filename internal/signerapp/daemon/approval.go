// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"fmt"
	"github.com/aplane-algo/aplane/internal/productmode"
	"time"
)

func (fs *Signer) requestTokenProvisioning(requestID, identityID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error) {
	return fs.requestTokenProvisioningContext(context.Background(), requestID, identityID, sshFingerprint, remoteAddr, timeout)
}

func (fs *Signer) requestTokenProvisioningContext(ctx context.Context, requestID, identityID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error) {
	ir := fs.runtime
	if ir == nil || identityID != productmode.IdentityID {
		return false, fmt.Errorf("identity not found: %s", identityID)
	}
	return ir.RequestTokenProvisioningContext(ctx, requestID, identityID, sshFingerprint, remoteAddr, timeout)
}
