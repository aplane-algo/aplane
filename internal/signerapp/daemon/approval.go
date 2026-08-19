// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"fmt"
	"time"
)

func (fs *Signer) requestTokenProvisioning(requestID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error) {
	return fs.requestTokenProvisioningContext(context.Background(), requestID, sshFingerprint, remoteAddr, timeout)
}

func (fs *Signer) requestTokenProvisioningContext(ctx context.Context, requestID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error) {
	ir := fs.runtime
	if ir == nil {
		return false, fmt.Errorf("product runtime is not initialized")
	}
	return ir.RequestTokenProvisioningContext(ctx, requestID, sshFingerprint, remoteAddr, timeout)
}
