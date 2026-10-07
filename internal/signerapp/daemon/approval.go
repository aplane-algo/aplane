// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"fmt"
	"time"
)

func (fs *Signer) requestClientEnrollment(requestID, sshFingerprint, label, remoteAddr string, timeout time.Duration) (bool, error) {
	return fs.requestClientEnrollmentContext(context.Background(), requestID, sshFingerprint, label, remoteAddr, timeout)
}

func (fs *Signer) requestClientEnrollmentContext(ctx context.Context, requestID, sshFingerprint, label, remoteAddr string, timeout time.Duration) (bool, error) {
	ir := fs.runtime
	if ir == nil {
		return false, fmt.Errorf("product runtime is not initialized")
	}
	return ir.RequestClientEnrollmentContext(ctx, requestID, sshFingerprint, label, remoteAddr, timeout)
}
