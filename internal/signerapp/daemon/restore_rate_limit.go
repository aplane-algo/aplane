// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"time"

	"github.com/aplane-algo/aplane/internal/signerapp/backupadmin"
)

func (fs *Signer) restoreAttemptLimiter() *backupadmin.RestoreAttemptLimiter {
	fs.restoreAttemptMu.Lock()
	defer fs.restoreAttemptMu.Unlock()
	if fs.restoreAttempts == nil {
		fs.restoreAttempts = backupadmin.NewRestoreAttemptLimiter(time.Now)
	}
	return fs.restoreAttempts
}
