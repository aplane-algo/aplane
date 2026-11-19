// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import "github.com/aplane-algo/aplane/internal/signerapp/adminserver"

// adminHub returns the process-root admin facade used by non-transport code.
func (fs *Signer) adminHub() adminserver.AdminHub {
	if fs == nil {
		return nil
	}
	return fs.hub
}
