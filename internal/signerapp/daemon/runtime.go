// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

func (fs *Signer) hasAdminClient() bool {
	hub := fs.adminHub()
	if hub == nil {
		return false
	}
	return hub.HasClient()
}
