// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
)

type SignerState = signerruntime.SignerState

const (
	SignerStateLocked   = signerruntime.SignerStateLocked
	SignerStateUnlocked = signerruntime.SignerStateUnlocked
	SignerStateRecovery = signerruntime.SignerStateRecovery
)

func (fs *Signer) hasClientForIdentity(identityID string) bool {
	_ = identityID
	hub := fs.adminHub()
	if hub == nil {
		return false
	}
	return hub.HasClient()
}
