// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"github.com/aplane-algo/aplane/internal/auth"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
)

type SignerState = signerruntime.SignerState

const (
	SignerStateLocked   = signerruntime.SignerStateLocked
	SignerStateUnlocked = signerruntime.SignerStateUnlocked
)

// These Signer-level wrappers exist for test convenience and legacy
// call sites. They route through productIdentityRuntime() which is the
// only process-boundary use of CurrentProductIdentityID in the runtime path.

func (fs *Signer) getState() SignerState {
	return fs.productIdentityRuntime().GetState()
}

func (fs *Signer) isUnlocked() bool {
	return fs.getState() == SignerStateUnlocked
}

func (fs *Signer) setUnlocked() {
	fs.productIdentityRuntime().SetUnlocked()
}

func (fs *Signer) lock() {
	fs.productIdentityRuntime().Lock()
}

// hasClient is a product-mode compatibility helper. Identity-aware code should
// call AdminHub.HasClient with the target runtime identity directly.
func (fs *Signer) hasClient() bool {
	return fs.hasClientForIdentity(auth.CurrentProductIdentityID())
}

func (fs *Signer) hasClientForIdentity(identityID string) bool {
	hub := fs.adminHub()
	if hub == nil {
		return false
	}
	return hub.HasClient(identityID)
}
