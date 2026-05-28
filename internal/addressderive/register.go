// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package addressderive

import "sync"

var registerEd25519Once sync.Once

// RegisterEd25519 registers the Ed25519 address deriver.
func RegisterEd25519() {
	registerEd25519Once.Do(func() {
		Register("ed25519", GetEd25519())
	})
}
