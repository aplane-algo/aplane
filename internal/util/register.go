// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/util/keys"
)

var registerEd25519AddrDeriverOnce sync.Once

// RegisterEd25519AddressDeriver registers the Ed25519 address deriver.
// This is idempotent and safe to call multiple times.
func RegisterEd25519AddressDeriver() {
	registerEd25519AddrDeriverOnce.Do(func() {
		RegisterAddressDeriver("ed25519", keys.GetEd25519AddressDeriver())
	})
}
