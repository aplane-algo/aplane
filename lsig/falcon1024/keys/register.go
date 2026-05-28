// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falconkeys

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/addressderive"
)

var registerAddressDeriversOnce sync.Once

// RegisterAddressDerivers registers Falcon address derivers.
// This is idempotent and safe to call multiple times.
func RegisterAddressDerivers() {
	registerAddressDeriversOnce.Do(func() {
		// Register Falcon address derivers with full versioned type name
		// The derivers are created with the key type so they know their version
		keyTypes := []string{
			"aplane.falcon1024.v1",
		}
		for _, keyType := range keyTypes {
			addressderive.Register(keyType, GetFalconAddressDeriverForType(keyType))
		}
	})
}

// RegisterProcessors registers Falcon key processors, LSig derivers, and address derivers.
// This currently registers only pure address derivation; signer-side key file
// processors should be added here if this package grows private-key processing.
func RegisterProcessors() {
	RegisterAddressDerivers()
}
