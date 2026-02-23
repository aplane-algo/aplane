// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package falconkeys

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/util"
)

var registerProcessorsOnce sync.Once

// RegisterProcessors registers Falcon key processors, LSig derivers, and address derivers.
// This is idempotent and safe to call multiple times.
func RegisterProcessors() {
	registerProcessorsOnce.Do(func() {
		// Register Falcon address derivers with full versioned type name
		// The derivers are created with the key type so they know their version
		keyTypes := []string{
			"falcon1024-v1",
			"falcon1024-timelock-v1",
			"falcon1024-hashlock-v1",
		}
		for _, keyType := range keyTypes {
			util.RegisterAddressDeriver(keyType, GetFalconAddressDeriverForType(keyType))
		}
	})
}
