// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

var registerSignerOnce sync.Once

// RegisterSigner registers all signer-owned native Falcon capabilities.
func RegisterSigner() {
	registerSignerOnce.Do(func() {
		nativefalcon.RegisterClient()
		RegisterKeyValidator()
		RegisterProvider()
		keygen.RegisterNativeFalconGenerator()
		mnemonic.RegisterNativeFalconHandler()
	})
}
