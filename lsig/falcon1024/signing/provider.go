// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falcon

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

var registerProviderOnce sync.Once

// RegisterProvider registers the Falcon signing provider with the signing registry.
// This is idempotent and safe to call multiple times.
func RegisterProvider() {
	registerProviderOnce.Do(func() {
		ops := signerops.New(nil)
		signing.Register(signing.NewLogicSigProvider("falcon1024", map[string]signing.LogicSigSignerOps{
			"falcon1024":           ops,
			"aplane.falcon1024.v1": ops,
		}))
	})
}
