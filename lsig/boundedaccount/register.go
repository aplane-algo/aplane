// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedaccount

import (
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
)

var registerClientOnce sync.Once

// RegisterClient registers the key type. Falcon-1024 is its only base, so it
// registers that first.
func RegisterClient() {
	registerClientOnce.Do(func() {
		falcon.RegisterClient()
		provider, err := NewProvider()
		if err != nil {
			panic(fmt.Sprintf("boundedaccount: %v", err))
		}
		base, ok := composeddsa.LookupBase(baseKeyType)
		if !ok {
			panic("boundedaccount: base key type is not registered")
		}
		addressderive.Register(KeyTypeV1, base.NewAddressDeriver(KeyTypeV1))
		logicsigdsa.Register(provider)
	})
}
