// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers Falcon-1024 attested-account signer-side
// key-generation support.
package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/keygen"
	falconkeygen "github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	falcon1024attested "github.com/aplane-algo/aplane/lsig/falcon1024_attested"
)

var registerSignerOnce sync.Once

func RegisterSigner() {
	registerSignerOnce.Do(func() {
		falcon1024attested.RegisterClient()
		ops := signerops.New(nil)
		keygen.Register(falconkeygen.NewFalconGenerator(falcon1024attested.KeyTypeV1, map[string]falconkeygen.LogicSigKeygenOps{
			falcon1024attested.KeyTypeV1: ops,
		}))
	})
}
