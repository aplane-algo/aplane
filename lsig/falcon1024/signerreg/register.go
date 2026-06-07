// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers Falcon-1024 signer-side providers.
package signerreg

import (
	"sync"

	internalkeygen "github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/mnemonic/bip39impl"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
	falconkeys "github.com/aplane-algo/aplane/lsig/falcon1024/keys"
	falconsigning "github.com/aplane-algo/aplane/lsig/falcon1024/signing"
)

var registerSignerOnce sync.Once

// RegisterSigner registers all Falcon-1024 signer-side components.
// This is idempotent and safe to call multiple times.
func RegisterSigner() {
	registerSignerOnce.Do(func() {
		falcon.RegisterClient()
		falconsigning.RegisterProvider()
		keygen.RegisterGenerator()
		internalkeygen.RegisterAttestorFalcon1024Generator()
		keytypecatalog.Register(keytypecatalog.Entry{
			KeyType:      keytypes.SentryComponentFalcon1024V1,
			Family:       "sentry-falcon1024",
			Availability: keytypecatalog.AvailabilityDefaultEnabled,
		})
		mnemonic.Register(bip39impl.NewHandler(family.Name, family.MnemonicWordCount))
		falconkeys.RegisterProcessors()
	})
}
