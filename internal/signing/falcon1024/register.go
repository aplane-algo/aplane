// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falcon1024

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
)

type metadata struct{}

func (metadata) RoutingFamily() string        { return KeyType }
func (metadata) CryptoSignatureSize() int     { return MaxSignatureSize }
func (metadata) MnemonicWordCount() int       { return MnemonicWordCount }
func (metadata) SupportsMnemonicImport() bool { return true }
func (metadata) MnemonicScheme() string       { return "algorand" }
func (metadata) AuthorizationKind() algorithm.AuthorizationKind {
	return algorithm.AuthorizationNativePQ
}
func (metadata) RequiresLogicSig() bool       { return false }
func (metadata) CurrentLsigVersion() int      { return 0 }
func (metadata) SupportedLsigVersions() []int { return nil }
func (metadata) DefaultDerivation() string    { return "algorand-pq-f1" }
func (metadata) DisplayColor() string         { return "35" }

var registerClientOnce sync.Once

// RegisterClient registers only metadata that is safe to link into clients.
func RegisterClient() {
	registerClientOnce.Do(func() {
		keytypecatalog.Register(keytypecatalog.Entry{
			KeyType:      KeyType,
			Family:       KeyType,
			Availability: keytypecatalog.AvailabilityDefaultEnabled,
		})
		algorithm.RegisterMetadata(metadata{})
	})
}
