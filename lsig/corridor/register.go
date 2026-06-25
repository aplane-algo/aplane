// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package corridor

import (
	"sync"

	"github.com/aplane-algo/aplane/lsig/dsafamily"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconkeys "github.com/aplane-algo/aplane/lsig/falcon1024/keys"
	"github.com/aplane-algo/aplane/lsig/sentryaccount"
)

var registerClientOnce sync.Once

func RegisterClient() {
	registerClientOnce.Do(func() {
		dsafamily.RegisterClient(dsafamily.ClientRegistration{
			Family: FamilyName,
			Metadata: sentryaccount.NewAlgorithmMetadata(
				FamilyName,
				SignatureSize,
				family.MnemonicScheme,
				family.MnemonicWordCount,
				family.DisplayColor,
			),
			KeyTypes: []dsafamily.KeyType{{
				KeyType:        KeyTypeV1,
				DSA:            NewProviderV1(),
				AddressDeriver: falconkeys.GetFalconAddressDeriverForType(KeyTypeV1),
			}},
		})
	})
}
