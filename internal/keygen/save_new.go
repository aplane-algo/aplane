// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// SaveNewKey saves a new aplane key record with its key type's
// valid_rekey_target declaration, resolved now. Every key creation path saves
// through here. A key type whose declaration does not resolve (neither a
// cataloged compiled key type nor an installed template that declares it)
// fails creation and nothing is written: a key never records a value its key
// type did not declare.
func SaveNewKey(paths storepaths.Paths, payload *keys.Payload, kr *crypto.Keyring) (*keys.ImportKeyResult, error) {
	if payload == nil {
		return nil, fmt.Errorf("key payload is required")
	}
	valid, ok := lsigprovider.ResolveValidRekeyTarget(payload.KeyType)
	if !ok {
		return nil, fmt.Errorf("cannot create a key of type %q: its valid_rekey_target declaration does not resolve (the key type is neither compiled in nor an installed template)", payload.KeyType)
	}
	return keys.SaveNewPayload(paths, payload, valid, kr)
}
