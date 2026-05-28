// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package family

import "errors"

// ErrInvalidFalconPublicKey is returned when no suitable counter value can be found
// to derive an address that is not a valid ed25519 public key.
var ErrInvalidFalconPublicKey = errors.New("unsuitable Falcon public key for Algorand address")
