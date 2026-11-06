// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build testmode

package clientreg

import "github.com/aplane-algo/aplane/internal/keytypecatalog"

// boundedAccountAvailability lets the on-chain tests reach aplane.bounded.v1.
// Only the integration harness builds with this tag; no release does.
const boundedAccountAvailability = keytypecatalog.AvailabilityLibrary
