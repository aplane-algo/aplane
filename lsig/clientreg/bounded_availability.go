// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build !testmode

package clientreg

import "github.com/aplane-algo/aplane/internal/keytypecatalog"

// boundedAccountAvailability keeps aplane.bounded.v1 out of every library and
// creation route. It stays disabled until the operator experience ships with it:
// listing it as disabled by default would still let an operator enable it.
const boundedAccountAvailability = keytypecatalog.AvailabilityDisabled
