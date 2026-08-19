// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

func requireProductRuntime(ir *identity.Runtime) error {
	if ir == nil {
		return fmt.Errorf("product identity runtime is required")
	}
	return nil
}
