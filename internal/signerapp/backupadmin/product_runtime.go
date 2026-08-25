// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

func requireProductRuntime(ir *productruntime.Runtime) error {
	if ir == nil {
		return fmt.Errorf("product runtime is required")
	}
	return nil
}
