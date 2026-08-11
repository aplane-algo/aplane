//go:build windows

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeperm

import (
	"fmt"
	"os"
)

func openManagedServicePrincipal(string) (*os.File, error) {
	return nil, fmt.Errorf("managed service principal metadata is unsupported on windows")
}
