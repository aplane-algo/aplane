// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "github.com/aplane-algo/aplane/internal/keytypefmt"

func displayKeyType(keyType string) string {
	return keytypefmt.Display(keyType)
}
