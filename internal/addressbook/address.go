// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package addressbook resolves aliases and sets into canonical addresses and
// provides compact address-formatting helpers for UI surfaces.
package addressbook

// FormatAddressShort returns address in abbreviated "ABCD..WXYZ" format.
// For addresses <= 12 characters, returns unchanged.
func FormatAddressShort(addr string) string {
	if len(addr) <= 12 {
		return addr
	}
	return addr[:4] + ".." + addr[len(addr)-4:]
}
