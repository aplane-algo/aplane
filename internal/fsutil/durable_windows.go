// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build windows

package fsutil

// Windows has no directory fsync; metadata durability is left to NTFS.
func syncDir(string) error { return nil }
