// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build !windows

package fsutil

import "os"

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
