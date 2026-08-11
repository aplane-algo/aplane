// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build !unix

package storeperm

import "os"

func regularFileLinkCount(_ os.FileInfo) (uint64, bool) {
	return 0, false
}
