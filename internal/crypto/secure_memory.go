// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import "runtime"

// ZeroBytes securely overwrites a byte slice with zeros.
// The loop is simple enough that the compiler won't optimize it away,
// and KeepAlive ensures b isn't collected before zeroing completes.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
