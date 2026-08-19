// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"
	"sync/atomic"
)

var signingTestFamilySequence atomic.Uint64

// uniqueSigningTestFamily prevents process-global test providers from
// colliding when the package suite is repeated with go test -count=N.
func uniqueSigningTestFamily(base string) string {
	return fmt.Sprintf("%s-%d", base, signingTestFamilySequence.Add(1))
}
