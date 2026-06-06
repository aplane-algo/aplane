// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"
	"time"
)

func attestedRequestID(prefix, supplied string) string {
	if supplied != "" {
		return supplied
	}
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}
