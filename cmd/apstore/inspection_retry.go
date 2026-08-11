// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

const apstoreInspectionRetryInterval = 100 * time.Millisecond

var sleepApstoreInspectionRetry = time.Sleep

// requestInspectionWithRetry retries the server's deliberately non-blocking
// identity inspection response without extending the command's IPC deadline.
// Each attempt builds a fresh message and request ID.
func requestInspectionWithRetry[T any](
	client apstoreAdminRequester,
	build func() any,
	resultCode func(*T) string,
) (T, error) {
	deadline := time.Now().Add(apstoreIPCTimeout)
	for {
		var result T
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return result, codedError{code: protocol.ResultCodeIdentityBusy, message: "identity remained busy during read-only inspection"}
		}
		if err := client.requestWithTimeout(build(), &result, remaining); err != nil {
			return result, err
		}
		if resultCode(&result) != protocol.ResultCodeIdentityBusy {
			return result, nil
		}
		wait := apstoreInspectionRetryInterval
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
		if wait <= 0 {
			return result, fmt.Errorf("identity remained busy during read-only inspection")
		}
		sleepApstoreInspectionRetry(wait)
	}
}
