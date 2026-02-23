// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package transport

import "errors"

// Sentinel errors for IPC connection failures.
var (
	// ErrAlreadyConnected is returned when another client is already connected.
	ErrAlreadyConnected = errors.New("another client is already connected")

	// ErrUnauthorized is returned when authentication fails.
	ErrUnauthorized = errors.New("authentication failed - invalid API token")
)
