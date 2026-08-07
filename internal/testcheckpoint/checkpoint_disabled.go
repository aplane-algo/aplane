// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build !storetest

// Package testcheckpoint provides semantic process checkpoints to store
// integration binaries. Production builds compile this no-op implementation.
package testcheckpoint

// Reach is a no-op outside the dedicated storetest build.
func Reach(string) error { return nil }
