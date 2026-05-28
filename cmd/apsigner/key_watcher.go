// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"

	"github.com/aplane-algo/aplane/internal/signerapp/filewatcher"
)

// startKeyWatcherForDir starts a filesystem watcher on the given directories.
// It calls reloadFn when qualifying .key, .template, or key type .json files change.
// Directories that don't exist are silently skipped at startup but will be
// picked up dynamically if created under a watched parent directory.
// This function satisfies the identity.WatcherStartFunc signature.
func startKeyWatcherForDir(dirs []string, ctx context.Context, reloadFn func() error) error {
	return filewatcher.Start(dirs, ctx, reloadFn, filewatcher.Options{
		Infof: logInfof,
		Warnf: logWarnf,
	})
}
