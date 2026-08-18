// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/engine"
)

func newIsolatedTestEngine(t *testing.T, network string) (*engine.Engine, error) {
	t.Helper()
	store := cache.NewStore(t.TempDir())
	return engine.NewEngine(network,
		engine.WithCacheStore(store),
		engine.WithAliasCache(cache.LoadAliasCacheFromStore(store)),
	)
}
