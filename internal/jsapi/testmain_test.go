// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"os"
	"testing"

	"github.com/aplane-algo/aplane/internal/cache"
)

func TestMain(m *testing.M) {
	cache.InitLogger()
	os.Exit(m.Run())
}
