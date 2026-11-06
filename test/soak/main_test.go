// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package soak

import (
	"os"
	"testing"

	"github.com/aplane-algo/aplane/test/integration/harness"
)

func TestMain(m *testing.M) {
	code := m.Run()
	harness.RemoveSharedBuilds()
	os.Exit(code)
}
