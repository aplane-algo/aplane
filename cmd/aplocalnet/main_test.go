// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/aplocalnet"
)

func TestModelViewShowsConfiguredKMDURL(t *testing.T) {
	m := newModel(aplocalnet.Options{
		AlgodURL: "http://localhost:4001",
		KMDURL:   "http://localhost:4012",
	})
	m.busy = false

	view := m.View()
	if !strings.Contains(view, "http://localhost:4012") {
		t.Fatalf("view missing KMD URL:\n%s", view)
	}
	if strings.Contains(view, "u algod URL") {
		t.Fatalf("view still advertises interactive algod URL edit:\n%s", view)
	}
}
