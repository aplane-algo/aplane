// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

func TestHTTPWriteTimeoutCoversApprovalWait(t *testing.T) {
	server := buildHTTPServer(nil, 0)
	if server.WriteTimeout <= apconfig.DefaultApprovalWait {
		t.Fatalf("WriteTimeout = %s, want greater than default approval wait %s", server.WriteTimeout, apconfig.DefaultApprovalWait)
	}
	if server.WriteTimeout <= apconfig.MaxApprovalWait {
		t.Fatalf("WriteTimeout = %s, want greater than max approval wait %s", server.WriteTimeout, apconfig.MaxApprovalWait)
	}
}
