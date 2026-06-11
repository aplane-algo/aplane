// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"testing"
)

func TestHTTPWriteTimeoutCoversApprovalWait(t *testing.T) {
	server := buildHTTPServer(nil, 0)
	if server.WriteTimeout <= serverconfig.DefaultApprovalWait {
		t.Fatalf("WriteTimeout = %s, want greater than default approval wait %s", server.WriteTimeout, serverconfig.DefaultApprovalWait)
	}
	if server.WriteTimeout <= serverconfig.MaxApprovalWait {
		t.Fatalf("WriteTimeout = %s, want greater than max approval wait %s", server.WriteTimeout, serverconfig.MaxApprovalWait)
	}
}
