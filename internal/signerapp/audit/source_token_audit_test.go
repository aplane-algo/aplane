// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

func TestSourceTokenEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()
	ctx := adminserver.SessionContext{SessionID: "s-1", AdminPrincipal: adminserver.SessionPrincipal{ID: "operator"}}
	if err := logger.LogSourceTokenChangeIntentDurableContext(ctx, "set-1", "set", "default", "screening"); err != nil {
		t.Fatal(err)
	}
	logger.LogSourceTokenChangeResultContext(ctx, "set-1", "set", "default", "screening", adminproto.SourceTokenChangeResult{Success: true})
	logger.LogSourceTokenChangeResultContext(ctx, "rm-1", "remove", "KEY1", "ops", adminproto.SourceTokenChangeResult{Success: true})
	logger.LogSourceTokenChangeResultContext(ctx, "rm-2", "remove", "KEY1", "ops",
		adminproto.SourceTokenChangeResult{Code: "key_not_found", Error: "no token is set for this source"})

	entries := mutationEntries(t, path)
	if len(entries) != 4 {
		t.Fatalf("%d entries, want 4", len(entries))
	}
	for i, want := range []struct{ event, outcome, action, selector, source string }{
		{"SOURCE_TOKEN_CHANGE_INTENT", "requested", "set", "default", "screening"},
		{"SOURCE_TOKEN_SET", "succeeded", "set", "default", "screening"},
		{"SOURCE_TOKEN_REMOVED", "succeeded", "remove", "KEY1", "ops"},
		{"SOURCE_TOKEN_CHANGE_FAILED", "failed", "remove", "KEY1", "ops"},
	} {
		e := entries[i]
		if e["event"] != want.event || e["outcome"] != want.outcome || e["source_token_action"] != want.action ||
			e["policy_selector"] != want.selector || e["external_source"] != want.source || e["admin_session_id"] != "s-1" {
			t.Fatalf("entry %d = %#v, want %+v", i, e, want)
		}
	}
	if failed := entries[3]; failed["result_code"] != "key_not_found" || failed["reason"] != "no token is set for this source" {
		t.Fatalf("failure entry = %#v", failed)
	}
	if entries[1]["reason"] != nil || entries[1]["result_code"] != nil {
		t.Fatalf("a success carries a failure: %#v", entries[1])
	}

	// Request strings are bounded, as every intent's are.
	huge := strings.Repeat("x", 64*1024)
	if err := logger.LogSourceTokenChangeIntentDurableContext(ctx, "set-2", huge, huge, huge); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if last := lines[len(lines)-1]; len(last) > 4096 {
		t.Fatalf("a huge intent wrote %d bytes", len(last))
	}

	_ = logger.file.Close()
	if err := logger.LogSourceTokenChangeIntentDurableContext(ctx, "set-3", "set", "default", "screening"); err == nil {
		t.Fatal("an intent on a closed log reported success")
	}
}
