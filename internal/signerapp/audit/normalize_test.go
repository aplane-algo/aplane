// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

// auditLines reads the log as lines, each with its length including the
// newline.
func auditLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.SplitAfter(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
}

// Every older event that carries a request's reason, path or lists stays
// under 128 KiB per line, whatever was sent, JSON escaping included.
func TestOlderEventsAreBoundedWhateverTheInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()
	ctx := adminserver.SessionContext{SessionID: "s-1"}
	// Control characters and < > & each encode to six bytes.
	hostile := strings.Repeat("\x01<\"\\", 512*1024) // 2 MiB
	long := strings.Repeat("g", 2<<20)
	many := make([]string, 50_000)
	for i := range many {
		many[i] = fmt.Sprintf("gen-%d-\x01<&>", i)
	}
	many[3] = hostile
	original := append([]string(nil), many...)

	logger.LogIdentityLockedContext(ctx, hostile)
	if err := logger.LogCredentialRestoreIntentDurableContext(ctx, "restore-1", hostile, false); err != nil {
		t.Fatal(err)
	}
	logger.LogCredentialRestoreContext(ctx, adminproto.RestoreBackupResult{OperationID: "restore-1", Error: hostile})
	if err := logger.LogGenerationQuarantinePruneIntentDurableContext(ctx, "prune-1", many); err != nil {
		t.Fatal(err)
	}
	pruned := make([]adminproto.PrunedQuarantinedGeneration, len(many))
	for i, id := range many {
		pruned[i] = adminproto.PrunedQuarantinedGeneration{GenerationID: id}
	}
	logger.LogGenerationQuarantinePruneContext(ctx, "prune-1", adminproto.PruneGenerationQuarantineResult{Pruned: pruned, Error: hostile})
	if err := logger.LogGenerationAbandonedDiscardIntentDurableContext(ctx, "discard-1", many); err != nil {
		t.Fatal(err)
	}
	logger.LogGenerationAbandonedDiscardContext(ctx, "discard-1", adminproto.DiscardAbandonedGenerationsResult{Discarded: pruned, Error: hostile})
	if err := logger.LogDeletedArchivePruneIntentDurableContext(ctx, "archive-1", many); err != nil {
		t.Fatal(err)
	}
	archived := make([]adminproto.PrunedDeletedArchiveEntry, len(many))
	for i, p := range many {
		archived[i] = adminproto.PrunedDeletedArchiveEntry{Path: p}
	}
	logger.LogDeletedArchivePruneContext(ctx, "archive-1", adminproto.PruneDeletedArchiveResult{Pruned: archived, Error: long})

	lines := auditLines(t, path)
	if len(lines) != 9 {
		t.Fatalf("%d entries, want 9", len(lines))
	}
	for i, line := range lines {
		if len(line) > 128*1024 {
			t.Fatalf("entry %d is %d bytes", i, len(line))
		}
		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if reason, _ := entry["reason"].(string); reason != "" && !strings.Contains(reason, "bytes)") {
			t.Fatalf("entry %d reason was not marked as cut", i)
		}
		for _, list := range []string{"generation_ids", "archive_entries"} {
			members, ok := entry[list].([]any)
			if !ok {
				continue
			}
			if len(members) != maxAuditSelectors || entry[list+"_omitted"] != float64(len(many)-maxAuditSelectors) {
				t.Fatalf("entry %d %s: %d members, omitted %v", i, list, len(members), entry[list+"_omitted"])
			}
			if members[0] != many[0] || !strings.Contains(members[3].(string), "bytes)") {
				t.Fatalf("entry %d %s sample: %q / %.40q", i, list, members[0], members[3])
			}
		}
	}
	// Bounding copies: the caller's selection is untouched.
	for i := range original {
		if many[i] != original[i] {
			t.Fatalf("member %d of the caller's list changed", i)
		}
	}
}

// Short values are logged exactly, with no omitted counts.
func TestShortOlderEventsAreUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()
	ids := []string{"gen-1700000000-0123abcd", "gen-1700000000-0123abcd"}
	logger.LogIdentityLockedContext(adminserver.SessionContext{}, "operator request")
	if err := logger.LogGenerationQuarantinePruneIntentDurableContext(adminserver.SessionContext{}, "prune-1", ids); err != nil {
		t.Fatal(err)
	}
	lines := auditLines(t, path)
	var locked, prune map[string]any
	if err := json.Unmarshal(lines[0], &locked); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &prune); err != nil {
		t.Fatal(err)
	}
	if locked["reason"] != "operator request" {
		t.Fatalf("a short reason changed: %v", locked["reason"])
	}
	if got := prune["generation_ids"].([]any); len(got) != 2 || got[0] != ids[0] || got[1] != ids[1] || prune["generation_ids_omitted"] != nil {
		t.Fatalf("a short list changed (duplicates kept, no omitted count): %v", prune)
	}
	if prune["operation_id"] != "prune-1" {
		t.Fatalf("operation ID %v", prune["operation_id"])
	}
}

// Every string field of AuditEntry is bounded, so a field added later
// cannot be logged unbounded unnoticed: set them all to an oversized value
// and check what normalization leaves.
func TestNormalizeEntryBoundsEveryStringField(t *testing.T) {
	huge := strings.Repeat("x", 1<<20)
	var entry AuditEntry
	v := reflect.ValueOf(&entry).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch {
		case f.Kind() == reflect.String:
			f.SetString(huge)
		case f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.String:
			list := make([]string, 1000)
			for j := range list {
				list[j] = huge
			}
			f.Set(reflect.ValueOf(list))
		}
	}
	got := reflect.ValueOf(normalizeEntry(entry))
	for i := 0; i < got.NumField(); i++ {
		name, f := got.Type().Field(i).Name, got.Field(i)
		switch {
		case f.Kind() == reflect.String && len(f.String()) > maxEntryReason:
			t.Errorf("%s is %d bytes after normalization", name, len(f.String()))
		case f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.String:
			if f.Len() > maxAuditSelectors {
				t.Errorf("%s has %d members after normalization", name, f.Len())
			}
			for j := 0; j < f.Len(); j++ {
				if len(f.Index(j).String()) > maxAuditField {
					t.Errorf("%s[%d] is %d bytes", name, j, len(f.Index(j).String()))
					break
				}
			}
		}
	}
	line, err := json.Marshal(normalizeEntry(entry))
	if err != nil {
		t.Fatal(err)
	}
	if len(line) > 128*1024 {
		t.Fatalf("a fully oversized entry encodes to %d bytes", len(line))
	}
}

// Real identifiers are far below the bounds and pass exactly, so rotating
// releases and correlation keep their values.
func TestNormalizeEntryKeepsRealIdentifiers(t *testing.T) {
	stage := uint64(4)
	entry := AuditEntry{
		Event:              AuditRotatingRelease,
		TxnAuth:            "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM",
		TxID:               "MJ5RG6E2SYQ5ZT3V4GZ4OEHEPKX3MQ2H7E6NOVRZ2DQWNTGUG2FA",
		RequesterPrincipal: "client:SHA256:Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6",
		RotatingStage:      &stage,
		GenerationID:       "gen-1793552194-98177ded",
		GroupID:            "zLfLtEbLS7JfVbH0l2ttqHHrrDpGn9RtrUHz55BTpD0=",
		GroupTxIDs: []string{
			"MJ5RG6E2SYQ5ZT3V4GZ4OEHEPKX3MQ2H7E6NOVRZ2DQWNTGUG2FA",
			"NNVV6LKA5C2V4WZBTLDCIDNVNVGHRDG6TXAJLCAM5KHC5MLMFUUQ",
		},
	}
	if got := normalizeEntry(entry); !reflect.DeepEqual(got, entry) {
		t.Fatalf("normalization changed real identifiers:\n got %+v\nwant %+v", got, entry)
	}
}
