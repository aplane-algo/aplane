// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/genstore"
)

// The unauthenticated health response does not reveal store paths when the
// archive check fails; the authenticated status response keeps the detail.
func TestHealthRedactsStoreCheckFailure(t *testing.T) {
	ir := setupProductRuntime(t, true)
	active, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(active.DeletedKeysDir()); err != nil {
		t.Fatal(err)
	}

	health := (Service{}).Health(ir)
	if len(health.Warnings) != 1 || strings.Contains(health.Warnings[0], active.Dir()) {
		t.Fatalf("health warnings = %q, want one warning without store paths", health.Warnings)
	}
	status := (Service{}).Status(ir)
	if len(status.Warnings) != 1 || !strings.Contains(status.Warnings[0], active.DeletedKeysDir()) {
		t.Fatalf("status warnings = %q, want the detailed failure", status.Warnings)
	}
}

// Health and status share one store inspection within the TTL, each with its
// own wording of a failure. One of them can't make the other's answer older than
// the TTL, and another generation is inspected at once.
func TestHealthAndStatusShareOneStoreInspection(t *testing.T) {
	ir := setupProductRuntime(t, true)
	active, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_760_000_000, 0)
	cache := &StoreHealthCache{now: func() time.Time { return now }}
	svc := Service{Deps: Dependencies{StoreHealth: cache}}
	requireWarnings := func(when string, want int) {
		t.Helper()
		health, status := svc.Health(ir).Warnings, svc.Status(ir).Warnings
		if len(health) != want || len(status) != want {
			t.Fatalf("%s: health warnings %q, status warnings %q, want %d each", when, health, status, want)
		}
		if want > 0 && (strings.Contains(health[0], active.Dir()) || !strings.Contains(status[0], active.DeletedKeysDir())) {
			t.Fatalf("%s: health says %q and status %q, want only status to name the directory", when, health[0], status[0])
		}
	}

	if warnings := svc.Status(ir).Warnings; len(warnings) != 0 {
		t.Fatalf("initial status warnings = %q", warnings)
	}
	if err := os.RemoveAll(active.DeletedKeysDir()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(storeHealthCacheTTL - time.Nanosecond)
	requireWarnings("within the TTL of status's inspection", 0)
	now = now.Add(time.Nanosecond)
	requireWarnings("once the TTL is over", 1)
	if err := os.MkdirAll(active.DeletedKeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	requireWarnings("within the TTL of the failure", 1)

	other := setupProductRuntime(t, true)
	if warnings := svc.Status(other).Warnings; len(warnings) != 0 {
		t.Fatalf("another generation's status warnings = %q, want its own inspection", warnings)
	}
}

// Health and status both warn once the deleted archive's reserve is consumed.
func TestHealthAndStatusWarnOfAConsumedReserve(t *testing.T) {
	ir := setupProductRuntime(t, true)
	active, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_760_000_000, 0)
	svc := Service{Deps: Dependencies{StoreHealth: &StoreHealthCache{
		now: func() time.Time { return now }, generationDir: active.Dir(), checkedAt: now,
		usage: genstore.DeletedArchiveUsage{Entries: genstore.DeletedArchiveWarnEntries + 1, EncodedBytes: 77},
	}}}
	want := fmt.Sprintf("deleted archive emergency reserve is consumed (%d entries, 77 encoded bytes); authenticated prune is required",
		genstore.DeletedArchiveWarnEntries+1)
	for name, warnings := range map[string][]string{"health": svc.Health(ir).Warnings, "status": svc.Status(ir).Warnings} {
		if len(warnings) != 1 || warnings[0] != want {
			t.Errorf("%s warnings = %q, want %q", name, warnings, want)
		}
	}
}

// Health reuses its store inspection within the TTL, so repeated
// unauthenticated calls do not each walk the archive.
func TestHealthCachesStoreInspection(t *testing.T) {
	ir := setupProductRuntime(t, true)
	active, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_760_000_000, 0)
	cache := &StoreHealthCache{now: func() time.Time { return now }}
	svc := Service{Deps: Dependencies{StoreHealth: cache}}

	if warnings := svc.Health(ir).Warnings; len(warnings) != 0 {
		t.Fatalf("initial warnings = %q, want none", warnings)
	}
	if err := os.RemoveAll(active.DeletedKeysDir()); err != nil {
		t.Fatal(err)
	}
	if warnings := svc.Health(ir).Warnings; len(warnings) != 0 {
		t.Fatalf("warnings within TTL = %q, want the cached result", warnings)
	}
	now = now.Add(storeHealthCacheTTL)
	if warnings := svc.Health(ir).Warnings; len(warnings) != 1 {
		t.Fatalf("warnings after TTL = %q, want a fresh failure", warnings)
	}
}
