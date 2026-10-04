// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"os"
	"strings"
	"testing"
	"time"
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

	health := (Service{}).Health(ir, false, false)
	if len(health.Warnings) != 1 || strings.Contains(health.Warnings[0], active.Dir()) {
		t.Fatalf("health warnings = %q, want one warning without store paths", health.Warnings)
	}
	status := (Service{}).Status(ir)
	if len(status.Warnings) != 1 || !strings.Contains(status.Warnings[0], active.DeletedKeysDir()) {
		t.Fatalf("status warnings = %q, want the detailed failure", status.Warnings)
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

	if warnings := svc.Health(ir, false, false).Warnings; len(warnings) != 0 {
		t.Fatalf("initial warnings = %q, want none", warnings)
	}
	if err := os.RemoveAll(active.DeletedKeysDir()); err != nil {
		t.Fatal(err)
	}
	if warnings := svc.Health(ir, false, false).Warnings; len(warnings) != 0 {
		t.Fatalf("warnings within TTL = %q, want the cached result", warnings)
	}
	now = now.Add(storeHealthCacheTTL)
	if warnings := svc.Health(ir, false, false).Warnings; len(warnings) != 1 {
		t.Fatalf("warnings after TTL = %q, want a fresh failure", warnings)
	}
}
