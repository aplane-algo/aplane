// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"strings"
	"testing"
)

// GetSet finds a set by its normalized name and refuses a set that does not
// exist, so a mistyped @set reference fails rather than resolving to no
// addresses.
func TestSetCacheGetSet(t *testing.T) {
	cache := SetCache{Sets: map[string][]string{"team": {aliasTestAddress(1)}}}
	if got, err := cache.GetSet("Team"); err != nil || len(got) != 1 || got[0] != aliasTestAddress(1) {
		t.Fatalf("GetSet(Team) = %v, %v; want the team set", got, err)
	}
	if got, err := cache.GetSet("teem"); err == nil || got != nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("GetSet(teem) = %v, %v; want a does-not-exist error", got, err)
	}
}
